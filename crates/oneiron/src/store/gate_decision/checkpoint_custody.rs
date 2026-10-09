//! What a checkpoint restore needs from exterior key custody, and the side
//! restore's custody fork (ARCH-0038 #erasure-completeness, "Key custody in a
//! side restore").
//!
//! A restore that takes its vault's place keeps that vault's custody. A copy
//! served beside its source gets custody of its own at restore time: only the
//! keys still live in the source's custody are copied, so a destroyed key
//! stays destroyed, and from then on each vault shreds only its own keys.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use heed::RwTxn;

use crate::error::{Error, Result};
use crate::side_table::SideKey;
use crate::store::Store;

use super::keys::GATE_DECISION_KEY_PREFIX;
use super::ledger::CUSTODY_ROOT;
use super::orcb::{self, CUSTODY_ROOT_KEY, corrupt};
use super::retention::checkpoint_retirements;
use super::types::GateDecisionId;

/// The custody a checkpoint's claim-bound receipts bind to, checked before a
/// restore creates its destination.
pub(crate) struct CheckpointCustody {
    bound: Option<PathBuf>,
    erased: Vec<(GateDecisionId, [u8; 16])>,
    /// Per claim: the newest key generation a row or a retirement intent
    /// names, and the newest one a committed retirement destroys.
    claims: BTreeMap<[u8; 16], (u64, Option<u64>)>,
}

impl CheckpointCustody {
    /// The rows a restore drops: their key generation was destroyed after
    /// the image was taken, or a committed retirement destroys it.
    pub(crate) fn erased(&self) -> &[(GateDecisionId, [u8; 16])] {
        &self.erased
    }
}

/// Authenticate encrypted canonical rows against CURRENT exterior keys before
/// restore creates its destination. The image supplies a pointer, not a key;
/// deleted keys remain absent when an old checkpoint is replayed.
///
/// A row whose key generation carries a retirement marker was erased (or
/// aged out) after the image was taken. So was a row under a generation that
/// a committed retirement among `rows` destroys, though its finisher has not
/// run yet. Such a row is listed, not decoded, so the restore drops it: the
/// restored vault is the vault at that time without the receipts an erase
/// destroyed. A key that is merely missing, with no marker, is lost custody
/// and still refuses the whole restore.
pub(crate) fn preflight_checkpoint_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> Result<CheckpointCustody> {
    let bound = rows
        .iter()
        .find(|(key, _)| key == CUSTODY_ROOT_KEY)
        .map(|(_, value)| orcb::decode_custody_root(value))
        .transpose()?;
    let mut claims = BTreeMap::new();
    for (claim, through, committed) in checkpoint_retirements(rows)? {
        claims.insert(claim, (through, committed.then_some(through)));
    }
    let mut erased = Vec::new();
    for (key, value) in rows {
        if key.starts_with(GATE_DECISION_KEY_PREFIX) && orcb::is_orcb(value) {
            let root = bound.as_deref().ok_or_else(corrupt)?;
            let id = key
                .strip_prefix(GATE_DECISION_KEY_PREFIX)
                .and_then(GateDecisionId::decode_key)
                .ok_or(Error::CorruptedIndex("gate decision ledger key"))?;
            let (claim, generation) = orcb::raw_claim_generation(value).ok_or_else(corrupt)?;
            let (through, committed) = claims.entry(claim).or_insert((generation, None));
            *through = (*through).max(generation);
            if committed.is_some_and(|newest| generation <= newest)
                || orcb::generation_retired(root, &claim, generation)?
            {
                erased.push((id, claim));
            } else {
                orcb::decode_hot(root, id, value)?;
            }
        }
    }
    Ok(CheckpointCustody {
        bound,
        erased,
        claims,
    })
}

/// A side restore forks custody into a directory of its own beside
/// `destination`. One already there, left by a vault removed without its
/// custody, is refused before the destination is created, never merged.
pub(crate) fn refuse_custody_beside(destination: &Path) -> Result<()> {
    if cfg!(unix) && orcb::custody_present(&std::path::absolute(destination)?)? {
        return Err(Error::InvalidConfig(
            "key custody already exists beside the restore destination; restore elsewhere".into(),
        ));
    }
    Ok(())
}

impl Store {
    /// Forks the custody `custody` binds to into this restored copy's own,
    /// beside its root, and binds the copy to it in this transaction. The
    /// copied keys are synced before the binding commits.
    pub(crate) fn fork_gate_custody_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        custody: &CheckpointCustody,
    ) -> Result<()> {
        if cfg!(not(unix)) {
            // No exterior custody exists here, so there is none to fork.
            return Ok(());
        }
        let root = &self.core.gate_custody_root;
        if let Some(source) = custody.bound.as_deref() {
            orcb::fork_custody(
                source,
                root,
                custody
                    .claims
                    .iter()
                    .map(|(claim, (through, committed))| (*claim, *through, *committed)),
            )?;
        }
        CUSTODY_ROOT.put(self, wtxn, &(), &orcb::encode_custody_root(root)?)
    }
}
