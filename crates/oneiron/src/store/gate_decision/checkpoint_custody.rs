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

use heed::types::Bytes;
use heed::{Env, EnvFlags, EnvOpenOptions, RwTxn};

use crate::error::{Error, Result};
use crate::side_table::SideKey;
use crate::store::Store;

use super::keys::GATE_DECISION_KEY_PREFIX;
use super::ledger::CUSTODY_ROOT;
use super::orcb::{self, CUSTODY_ROOT_KEY, ForkedCustodyDir, corrupt};
use super::retention::{checkpoint_retirements, retirement_prefixes};
use super::types::GateDecisionId;

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// One vault's live key-custody state, read when a side restore of it
/// starts: where its custody is, and its key-retirement intents with their
/// erase marks and holds.
pub(crate) struct LiveCustody {
    root: PathBuf,
    rows: Rows,
}

impl LiveCustody {
    fn read(env: &Env, root: PathBuf) -> Result<Self> {
        let txn = env.read_txn()?;
        let vault_meta = env
            .open_database::<Bytes, Bytes>(&txn, Some("vault_meta"))?
            .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
        let mut rows = Vec::new();
        for prefix in retirement_prefixes() {
            for row in vault_meta.prefix_iter(&txn, prefix)? {
                let (key, value) = row?;
                rows.push((key.to_vec(), value.to_vec()));
            }
        }
        Ok(Self { root, rows })
    }
}

/// The live custody state of the vault at `vault_dir`, read without opening
/// it as a vault. No vault there has committed nothing.
pub(crate) fn read_live_custody(vault_dir: &Path) -> Result<Option<LiveCustody>> {
    if !vault_dir.join("data.mdb").is_file() {
        return Ok(None);
    }
    let mut options = EnvOpenOptions::new();
    options.max_dbs(1);
    // SAFETY: `READ_ONLY` asks LMDB for a read-only environment; heed
    // documents no further requirement on the flag itself.
    unsafe {
        options.flags(EnvFlags::READ_ONLY);
    }
    // SAFETY: the environment is read-only, so this handle never writes the
    // vault's data file, and LMDB's lock file registers its readers the way
    // it does for any reader beside a live writer. heed refuses a second open
    // of the same path in this process; a vault open here reads its own
    // state through `Store::live_custody`.
    let env = unsafe { options.open(vault_dir) }?;
    let live = (|| -> Result<LiveCustody> {
        let txn = env.read_txn()?;
        let vault_meta = env
            .open_database::<Bytes, Bytes>(&txn, Some("vault_meta"))?
            .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
        let root = match vault_meta.get(&txn, CUSTODY_ROOT_KEY)? {
            Some(raw) => orcb::decode_custody_root(raw)?,
            None => vault_dir.canonicalize()?,
        };
        drop(txn);
        LiveCustody::read(&env, root)
    })();
    // heed keeps an environment registered until it closes; close this one
    // so the vault can still be opened in this process afterwards.
    env.prepare_for_closing().wait();
    live.map(Some)
}

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
/// a committed retirement destroys, though its finisher has not run yet: one
/// among `rows`, or among `source`'s, the live state of the vault a side
/// restore copies, which wins over the image's. Such a row is listed, not
/// decoded, so the restore drops it: the restored vault is the vault at that
/// time without the receipts an erase destroyed. A key that is merely
/// missing, with no marker, is lost custody and still refuses the restore.
pub(crate) fn preflight_checkpoint_rows(
    rows: &[(Vec<u8>, Vec<u8>)],
    source: Option<&LiveCustody>,
) -> Result<CheckpointCustody> {
    let bound = rows
        .iter()
        .find(|(key, _)| key == CUSTODY_ROOT_KEY)
        .map(|(_, value)| orcb::decode_custody_root(value))
        .transpose()?;
    let mut retirements = checkpoint_retirements(rows)?;
    if let Some(source) = source {
        // The source's intents say nothing about another vault's keys.
        if bound.as_ref().is_some_and(|bound| *bound != source.root) {
            return Err(Error::InvalidConfig(
                "this checkpoint's key custody is not its source vault's".into(),
            ));
        }
        retirements.extend(checkpoint_retirements(&source.rows)?);
    }
    let mut claims = BTreeMap::new();
    for (claim, through, committed) in retirements {
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
    /// This vault's live custody state, for a side restore of it.
    pub(crate) fn live_custody(&self) -> Result<LiveCustody> {
        LiveCustody::read(&self.env, self.core.gate_custody_root.clone())
    }

    /// Forks the custody `custody` binds to into this restored copy's own,
    /// beside its root, and binds the copy to it in this transaction. The
    /// copied keys are synced before the binding commits. Returns the
    /// directory the fork created, if it had anything to copy.
    pub(crate) fn fork_gate_custody_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        custody: &CheckpointCustody,
    ) -> Result<Option<ForkedCustodyDir>> {
        if cfg!(not(unix)) {
            // No exterior custody exists here, so there is none to fork.
            return Ok(None);
        }
        let root = &self.core.gate_custody_root;
        let binding = orcb::encode_custody_root(root)?;
        let forked = match custody.bound.as_deref() {
            Some(source) => {
                let claims: Vec<_> = custody
                    .claims
                    .iter()
                    .map(|(claim, (through, committed))| (*claim, *through, *committed))
                    .collect();
                orcb::fork_custody(source, root, &claims)?
            }
            None => None,
        };
        if let Err(err) = CUSTODY_ROOT.put(self, wtxn, &(), &binding) {
            if let Some(forked) = forked {
                forked.remove();
            }
            return Err(err);
        }
        Ok(forked)
    }
}
