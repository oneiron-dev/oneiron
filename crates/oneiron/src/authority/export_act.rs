//! Folds the owner's signed whole-vault exports (FIX 4624): audit only. An
//! export changes nothing, so the fold keeps no register for it and no state
//! moves with one (the `AgentGrantAct` precedent); the export audit row of
//! the install that made the copy is its local index.
//!
//! A replica checks the record: its signer is the carrier's install key,
//! which some chain of the carrier names, never a roster key (FIX 2222),
//! past that key's last sequence, or the entry is invalid. A carrier the one
//! rule did not admit ([`super::owner_act_signer_admits`]), or an owner the
//! parents hold removed, leaves it valid and without effect: it joins the
//! fold's refused exports, which this install holds back, and never stalls
//! what descends from it. An agent's export Grant row is no authority-log
//! row, so the fold trusts the carrier for it (contract §4).
//!
//! The export door ([`Vault::record_export_act_op_in_txn`]) signs the act
//! after the copy left, in the write of its audit row, best effort
//! ([`super::carried_act`]): the copy is never withheld.

use crate::Vault;
use crate::entity_id::EntityId;

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::*;

/// The `ExportAct` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check.
pub(super) fn apply_export_act(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    record: &ExportActRecord,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    let key = *key;
    let standing = Standing::new(state, pin, counted);
    if !standing.names_key(record.machine, &key) || state.roster.contains_key(signer) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(record.machine, &key, roster);
    drop(standing);
    if !admitted || !super::owner_act::owner_live_at(state, record.act.owner) {
        state.refused_export_acts.insert(hash);
    }
    Ok(())
}

impl Vault {
    /// Records the owner's export `act` of the copy `export` as a signed
    /// `ExportAct` in the write `txn` of its audit row, best effort
    /// ([`super::carried_act`]): `format` as the row names it, `bytes` and
    /// `digest` (BLAKE3, lowercase hex) where the door read the copy back. A
    /// digest that does not read is left out of the record.
    pub(crate) fn record_export_act_op_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: OwnerAct,
        export: EntityId,
        format: &str,
        bytes: Option<u64>,
        digest: Option<&str>,
    ) -> Option<AuthorityEntryHash> {
        let digest = digest
            .and_then(|hex| blake3::Hash::from_hex(hex).ok())
            .map(|hash| *hash.as_bytes());
        let format = format.to_owned();
        self.record_carried_act_in_txn(txn, "export", |machine| {
            AuthorityOp::ExportAct(ExportActRecord {
                act,
                machine,
                export,
                format,
                bytes,
                digest,
            })
        })
    }
}
