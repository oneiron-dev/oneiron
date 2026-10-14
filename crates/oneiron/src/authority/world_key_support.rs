//! The authority side of the world-key doors (world privacy P6b): the
//! sequence and parents a key record takes, signing one, the stored roots
//! and this machine's own key records, and a fold under another pin.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::EntityId;
use crate::error::Result;
use crate::store::Store;

/// The next sequence `signer` signs on `fold`.
pub(crate) fn next_sequence(fold: &AuthorityFold, signer: &AuthorityKey) -> Result<u64> {
    match fold.append_sequences.get(signer) {
        None => Ok(1),
        Some(seq) => seq.checked_add(1).ok_or_else(invalid_authority),
    }
}

/// One entry of `fold`'s vault that `signing` signs alone over `parents`.
pub(crate) fn sign_side_entry(
    fold: &AuthorityFold,
    signing: &SigningKey,
    seq: u64,
    parents: BTreeSet<AuthorityEntryHash>,
    op: AuthorityOp,
    now: u64,
) -> Result<AuthorityLogEntry> {
    if fold.vault_id.is_none() || parents.is_empty() || parents.len() > MAX_PARENTS {
        return Err(invalid_authority());
    }
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: fold.vault_id,
        seq,
        parent_hashes: parents.into_iter().collect(),
        op,
        signer: AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: now,
    };
    entry.signer.signature = signing
        .sign(&authority_transcript(&entry)?)
        .to_bytes()
        .to_vec();
    Ok(entry)
}

/// The rows a machine's standing rests on under `fold`'s pin: its roster
/// head, its accepted roster revision, and its chain under the pinned
/// anchor. A world-key record names them, never an unrelated main-log head
/// that a replica could have refused (Engine ruling E7, as for world edits).
pub(crate) fn standing_rows(
    fold: &AuthorityFold,
    machine: EntityId,
) -> BTreeSet<AuthorityEntryHash> {
    let Some(folded) = fold.machine(machine) else {
        return BTreeSet::new();
    };
    let pinned = fold
        .pinned_root
        .and_then(|pin| folded.anchored.get(&pin.anchor_key));
    folded
        .roster
        .iter()
        .chain(folded.roster_trusted.iter())
        .chain(pinned)
        .map(|revision| revision.entry)
        .collect()
}

/// The stored, valid root record `root`, in the caller's snapshot.
pub(crate) fn owner_root_record_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    root: RecoveryRootId,
) -> Result<Option<(AuthorityEntryHash, OwnerRootRecord)>> {
    Ok(super::owner_roots::owner_root_records_in_txn(store, txn, fold)?.remove(&root))
}

/// Every stored, valid root record, in the caller's snapshot.
pub(crate) fn owner_root_records_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<BTreeMap<RecoveryRootId, (AuthorityEntryHash, OwnerRootRecord)>> {
    super::owner_roots::owner_root_records_in_txn(store, txn, fold)
}

/// Every valid key record `machine` signed with `machine_key`, counted here
/// or not: this machine's own past acts, which its doors may open whatever
/// the pin (contract §4, own records).
pub(crate) fn own_world_key_records_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    machine: EntityId,
    machine_key: [u8; 32],
) -> Result<Vec<(AuthorityEntryHash, WorldKeyWrapsRecord)>> {
    let mut records = Vec::new();
    for (_, body) in authority_log_rows_in_txn(store, txn)? {
        let entry = decode_authority_log_entry_body(&body)?;
        let AuthorityOp::WorldKeyWraps(record) = &entry.op else {
            continue;
        };
        if record.machine != machine
            || entry.signer.public_key != AuthorityKey::Ed25519(machine_key)
        {
            continue;
        }
        let hash = authority_entry_hash(&entry)?;
        if fold.valid_entries.contains(&hash) {
            let AuthorityOp::WorldKeyWraps(record) = entry.op else {
                continue;
            };
            records.push((hash, record));
        }
    }
    Ok(records)
}

impl crate::Vault {
    /// This vault's own log folded under `pin` instead of the stored one.
    pub(crate) fn authority_view_under_pin_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pin: Option<PinnedRoot>,
    ) -> Result<AuthorityView> {
        super::readonly_fold::authority_view_under_pin_for_store_in_txn(
            &self.store,
            self.privacy_posture(),
            txn,
            pin,
        )
    }
}
