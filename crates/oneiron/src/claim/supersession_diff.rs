//! Immutable before/after revision bindings for accepted supersession edges.
//!
//! Gate `diff_handle` is a consent digest, not a body store. The exact entity
//! frontiers are captured inside the transaction that accepts a replacement.
//! A replica without these local revision frontiers has no renderable pair and
//! must not reconstruct one from mutable live rows.
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::{ReadMode, RevisionRef};

const PREFIX: &[u8] = b"claim.supersession_diff.v1:";
const ROW_LEN: usize = 16 + 16 + 32 + 32;

#[derive(Clone, Copy)]
pub(crate) struct RevisionPair {
    pub before: RevisionRef,
    pub after: RevisionRef,
    pub before_hash: [u8; 32],
    pub after_hash: [u8; 32],
}

fn key(old: EntityId, new: EntityId) -> Vec<u8> {
    [PREFIX, old.as_bytes(), new.as_bytes()].concat()
}

pub(crate) fn capture_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    old: EntityId,
    new: EntityId,
) -> Result<RevisionPair> {
    let before_raw = vault.get_raw_in(txn, &old)?.ok_or(Error::EntityNotFound)?;
    let after_raw = vault.get_raw_in(txn, &new)?.ok_or(Error::EntityNotFound)?;
    let before = crate::vault::entity_revision::revision_for_mode_in_txn(
        &vault.store,
        txn,
        &old,
        ReadMode::Live,
    )?
    .ok_or(Error::CorruptedIndex("supersession before revision"))?;
    let after = crate::vault::entity_revision::revision_for_mode_in_txn(
        &vault.store,
        txn,
        &new,
        ReadMode::Live,
    )?
    .ok_or(Error::CorruptedIndex("supersession after revision"))?;
    Ok(RevisionPair {
        before,
        after,
        before_hash: *blake3::hash(&before_raw).as_bytes(),
        after_hash: *blake3::hash(&after_raw).as_bytes(),
    })
}

pub(crate) fn store_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    old: EntityId,
    new: EntityId,
    pair: RevisionPair,
) -> Result<()> {
    let key = key(old, new);
    if vault.store.vault_meta.get(txn, &key)?.is_some() {
        return Err(Error::InvariantViolation(
            "supersession revision pair already recorded",
        ));
    }
    let mut row = Vec::with_capacity(ROW_LEN);
    row.extend_from_slice(&pair.before.0);
    row.extend_from_slice(&pair.after.0);
    row.extend_from_slice(&pair.before_hash);
    row.extend_from_slice(&pair.after_hash);
    vault.store.vault_meta.put(txn, &key, &row)?;
    Ok(())
}

pub(crate) fn load_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    old: EntityId,
    new: EntityId,
) -> Result<Option<RevisionPair>> {
    let key = key(old, new);
    let Some(row) = vault.store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    if row.len() != ROW_LEN {
        return Err(Error::CorruptedIndex("supersession revision pair"));
    }
    let mut before_hash = [0; 32];
    let mut after_hash = [0; 32];
    before_hash.copy_from_slice(&row[32..64]);
    after_hash.copy_from_slice(&row[64..96]);
    Ok(Some(RevisionPair {
        before: RevisionRef(
            row[0..16]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("supersession before revision"))?,
        ),
        after: RevisionRef(
            row[16..32]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("supersession after revision"))?,
        ),
        before_hash,
        after_hash,
    }))
}
