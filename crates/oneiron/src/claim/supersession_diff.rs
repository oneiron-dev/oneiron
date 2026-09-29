//! Immutable before/after revision bindings for accepted supersession edges.
//!
//! Gate `diff_handle` is a consent digest, not a body store. The exact entity
//! frontiers are captured inside the transaction that accepts a replacement.
//! A replica without these local revision frontiers has no renderable pair and
//! must not reconstruct one from mutable live rows.
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::vault::{ReadMode, RevisionRef};

const ROW_LEN: usize = 16 + 16 + 32 + 32;
const PAIRS: SideTable<(EntityId, EntityId), RevisionPair, Raw> =
    SideTable::new(&side_table::CLAIM_SUPERSESSION_DIFF);

#[derive(Clone, Copy)]
pub(crate) struct RevisionPair {
    pub before: RevisionRef,
    pub after: RevisionRef,
    pub before_hash: [u8; 32],
    pub after_hash: [u8; 32],
}
impl RawValue for RevisionPair {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut row = Vec::with_capacity(ROW_LEN);
        row.extend_from_slice(&self.before.0);
        row.extend_from_slice(&self.after.0);
        row.extend_from_slice(&self.before_hash);
        row.extend_from_slice(&self.after_hash);
        Ok(row)
    }
    fn from_raw(row: &[u8]) -> std::result::Result<Self, CodecError> {
        if row.len() != ROW_LEN {
            return Err(Error::CorruptedIndex("supersession revision pair").into());
        }
        Ok(Self {
            before: RevisionRef(row[0..16].try_into().expect("length checked")),
            after: RevisionRef(row[16..32].try_into().expect("length checked")),
            before_hash: row[32..64].try_into().expect("length checked"),
            after_hash: row[64..96].try_into().expect("length checked"),
        })
    }
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
    if PAIRS.contains(&vault.store, txn, &(old, new))? {
        return Err(Error::InvariantViolation(
            "supersession revision pair already recorded",
        ));
    }
    PAIRS.put(&vault.store, txn, &(old, new), &pair)?;
    Ok(())
}

pub(crate) fn load_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    old: EntityId,
    new: EntityId,
) -> Result<Option<RevisionPair>> {
    PAIRS.get(&vault.store, txn, &(old, new))
}
