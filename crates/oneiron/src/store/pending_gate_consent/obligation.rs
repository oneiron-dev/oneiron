//! Claim-scoped owner-answer obligations: the durable hold a critical confirm
//! opens, which only its owner's answer closes (see `crate::gate::owner_answer`).

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::GateDecisionId;
use super::Store;
use super::records::{
    OWNER_ANSWER_OBLIGATION_VERSION, OwnerAnswerObligationRecord, decode_owner_answer_obligation,
    encode_owner_answer_obligation,
};

/// Codec fixed `Raw` (see the decls.rs note): [`RawValue`] delegates to
/// [`encode_owner_answer_obligation`]/[`decode_owner_answer_obligation`]. The
/// table keeps the invalidation prefix it grew from, so earlier rows read as
/// open obligations.
const OBLIGATION: SideTable<EntityId, OwnerAnswerObligationRecord, Raw> =
    SideTable::new(&side_table::CRITICAL_CONFIRM_INVALIDATION);

impl RawValue for OwnerAnswerObligationRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_owner_answer_obligation(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_owner_answer_obligation(bytes)?)
    }
}

/// The hash an obligation names its owner's item by: the item's content
/// binding (`diff_handle`), whatever its length.
pub(crate) fn owner_answer_item_hash(diff_handle: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:owner-answer-item:v1");
    hasher.update(diff_handle);
    *hasher.finalize().as_bytes()
}

/// `claim_id`'s open owner-answer obligation, read through any store view.
pub(crate) fn owner_answer_obligation_in(
    dbs: &impl side_table::SideTableDbs,
    txn: &RoTxn<'_>,
    claim_id: &EntityId,
) -> Result<Option<OwnerAnswerObligationRecord>> {
    let Some(record) = OBLIGATION.get(dbs, txn, claim_id)? else {
        return Ok(None);
    };
    if record.claim_id != *claim_id.as_bytes() {
        return Err(Error::CorruptedIndex("owner answer obligation"));
    }
    Ok(Some(record))
}

impl Store {
    pub(crate) fn owner_answer_obligation_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<Option<OwnerAnswerObligationRecord>> {
        owner_answer_obligation_in(self, txn, claim_id)
    }

    /// Opens `claim_id`'s obligation on the item `opened_by` parked, unless
    /// one is open already: an open one keeps the item it names. Opening or
    /// closing one moves the graph version, since a held claim connects no
    /// community and a cached community snapshot must not outlive the change.
    pub(crate) fn open_owner_answer_obligation_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        opened_by: GateDecisionId,
        diff_handle: &[u8],
    ) -> Result<()> {
        if self
            .owner_answer_obligation_in_txn(wtxn, claim_id)?
            .is_some()
        {
            return Ok(());
        }
        self.put_owner_answer_obligation_in_txn(
            wtxn,
            &OwnerAnswerObligationRecord {
                version: OWNER_ANSWER_OBLIGATION_VERSION,
                claim_id: *claim_id.as_bytes(),
                opened_by,
                item: owner_answer_item_hash(diff_handle),
            },
        )?;
        crate::ppr::increment_graph_version(self, wtxn)
    }

    pub(crate) fn put_owner_answer_obligation_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &OwnerAnswerObligationRecord,
    ) -> Result<()> {
        let claim_id = EntityId::from_bytes(record.claim_id)
            .map_err(|_| Error::CorruptedIndex("owner answer obligation"))?;
        OBLIGATION.put(self, wtxn, &claim_id, record)?;
        Ok(())
    }

    /// An erasure leaves `claim_id`'s obligation open but blanks the item it
    /// names, whose hash derives from the erased body. A blank item names no
    /// item, so no answer closes it.
    pub(crate) fn blank_owner_answer_obligation_item_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<()> {
        let Some(mut obligation) = self.owner_answer_obligation_in_txn(wtxn, claim_id)? else {
            return Ok(());
        };
        obligation.item = [0; 32];
        self.put_owner_answer_obligation_in_txn(wtxn, &obligation)
    }

    /// Only the owner's answer reaches this: `crate::gate::owner_answer`
    /// calls it with an answer in hand.
    pub(crate) fn delete_owner_answer_obligation_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<()> {
        if OBLIGATION.delete(self, wtxn, claim_id)? {
            crate::ppr::increment_graph_version(self, wtxn)?;
        }
        Ok(())
    }
}
