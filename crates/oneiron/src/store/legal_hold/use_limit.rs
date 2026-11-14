//! Shared storage-only admission for a recipient's cooperative review
//! restriction.

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// One record under one filed courtesy ask, record first for admission scans.
pub(crate) type CooperativeRestrictionKey = (EntityId, [u8; 32], [u8; 16]);

/// A recipient's selected restriction. No hold, content, free-text
/// allegation, duration or automatic lift is implied by these codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CooperativeRestriction {
    pub since: u64,
    pub reason_code: String,
    pub review_at: u64,
}

const COOPERATIVE_RESTRICTIONS: SideTable<
    CooperativeRestrictionKey,
    CooperativeRestriction,
    Named,
> = SideTable::new(&side_table::COOPERATIVE_RESTRICTION);

/// Whether any ask still restricts this record. Decode the actual row,
/// so a corrupt marker cannot silently turn a restriction off.
pub(crate) fn cooperative_restriction_active_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<bool> {
    Ok(COOPERATIVE_RESTRICTIONS
        .iter_from(dbs, txn, record.as_bytes())?
        .next()
        .transpose()?
        .is_some())
}

/// Whether any cooperative restriction row exists. Since PR 2 only a
/// restriction can keep a birth, a token or a carrier, and the birth read
/// scans every `ROW_BIRTH` row, so it runs only while a restriction is
/// filed.
pub(crate) fn any_cooperative_restriction_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<bool> {
    Ok(COOPERATIVE_RESTRICTIONS
        .iter_from(dbs, txn, &[])?
        .next()
        .transpose()?
        .is_some())
}

/// The same record-retention facts as `held_in_txn`, read from a
/// checkpoint custody plan's captured rows.
pub(crate) fn rows_keep_record(rows: &[(Vec<u8>, Vec<u8>)], id: &[u8; 16]) -> Result<bool> {
    let mut prefix = COOPERATIVE_RESTRICTIONS.decl().prefix.to_vec();
    prefix.extend_from_slice(id);
    if let Some((_, value)) = rows.iter().find(|(key, _)| key.starts_with(&prefix)) {
        COOPERATIVE_RESTRICTIONS.decode_value(value)?;
        return Ok(true);
    }
    Ok(false)
}

/// Private vocabulary: boolean read/egress consumers need only presence.
pub(crate) enum RecordUseLimit {
    CooperativeReview,
}

pub(crate) fn use_limit_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<RecordUseLimit>> {
    Ok(cooperative_restriction_active_in_txn(dbs, txn, record)?
        .then_some(RecordUseLimit::CooperativeReview))
}

/// Whether a selected cooperative restriction keeps this exact record for a
/// door with no Store handle. Not a hold-placement fact. Read inside the
/// destroying transaction.
pub(crate) fn held_in_txn(dbs: &impl SideTableDbs, txn: &RoTxn<'_>, id: &[u8; 16]) -> Result<bool> {
    match EntityId::from_bytes(*id) {
        Ok(record) => cooperative_restriction_active_in_txn(dbs, txn, &record),
        Err(_) => Ok(false),
    }
}

/// Whether a selected restriction keeps this claim's gate-decision
/// partition. `None`, the claim-free partition, is never kept.
pub(crate) fn partition_held_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    claim: Option<&[u8; 16]>,
) -> Result<bool> {
    match claim.and_then(|id| EntityId::from_bytes(*id).ok()) {
        Some(record) => cooperative_restriction_active_in_txn(dbs, txn, &record),
        None => Ok(false),
    }
}
