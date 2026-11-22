//! Shared storage-only admission for a recipient's cooperative review
//! restriction.

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::ManifestDbs;

/// One record under one filed courtesy ask, record first for admission scans.
pub(crate) type CooperativeRestrictionKey = (EntityId, [u8; 32], [u8; 16]);

#[doc(hidden)]
pub(crate) use oneiron_records::store::legal_hold::use_limit::CooperativeRestriction;

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

/// Whether the vault holds any record use limit at all, standing or not:
/// under LEGAL-HOLD-USE = B only a cooperative review restriction limits a
/// record's use, so this is one table probe, and a door that would ask
/// [`use_limit_in_txn`] of every row it ranks asks it only where one can
/// answer.
pub(crate) fn any_record_use_limit_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<bool> {
    Ok(COOPERATIVE_RESTRICTIONS
        .iter_raw_from(dbs, txn, &[])?
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

/// What keeps `record` from use at a read or egress door, if anything: a
/// cooperative review restriction on it. A legal hold limits no use
/// (LEGAL-HOLD-USE = B), so no refused privacy erase keeps a record or a
/// PERSON's content from use. The typed getter, retention and write
/// admission ask the record's own facts only.
pub(crate) fn use_limit_in_txn(
    dbs: &impl ManifestDbs,
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

/// Every record a cooperative restriction keeps: each record with a
/// restriction row, under any ask. A lift deletes its row, so every row read
/// here stands; a row that does not decode fails the read rather than drop
/// its record.
pub(crate) fn records_under_cooperative_restriction_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<std::collections::BTreeSet<EntityId>> {
    Ok(COOPERATIVE_RESTRICTIONS
        .scan(dbs, txn)?
        .into_iter()
        .map(|((record, _, _), _)| record)
        .collect())
}
