//! Shared storage-only admission, with legal holds and a recipient's
//! cooperative review restriction kept as separate states.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{id_key, notice, standing_on_in_txn};
use crate::deletion::{LegalHoldReason, LegalHoldUseLimit};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;

/// Records kept after a refused privacy erasure (C6). Key: id16 (record).
pub(super) const USE_LIMITS: SideTable<EntityId, LegalHoldUseLimit, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_USE_LIMIT);

pub(super) fn keep_use_limited_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    record: EntityId,
    at: u64,
) -> Result<()> {
    if USE_LIMITS.contains(store, txn, &record)? {
        return Ok(());
    }
    // A use-limited fact no longer reads: its `about` lines hide (FIX 3196).
    crate::dreamer_consolidation::mark_person_about_dropped_in_txn(store, txn, &record)?;
    USE_LIMITS.put(
        store,
        txn,
        &record,
        &LegalHoldUseLimit {
            record,
            since: at,
            reason: LegalHoldReason::PrivacyEraseKept,
        },
    )
}

/// The C6 use limit on `record`, if it was kept after a refused privacy
/// erasure and a standing customer hold still keeps it (WILL-PLAN L01 row
/// 03, FIX 8849): it lasts the whole retention, until the
/// last hold lifts, narrows or lapses. A marker no standing hold backs
/// restricts nothing.
pub(crate) fn legal_hold_use_limit_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<LegalHoldUseLimit>> {
    let Some(limit) = USE_LIMITS.get(dbs, txn, record)? else {
        return Ok(None);
    };
    if notice::retaining_holds_in_txn(dbs, txn, record)?.is_empty() {
        return Ok(None);
    }
    Ok(Some(limit))
}

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

/// The same record-retention facts as `held_in_txn`, read from a
/// checkpoint custody plan's captured rows.
pub(crate) fn rows_keep_record(rows: &[(Vec<u8>, Vec<u8>)], id: &[u8; 16]) -> Result<bool> {
    if super::rows_hold_claim(rows, id) {
        return Ok(true);
    }
    let mut prefix = COOPERATIVE_RESTRICTIONS.decl().prefix.to_vec();
    prefix.extend_from_slice(id);
    if let Some((_, value)) = rows.iter().find(|(key, _)| key.starts_with(&prefix)) {
        COOPERATIVE_RESTRICTIONS.decode_value(value)?;
        return Ok(true);
    }
    Ok(false)
}

/// Private vocabulary: boolean read/egress consumers need only presence.
/// The legal-hold-specific public getter retains its own typed query.
pub(crate) enum RecordUseLimit {
    LegalHold,
    CooperativeReview,
}

pub(crate) fn use_limit_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<RecordUseLimit>> {
    if legal_hold_use_limit_in_txn(dbs, txn, record)?.is_some() {
        return Ok(Some(RecordUseLimit::LegalHold));
    }
    Ok(cooperative_restriction_active_in_txn(dbs, txn, record)?
        .then_some(RecordUseLimit::CooperativeReview))
}

/// The real legal-hold fact, for callers that report that exact reason.
pub(crate) fn legal_hold_held_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &[u8; 16],
) -> Result<bool> {
    Ok(!standing_on_in_txn(dbs, txn, &id_key(id))?.is_empty())
}

/// Whether a standing hold or a selected cooperative restriction keeps
/// this exact record for a door with no Store handle. Not a hold-placement
/// fact. Read inside the destroying transaction.
pub(crate) fn held_in_txn(dbs: &impl SideTableDbs, txn: &RoTxn<'_>, id: &[u8; 16]) -> Result<bool> {
    if legal_hold_held_in_txn(dbs, txn, id)? {
        return Ok(true);
    }
    match EntityId::from_bytes(*id) {
        Ok(record) => cooperative_restriction_active_in_txn(dbs, txn, &record),
        Err(_) => Ok(false),
    }
}

/// Whether a standing hold or selected restriction keeps this claim's
/// gate-decision partition. `None` remains the real-hold-only claim-free one.
pub(crate) fn partition_held_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    claim: Option<&[u8; 16]>,
) -> Result<bool> {
    let key = claim.map_or([0; 17], id_key);
    if !standing_on_in_txn(dbs, txn, &key)?.is_empty() {
        return Ok(true);
    }
    match claim.and_then(|id| EntityId::from_bytes(*id).ok()) {
        Some(record) => cooperative_restriction_active_in_txn(dbs, txn, &record),
        None => Ok(false),
    }
}
