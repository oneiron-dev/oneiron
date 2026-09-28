//! Content-address and occurrence binding shared by local and replicated puts.

use super::{
    diagnostic_event_id, invalid_diagnostic, validate_diagnostic_event_body_bytes, validate_token,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::temporal::TimeRange;

pub(super) fn validate_detector_id(detector_id: &str) -> Result<()> {
    validate_token(detector_id, "detector id is not a bounded token")
        .map_err(|_| invalid_diagnostic("detector id is not a bounded token"))
}

/// Checks canonical bytes, their address, and the interval indexes will use.
/// Sync calls this before quota debit; the batch chokepoint also calls it so
/// no internal local or replicated writer can bypass either binding.
pub(crate) fn validate_diagnostic_event_admission(
    id: &EntityId,
    occurred: TimeRange,
    data: &[u8],
) -> Result<()> {
    let event = validate_diagnostic_event_body_bytes(data)?;
    if diagnostic_event_id(&event.detector_id, data) != *id {
        return Err(invalid_diagnostic(
            "diagnostic id does not match detector and body",
        ));
    }
    if occurred.start != event.valid_from || occurred.end != event.valid_to.unwrap_or(u64::MAX) {
        return Err(invalid_diagnostic(
            "diagnostic occurrence does not match body validity",
        ));
    }
    Ok(())
}

/// Base DIAGNOSTIC writes may not cite an evaporating room, even when their
/// own content-addressed ID is different from the overlay member ID. Run this
/// after canonical decode at the shared batch door (local and replicated).
pub(crate) fn reject_off_record_diagnostic_sources(store: &Store, data: &[u8]) -> Result<()> {
    let event = validate_diagnostic_event_body_bytes(data)?;
    for id in event.evidence_refs.iter().chain(event.actor_ref.iter()) {
        if store.off_record_sessions.contains_entity(id)? {
            return Err(invalid_diagnostic("diagnostic cites off-record source"));
        }
    }
    Ok(())
}
