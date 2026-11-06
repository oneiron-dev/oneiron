//! Core half of `store::diagnostic_record::admission`: its store-layer items live in `oneiron_store::diagnostic_record::admission` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::diagnostic_record::admission::*;

use super::{
    DiagnosticEvent, diagnostic_event_id, invalid_diagnostic, validate_diagnostic_event_body_bytes,
    validate_stored_diagnostic_event_body_bytes, validate_token,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::temporal::TimeRange;

pub(crate) fn validate_detector_id(detector_id: &str) -> Result<()> {
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
    bind_address(id, occurred, data, &event)
}

/// A stored DIAGNOSTIC row, read back with the same address and occurrence
/// binding. A body stored before the owner ruling of 2026-10-14 reads with
/// the text its grammar allowed dropped, at the id it was stored under.
pub(crate) fn stored_diagnostic_event(
    id: &EntityId,
    occurred: TimeRange,
    data: &[u8],
) -> Result<DiagnosticEvent> {
    let event = validate_stored_diagnostic_event_body_bytes(data)?;
    bind_address(id, occurred, data, &event)?;
    Ok(event)
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
