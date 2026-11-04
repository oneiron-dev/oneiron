//! Content-address and occurrence binding shared by local and replicated puts.

use super::{invalid_diagnostic, validate_diagnostic_event_body_bytes};
use crate::error::Result;
use crate::store::Store;
pub(crate) use crate::store::diagnostic_record::admission::validate_diagnostic_event_admission;
pub(super) use crate::store::diagnostic_record::admission::{
    stored_diagnostic_event, validate_detector_id,
};

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
