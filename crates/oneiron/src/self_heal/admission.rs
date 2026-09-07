//! Bind canonical diagnostic bodies to their address and indexed validity.

use super::{
    diagnostic_event_id, invalid_diagnostic, validate_diagnostic_event_body_bytes, validate_token,
};
use crate::{entity_id::EntityId, error::Result, temporal::TimeRange};

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
