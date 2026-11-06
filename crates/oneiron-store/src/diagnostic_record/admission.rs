//! Content-address and occurrence binding shared by local and replicated puts.

use crate::diagnostic_record::address::diagnostic_event_id;
use crate::diagnostic_record::event::DiagnosticEvent;
use crate::diagnostic_record::event::invalid_diagnostic;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

pub fn bind_address(
    id: &EntityId,
    occurred: TimeRange,
    data: &[u8],
    event: &DiagnosticEvent,
) -> Result<()> {
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
