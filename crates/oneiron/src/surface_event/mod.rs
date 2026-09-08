//! Inbound SurfaceEvent adapter contract (OF-347 CID-6).
//!
//! Adapters normalize inbound provider payloads through this module after
//! resolving the receiving channel identity. Routing returns a receipt and,
//! when accepted, the identity-stamped SurfaceEvent; admission then commits
//! that event to the durable attempt queue and acks before any dispatcher
//! runs.

use crate::error::{Error, Result};

mod handoff;
mod inbound;

pub use self::handoff::{
    SURFACE_EVENT_ATTEMPT_KIND, SurfaceEventAck, SurfaceEventAdmission, SurfaceEventAttemptPayload,
    SurfaceEventAttemptRef, SurfaceEventDispatchDisposition, SurfaceEventDispatchRequest,
    SurfaceEventDispatcher, SurfaceEventHandoffState, SurfaceEventHandoffStatus,
    SurfaceEventWorkerOutcome, decode_surface_event_attempt_payload,
    encode_surface_event_attempt_payload, surface_event_run_id,
};
pub use self::inbound::{
    INBOUND_SURFACE_RECEIPT_KIND, InboundSurfaceEventInput, InboundSurfaceRejectionReason,
    InboundSurfaceRouteOutcome, InboundSurfaceRouteReceipt, SURFACE_EVENT_SCHEMA_VERSION,
    SurfaceCounterpartyStamp, SurfaceEvent, SurfaceEventAction, SurfaceEventDispatchRoute,
    SurfaceEventSource, SurfaceInteractionKind, SurfaceSourceApp,
};

fn validate_non_blank(value: &str, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidConfig(reason.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

// The flat surface_event.rs module used to provide these names to the sibling
// test module through `use super::*`: its own private crate import header, and
// every surface-event-internal item the tests name bare. After the directory
// split the seam re-imports both so `tests.rs` resolves exactly as it did
// before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::AttemptState;
#[cfg(test)]
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState};
#[cfg(test)]
use crate::entity_id::EntityId;
