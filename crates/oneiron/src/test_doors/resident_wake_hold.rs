//! Doors for `tests/agent_wake_hold.rs` (AGM-4 wake hold): an inbound
//! message to a resident's inbox, admitted as routing admits one, with no
//! provider adapter in the loop.

use crate::error::Result;
use crate::surface_event::{
    SURFACE_EVENT_SCHEMA_VERSION, SurfaceCounterpartyStamp, SurfaceEvent, SurfaceEventAction,
    SurfaceEventSource, SurfaceSourceApp,
};
use crate::{EntityId, Vault};

/// Admits one inbound `web` message to `identity`, the inbox `agent` speaks
/// on, from the unknown sender `sender`, under the provider correlation id
/// `correlation_id`: the identity-stamped surface-event row a routed message
/// leaves. The store clock stamps when it arrived. The message carries no
/// body, so its wake carries its line alone.
pub fn admit_inbox_message(
    vault: &Vault,
    identity: EntityId,
    agent: EntityId,
    sender: &str,
    correlation_id: &str,
) -> Result<()> {
    let now = vault.now_recorded_at();
    let event = SurfaceEvent {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        event_id: format!("evt-{correlation_id}"),
        channel: "web".to_owned(),
        receiving_address_or_handle: format!("own_app:{}", agent.to_hex()),
        workspace_ref: None,
        receiving_identity_ref: identity.to_hex(),
        actor_ref: agent.to_hex(),
        facet_ref: None,
        subject_ref: None,
        counterparty: SurfaceCounterpartyStamp::Unknown {
            counterparty_key: sender.to_owned(),
        },
        source: SurfaceEventSource {
            app: SurfaceSourceApp::Web,
            user_ref: sender.to_owned(),
        },
        action: SurfaceEventAction::Message,
        correlation_id: correlation_id.to_owned(),
        payload_ref: None,
        received_at: now,
        foreign_inbound: true,
        claims_not_instructions: true,
        identity_retiring: false,
    };
    crate::surface_event::admit_routed_surface_event(vault, &event, now)
}
