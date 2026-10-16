//! Surface events as standing-connector wake sources (OF-218).
//!
//! A routed inbound event becomes a [`ConnectorEvent`] its actor's standing
//! subscriptions can wake on. The event is input data, never authority: the
//! wake is attenuated to the actor the receiving identity routed to, and a
//! reply leaves through the ordinary outbound pipeline
//! ([`crate::outbound::connector_reply_request`]).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::connector_key::events::ConnectorEvent;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::{
    SurfaceCounterpartyStamp, SurfaceEventAction, SurfaceEventDispatchDisposition,
    SurfaceEventDispatchRequest, SurfaceEventDispatchRoute, SurfaceEventDispatcher,
    SurfaceEventSource, SurfaceEventWorkerOutcome,
};

/// Predicate every surface-born connector event carries; a subscription
/// filter names it to take only inbound channel traffic.
pub const SURFACE_CONNECTOR_EVENT_PREDICATE: &str = "surface_event.v1";

/// How long a transiently failed ingest waits before the queue retries it.
const INGEST_RETRY_BACKOFF_SECS: u64 = 30;

/// What a surface-born connector event froze: who was addressed, as whom,
/// by whom, and on which thread. Everything a reply needs to go back out on
/// the same identity and thread rides here, so no reply reads it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceConnectorPayload {
    /// The provider's own event id, preserved verbatim.
    pub surface_event_id: String,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    pub receiving_identity_ref: String,
    pub actor_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facet_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    pub counterparty: SurfaceCounterpartyStamp,
    pub source: SurfaceEventSource,
    pub action: SurfaceEventAction,
    pub route: SurfaceEventDispatchRoute,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_ref: Option<String>,
    pub correlation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
    pub foreign_inbound: bool,
    pub claims_not_instructions: bool,
}

impl SurfaceConnectorPayload {
    /// Reads the payload a surface-born connector event froze.
    ///
    /// # Errors
    /// The event is not surface-born, or its payload does not decode.
    pub fn from_connector_event(event: &ConnectorEvent) -> Result<Self> {
        if event.predicate != SURFACE_CONNECTOR_EVENT_PREDICATE {
            return Err(invalid("connector event is not surface-born"));
        }
        serde_json::from_value(event.payload.clone())
            .map_err(|_| invalid("surface connector payload did not decode"))
    }

    /// The actor the receiving identity routed this event to.
    ///
    /// # Errors
    /// The frozen actor ref is not an entity id.
    pub fn actor(&self) -> Result<EntityId> {
        EntityId::from_hex(&self.actor_ref)
            .map_err(|_| invalid("surface connector actor is not an entity"))
    }

    /// The channel identity the event arrived on.
    ///
    /// # Errors
    /// The frozen identity ref is not an entity id.
    pub fn receiving_identity(&self) -> Result<EntityId> {
        EntityId::from_hex(&self.receiving_identity_ref)
            .map_err(|_| invalid("surface connector identity is not an entity"))
    }
}

/// The connector event kind a dispatch route wakes on.
#[must_use]
pub const fn surface_connector_event_kind(route: SurfaceEventDispatchRoute) -> &'static str {
    match route {
        SurfaceEventDispatchRoute::ActorSelf => "message",
        SurfaceEventDispatchRoute::ObservedSourceEnrichment => "interaction",
        SurfaceEventDispatchRoute::ProposeConfirm => "cc_intake",
    }
}

/// Maps one leased surface event to the connector event its actor's
/// standing subscriptions match. The event id is the delivery tuple's key
/// (channel, receiving address, correlation id), so a provider re-delivery
/// dedupes against the first wake decision instead of waking twice.
///
/// # Errors
/// The payload does not serialize.
pub fn connector_event_from_surface(
    request: &SurfaceEventDispatchRequest<'_>,
) -> Result<ConnectorEvent> {
    let event = request.event;
    let payload = SurfaceConnectorPayload {
        surface_event_id: event.event_id.clone(),
        channel: event.channel.clone(),
        receiving_address_or_handle: event.receiving_address_or_handle.clone(),
        workspace_ref: event.workspace_ref.clone(),
        receiving_identity_ref: event.receiving_identity_ref.clone(),
        actor_ref: event.actor_ref.clone(),
        facet_ref: event.facet_ref.clone(),
        subject_ref: event.subject_ref.clone(),
        counterparty: event.counterparty.clone(),
        source: event.source.clone(),
        action: event.action.clone(),
        route: request.route,
        thread_ref: request.thread_ref.map(str::to_owned),
        correlation_id: request.correlation_id.to_owned(),
        payload_ref: event.payload_ref.clone(),
        received_at: event.received_at,
        foreign_inbound: event.foreign_inbound,
        claims_not_instructions: event.claims_not_instructions,
    };
    Ok(ConnectorEvent {
        event_id: request.idempotency_key.to_owned(),
        connector: crate::connector_key::normalize_connector_key(&event.channel),
        event_kind: surface_connector_event_kind(request.route).to_owned(),
        predicate: SURFACE_CONNECTOR_EVENT_PREDICATE.to_owned(),
        payload: serde_json::to_value(&payload)
            .map_err(|_| invalid("surface connector payload did not encode"))?,
    })
}

/// The served surface-event dispatcher: each leased event wakes the
/// standing subscriptions of the actor it routed to, and no one else's.
/// An event no subscription takes completes; it was delivered, and nobody
/// stands on that connector.
pub struct ConnectorWakeBridge<'a> {
    vault: &'a Vault,
}

impl<'a> ConnectorWakeBridge<'a> {
    #[must_use]
    pub const fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }
}

impl SurfaceEventDispatcher for ConnectorWakeBridge<'_> {
    fn dispatch(
        &self,
        request: SurfaceEventDispatchRequest<'_>,
    ) -> SurfaceEventDispatchDisposition {
        let now = crate::unix_seconds_now();
        let agent = match EntityId::from_hex(request.agent_ref) {
            Ok(agent) => agent,
            Err(_) => {
                return SurfaceEventDispatchDisposition::Fail {
                    reason: "surface event actor is not an entity".to_owned(),
                };
            }
        };
        let event = match connector_event_from_surface(&request) {
            Ok(event) => event,
            Err(err) => {
                return SurfaceEventDispatchDisposition::Fail {
                    reason: err.to_string(),
                };
            }
        };
        match self
            .vault
            .ingest_surface_connector_event(&event, agent, now)
        {
            Ok(_) => SurfaceEventDispatchDisposition::Complete,
            // A shape the ingest door refuses never becomes valid on retry.
            Err(Error::InvalidConfig(reason)) => SurfaceEventDispatchDisposition::Fail { reason },
            Err(err) => SurfaceEventDispatchDisposition::Retry {
                backoff_until: now.saturating_add(INGEST_RETRY_BACKOFF_SECS),
                reason: err.to_string(),
            },
        }
    }
}

impl Vault {
    /// One served drain turn: claims the next queued surface event and hands
    /// it to its actor's standing connector subscriptions.
    ///
    /// # Errors
    /// Queue or payload failures; a dispatch failure settles the attempt.
    pub fn drain_surface_event_to_connector_wakes(
        &self,
        lease_owner: &str,
        now: u64,
    ) -> Result<SurfaceEventWorkerOutcome> {
        self.dispatch_next_surface_event(lease_owner, now, &ConnectorWakeBridge::new(self))
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
