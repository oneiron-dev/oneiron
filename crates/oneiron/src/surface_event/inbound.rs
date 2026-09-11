//! Inbound surface event, source and action types, channel routing, and route receipts.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::validate_non_blank;
use crate::error::RecordError;

/// Current inbound SurfaceEvent schema version.
pub const SURFACE_EVENT_SCHEMA_VERSION: u64 = 2;

/// Stable receipt family label for inbound SurfaceEvent routing.
pub const INBOUND_SURFACE_RECEIPT_KIND: &str = "inbound_surface_event_route";

/// Provider app a normalized inbound event came from.
///
/// Closed by ruling (OF-247 R4 channel reconciliation): adapters map their
/// provider key onto one of these, and an unmapped key is an adapter defect,
/// not an open extension point.
///
/// The wire spelling is the provider channel key verbatim, so
/// [`SurfaceSourceApp::from_channel_key`] round-trips. The two acronym
/// variants are renamed explicitly because serde's mechanical snake_case
/// inserts a leading underscore on the interior capital, producing
/// `i_message` / `linked_in` rather than the pinned `imessage` / `linkedin`
/// channel keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceSourceApp {
    Email,
    Slack,
    Discord,
    Web,
    Voice,
    #[serde(rename = "imessage")]
    IMessage,
    Line,
    Telegram,
    #[serde(rename = "linkedin")]
    LinkedIn,
}

impl SurfaceSourceApp {
    /// Derives the source app from a raw provider channel key.
    ///
    /// The raw key stays authoritative for identity assignment lookups; this
    /// is the closed projection adapters get for free through
    /// [`InboundSurfaceEventInput::new`].
    #[must_use]
    pub fn from_channel_key(channel: &str) -> Option<Self> {
        match channel {
            "email" => Some(Self::Email),
            "slack" => Some(Self::Slack),
            "discord" => Some(Self::Discord),
            "web" => Some(Self::Web),
            "voice" => Some(Self::Voice),
            "imessage" => Some(Self::IMessage),
            "line" => Some(Self::Line),
            "telegram" => Some(Self::Telegram),
            "linkedin" => Some(Self::LinkedIn),
            _ => None,
        }
    }
}

/// Where an inbound event came from, as a closed app plus a provider user ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceEventSource {
    pub app: SurfaceSourceApp,
    pub user_ref: String,
}

impl SurfaceEventSource {
    /// Builds a source stamp.
    #[must_use]
    pub fn new(app: SurfaceSourceApp, user_ref: impl Into<String>) -> Self {
        Self {
            app,
            user_ref: user_ref.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_non_blank(
            &self.user_ref,
            "surface event source user ref must be non-empty",
        )
    }
}

/// Non-message interaction kinds carried by an inbound surface event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceInteractionKind {
    Reaction,
    CardCompletion,
    Dwell,
    Tap,
}

/// What the counterparty did on the surface.
///
/// A message dispatches toward the addressed actor's `self.*` flow; every
/// interaction normalizes into observed-source enrichment and never
/// synthesizes a TURN (OF-247 R4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SurfaceEventAction {
    Message,
    Interaction {
        interaction: SurfaceInteractionKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_ref: Option<String>,
    },
}

impl SurfaceEventAction {
    /// Dispatch route this action normalizes into.
    #[must_use]
    pub const fn dispatch_route(&self) -> SurfaceEventDispatchRoute {
        match self {
            Self::Message => SurfaceEventDispatchRoute::ActorSelf,
            Self::Interaction { .. } => SurfaceEventDispatchRoute::ObservedSourceEnrichment,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Message => Ok(()),
            Self::Interaction { target_ref, .. } => target_ref.as_deref().map_or(Ok(()), |value| {
                validate_non_blank(value, "surface interaction target ref must be non-empty")
            }),
        }
    }
}

/// Downstream flow a routed surface event hands off to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceEventDispatchRoute {
    ActorSelf,
    ObservedSourceEnrichment,
}

/// Counterparty identity known at inbound normalization time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SurfaceCounterpartyStamp {
    /// A known counterparty/contact record. CID-7 owns consent semantics.
    Known { counterparty_ref: String },
    /// A provider-native sender key not yet attached to a contact record.
    Unknown { counterparty_key: String },
}

impl SurfaceCounterpartyStamp {
    /// Builds a known-counterparty stamp from an entity id.
    #[must_use]
    pub fn known(counterparty_ref: EntityId) -> Self {
        Self::Known {
            counterparty_ref: counterparty_ref.to_hex(),
        }
    }

    /// Builds an unknown-counterparty stamp from provider-native sender data.
    #[must_use]
    pub fn unknown(counterparty_key: impl Into<String>) -> Self {
        Self::Unknown {
            counterparty_key: counterparty_key.into(),
        }
    }

    /// Provider-native user ref this stamp contributes when an adapter does
    /// not supply a richer one.
    fn default_user_ref(&self) -> String {
        match self {
            Self::Known { counterparty_ref } => counterparty_ref.clone(),
            Self::Unknown { counterparty_key } => counterparty_key.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Known { counterparty_ref } => validate_non_blank(
                counterparty_ref,
                "surface counterparty ref must be non-empty",
            ),
            Self::Unknown { counterparty_key } => validate_non_blank(
                counterparty_key,
                "surface counterparty key must be non-empty",
            ),
        }
    }
}

/// Adapter-normalized inbound payload before identity routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundSurfaceEventInput {
    pub event_id: String,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    pub counterparty: SurfaceCounterpartyStamp,
    /// Closed source app plus the provider-native sending user.
    pub source: SurfaceEventSource,
    /// What the counterparty did: a message, or a typed interaction.
    pub action: SurfaceEventAction,
    /// Provider-authored correlation id. Public and preserved verbatim; the
    /// queue run id is derived from it, never the other way around.
    pub correlation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
    /// Foreign/provider-authored inbound is claims-not-instructions canon.
    pub foreign_inbound: bool,
}

impl InboundSurfaceEventInput {
    /// Builds an inbound payload for identity routing.
    ///
    /// Adapters that carry no richer signal get the ruled defaults: the source
    /// app is derived from the channel key, the source user ref falls back to
    /// the counterparty stamp, the correlation id falls back to the provider
    /// event id, and the action is a message. Builders override each of those
    /// when an adapter knows better.
    #[must_use]
    pub fn new(
        event_id: impl Into<String>,
        channel: impl Into<String>,
        receiving_address_or_handle: impl Into<String>,
        counterparty: SurfaceCounterpartyStamp,
        received_at: u64,
        foreign_inbound: bool,
    ) -> Self {
        let event_id = event_id.into();
        let channel = channel.into();
        let source = SurfaceEventSource {
            // A key outside the ruled nine has no source app, and this
            // constructor stays infallible for the provider adapters that
            // consume it. The placeholder never reaches a durable envelope:
            // routing refuses to stamp an event whose channel key does not map
            // (see `routed_receipt`).
            app: SurfaceSourceApp::from_channel_key(&channel).unwrap_or(SurfaceSourceApp::Web),
            user_ref: counterparty.default_user_ref(),
        };
        Self {
            correlation_id: event_id.clone(),
            event_id,
            channel,
            receiving_address_or_handle: receiving_address_or_handle.into(),
            workspace_ref: None,
            counterparty,
            source,
            action: SurfaceEventAction::Message,
            payload_ref: None,
            received_at,
            foreign_inbound,
        }
    }

    /// Attaches a provider-native workspace/team stamp.
    #[must_use]
    pub fn with_workspace_ref(mut self, workspace_ref: impl Into<String>) -> Self {
        self.workspace_ref = Some(workspace_ref.into());
        self
    }

    /// Attaches an adapter-local payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Self {
        self.payload_ref = Some(payload_ref.into());
        self
    }

    /// Overrides the derived source stamp with adapter-supplied detail.
    #[must_use]
    pub fn with_source(mut self, source: SurfaceEventSource) -> Self {
        self.source = source;
        self
    }

    /// Marks this event as a non-message interaction.
    #[must_use]
    pub fn with_action(mut self, action: SurfaceEventAction) -> Self {
        self.action = action;
        self
    }

    /// Overrides the correlation id defaulted from the provider event id.
    #[must_use]
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = correlation_id.into();
        self
    }

    fn validate(&self) -> Result<()> {
        validate_non_blank(&self.event_id, "surface event id must be non-empty")?;
        validate_non_blank(&self.channel, "surface event channel must be non-empty")?;
        validate_non_blank(
            &self.receiving_address_or_handle,
            "surface event receiving address must be non-empty",
        )?;
        validate_non_blank(
            &self.correlation_id,
            "surface event correlation id must be non-empty",
        )?;
        if let Some(payload_ref) = &self.payload_ref {
            validate_non_blank(payload_ref, "surface event payload ref must be non-empty")?;
        }
        if let Some(workspace_ref) = &self.workspace_ref {
            validate_non_blank(
                workspace_ref,
                "surface event workspace ref must be non-empty",
            )?;
        }
        self.source.validate()?;
        self.action.validate()?;
        self.counterparty.validate()
    }
}

/// Identity-stamped inbound event passed to downstream surface ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceEvent {
    pub schema_version: u64,
    pub event_id: String,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    /// ChannelIdentity entity addressed by this inbound payload.
    pub receiving_identity_ref: String,
    /// Actor resolved from the receiving ChannelIdentity binding.
    ///
    /// Reads rows written before INB-06, where this field was spelled
    /// `agent_ref`: the rename did not change the value — an agent bound to an
    /// identity always WAS the actor speaking on it.
    #[serde(alias = "agent_ref")]
    pub actor_ref: String,
    /// Facet mask the actor wears on this channel, when one is bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facet_ref: Option<String>,
    /// PERSON or ORG standing behind the actor, resolved at routing time.
    ///
    /// `None` is the PLUMBING answer and is NOT a failure: an actor with no
    /// subject anchor is a relay or bot with no someone behind it, and it
    /// routes exactly like an anchored one. Already canonicalized through the
    /// redirect projection, so a merged subject stamps its survivor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    pub counterparty: SurfaceCounterpartyStamp,
    /// Closed source app plus the provider-native sending user.
    pub source: SurfaceEventSource,
    /// What the counterparty did: a message, or a typed interaction.
    pub action: SurfaceEventAction,
    /// Provider-authored correlation id, preserved verbatim.
    pub correlation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
    pub foreign_inbound: bool,
    /// Foreign inbound is claims, not executable owner instructions.
    pub claims_not_instructions: bool,
    /// Quarantined/released identities still route so replies are not dropped.
    pub identity_retiring: bool,
}

impl SurfaceEvent {
    /// Downstream flow this event hands off to.
    #[must_use]
    pub const fn dispatch_route(&self) -> SurfaceEventDispatchRoute {
        self.action.dispatch_route()
    }
}

/// Inbound routing result class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InboundSurfaceRouteOutcome {
    Routed,
    Rejected,
}

/// Stable rejection reasons for inbound SurfaceEvent routing receipts.
///
/// Closed on purpose, like [`SurfaceSourceApp`]: adapters branch on the reason
/// and the `/v1/core` schema enumerates these four spellings, so a projection
/// of this enum onto a wire contract must stay exhaustive. Sealing it would
/// only buy semver headroom this pre-release crate has no consumer for, at the
/// cost of letting a fifth reason ship a schema that silently lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundSurfaceRejectionReason {
    UnknownReceivingIdentity,
    NonAgentBoundIdentity,
    InactiveReceivingIdentity,
    TombstonedReceivingIdentity,
}

impl InboundSurfaceRejectionReason {
    /// Stable string used in adapter logs and receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownReceivingIdentity => "unknown_receiving_identity",
            Self::NonAgentBoundIdentity => "non_agent_bound_identity",
            Self::InactiveReceivingIdentity => "inactive_receiving_identity",
            Self::TombstonedReceivingIdentity => "tombstoned_receiving_identity",
        }
    }
}

/// Adapter-facing receipt for accepted and rejected inbound routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundSurfaceRouteReceipt {
    pub schema_version: u64,
    pub receipt_kind: String,
    pub event_id: String,
    pub outcome: InboundSurfaceRouteOutcome,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiving_identity_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_ref: Option<String>,
    pub counterparty: SurfaceCounterpartyStamp,
    pub foreign_inbound: bool,
    pub claims_not_instructions: bool,
    pub identity_retiring: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<InboundSurfaceRejectionReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_event: Option<SurfaceEvent>,
}

impl InboundSurfaceRouteReceipt {
    /// Returns the stable rejection reason string, when rejected.
    #[must_use]
    pub fn rejection_reason_str(&self) -> Option<&'static str> {
        self.rejection_reason
            .map(InboundSurfaceRejectionReason::as_str)
    }
}

/// Everything the binding + subject model say about who is speaking here.
///
/// Bundled so the routed arms cannot drift on which of the three stamps they
/// carry: an event that names an actor but forgets its resolved subject would
/// read downstream as plumbing, which is a different claim about the world.
struct ActorStamps {
    actor_ref: EntityId,
    facet_ref: Option<EntityId>,
    subject_ref: Option<EntityId>,
}

impl ActorStamps {
    fn resolve(
        vault: &Vault,
        actor_ref: EntityId,
        facet_ref: Option<EntityId>,
        at: u64,
    ) -> Result<Self> {
        let rtxn = vault.store.env.read_txn()?;
        if let Some(facet) = facet_ref
            && vault.get_entity_type_in_txn(&rtxn, &facet)?
                != Some(crate::registry::ENTITY_TYPE_FACET)
        {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "channel identity binding facet_ref must name a FACET",
            )));
        }
        let subject_ref =
            crate::subject_model::actor_subject_anchor_in_txn(vault, &rtxn, &actor_ref, at)?
                .map(|anchor| anchor.subject_ref);
        Ok(Self {
            actor_ref,
            facet_ref,
            subject_ref,
        })
    }
}

pub(super) fn route_inbound_surface_event(
    vault: &Vault,
    input: InboundSurfaceEventInput,
) -> Result<InboundSurfaceRouteReceipt> {
    input.validate()?;
    let claims_not_instructions = input.foreign_inbound;
    let Some((identity_ref, identity)) =
        vault.channel_identity_by_assignment(&input.channel, &input.receiving_address_or_handle)?
    else {
        return Ok(rejected_receipt(
            input,
            None,
            None,
            false,
            claims_not_instructions,
            InboundSurfaceRejectionReason::UnknownReceivingIdentity,
        ));
    };

    // A vault-bound identity names no actor, so there is nobody for the event
    // to be delivered TO. The reason keeps its pre-INB-06 variant name and
    // wire string `non_agent_bound_identity`: adapters branch on it and the
    // `/v1/core` schema enumerates it, so it is receipt-stable and is NOT
    // renamed to follow the actor vocabulary.
    let (actor_ref, facet_ref) = match identity.binding {
        ChannelIdentityBinding::Actor {
            actor_ref,
            facet_ref,
        } => (actor_ref, facet_ref),
        ChannelIdentityBinding::Vault { .. } => {
            return Ok(rejected_receipt(
                input,
                Some(identity_ref),
                None,
                false,
                claims_not_instructions,
                InboundSurfaceRejectionReason::NonAgentBoundIdentity,
            ));
        }
    };

    // Subject eligibility follows the adapter event, not queue processing time.
    let at = input.received_at;
    match identity.state {
        ChannelIdentityState::Active | ChannelIdentityState::Rotating => routed_receipt(
            input,
            identity_ref,
            ActorStamps::resolve(vault, actor_ref, facet_ref, at)?,
            false,
            claims_not_instructions,
        ),
        ChannelIdentityState::Released | ChannelIdentityState::Quarantine => routed_receipt(
            input,
            identity_ref,
            ActorStamps::resolve(vault, actor_ref, facet_ref, at)?,
            true,
            claims_not_instructions,
        ),
        ChannelIdentityState::Tombstone => Ok(rejected_receipt(
            input,
            Some(identity_ref),
            Some(actor_ref),
            false,
            claims_not_instructions,
            InboundSurfaceRejectionReason::TombstonedReceivingIdentity,
        )),
        ChannelIdentityState::Requested | ChannelIdentityState::PendingFulfillment => {
            Ok(rejected_receipt(
                input,
                Some(identity_ref),
                Some(actor_ref),
                false,
                claims_not_instructions,
                InboundSurfaceRejectionReason::InactiveReceivingIdentity,
            ))
        }
    }
}

/// Builds the routed receipt, or refuses the event whose channel key the
/// closed source enum cannot name.
///
/// Stamping is the point of no return: `source.app` is durable, and
/// [`InboundSurfaceEventInput::new`] derives `Web` for any key it cannot map.
/// Since [`ChannelIdentity`](crate::channel_identity::ChannelIdentity) admits
/// any nonempty channel string, an identity assigned an unruled key is
/// reachable — and would be branded with a plausible, wrong source app forever.
/// The raw key stays authoritative for identity assignment; only the closed
/// projection is refused, which is an adapter defect, not an open extension
/// point (OF-247 R4).
fn routed_receipt(
    input: InboundSurfaceEventInput,
    identity_ref: EntityId,
    stamps: ActorStamps,
    identity_retiring: bool,
    claims_not_instructions: bool,
) -> Result<InboundSurfaceRouteReceipt> {
    if SurfaceSourceApp::from_channel_key(&input.channel).is_none() {
        return Err(Error::InvalidConfig(format!(
            "surface event channel has no ruled source app: {}",
            input.channel
        )));
    }

    let surface_event = SurfaceEvent {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        event_id: input.event_id.clone(),
        channel: input.channel.clone(),
        receiving_address_or_handle: input.receiving_address_or_handle.clone(),
        workspace_ref: input.workspace_ref.clone(),
        receiving_identity_ref: identity_ref.to_hex(),
        actor_ref: stamps.actor_ref.to_hex(),
        facet_ref: stamps.facet_ref.map(|id| id.to_hex()),
        subject_ref: stamps.subject_ref.map(|id| id.to_hex()),
        counterparty: input.counterparty.clone(),
        source: input.source.clone(),
        action: input.action.clone(),
        correlation_id: input.correlation_id.clone(),
        payload_ref: input.payload_ref.clone(),
        received_at: input.received_at,
        foreign_inbound: input.foreign_inbound,
        claims_not_instructions,
        identity_retiring,
    };

    Ok(InboundSurfaceRouteReceipt {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        receipt_kind: INBOUND_SURFACE_RECEIPT_KIND.to_owned(),
        event_id: input.event_id,
        outcome: InboundSurfaceRouteOutcome::Routed,
        channel: input.channel,
        receiving_address_or_handle: input.receiving_address_or_handle,
        workspace_ref: input.workspace_ref,
        receiving_identity_ref: Some(identity_ref.to_hex()),
        // The receipt field keeps its `agent_ref` spelling: it is projected
        // into the `/v1/core` OpenAPI contract, so renaming it would break a
        // published wire schema for a vocabulary change.
        agent_ref: Some(stamps.actor_ref.to_hex()),
        counterparty: input.counterparty,
        foreign_inbound: input.foreign_inbound,
        claims_not_instructions,
        identity_retiring,
        rejection_reason: None,
        surface_event: Some(surface_event),
    })
}

fn rejected_receipt(
    input: InboundSurfaceEventInput,
    identity_ref: Option<EntityId>,
    agent_ref: Option<EntityId>,
    identity_retiring: bool,
    claims_not_instructions: bool,
    rejection_reason: InboundSurfaceRejectionReason,
) -> InboundSurfaceRouteReceipt {
    InboundSurfaceRouteReceipt {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        receipt_kind: INBOUND_SURFACE_RECEIPT_KIND.to_owned(),
        event_id: input.event_id,
        outcome: InboundSurfaceRouteOutcome::Rejected,
        channel: input.channel,
        receiving_address_or_handle: input.receiving_address_or_handle,
        workspace_ref: input.workspace_ref,
        receiving_identity_ref: identity_ref.map(|id| id.to_hex()),
        agent_ref: agent_ref.map(|id| id.to_hex()),
        counterparty: input.counterparty,
        foreign_inbound: input.foreign_inbound,
        claims_not_instructions,
        identity_retiring,
        rejection_reason: Some(rejection_reason),
        surface_event: None,
    }
}
