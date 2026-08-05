//! Inbound SurfaceEvent adapter contract (OF-347 CID-6).
//!
//! Adapters normalize inbound provider payloads through this module after
//! resolving the receiving channel identity. Routing returns a receipt and,
//! when accepted, the identity-stamped SurfaceEvent; admission then commits
//! that event to the durable attempt queue and acks before any dispatcher
//! runs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, CompleteOutcome, EnqueueAttempt, EnqueueOutcome, FailAttempt, FailOutcome,
    RetryAttempt, RetryOutcome,
};
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Current inbound SurfaceEvent schema version.
pub const SURFACE_EVENT_SCHEMA_VERSION: u64 = 2;

/// Stable receipt family label for inbound SurfaceEvent routing.
pub const INBOUND_SURFACE_RECEIPT_KIND: &str = "inbound_surface_event_route";

/// Attempt-queue kind owning inbound surface-event dispatch.
pub const SURFACE_EVENT_ATTEMPT_KIND: &str = "surface_event.dispatch.v1";

/// Route prefix the ack's status path is built on.
const SURFACE_EVENT_STATUS_PATH_PREFIX: &str = "/v1/core/surface-events/";

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
    /// Agent resolved from the receiving ChannelIdentity binding.
    pub agent_ref: String,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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

/// Durable payload a queued surface-event attempt carries to its worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceEventAttemptPayload {
    pub event: SurfaceEvent,
    pub route: SurfaceEventDispatchRoute,
    /// Downstream idempotency key. Exactly the public correlation id.
    pub dispatch_idempotency_key: String,
}

/// Public reference to the durable attempt backing one admitted event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SurfaceEventAttemptRef(String);

impl SurfaceEventAttemptRef {
    fn from_attempt_id(id: AttemptId) -> Self {
        let bytes = id.as_bytes();
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
            hex.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
        }
        Self(hex)
    }

    /// Lowercase 32-hex attempt id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Durable lifecycle of an admitted surface event, in public spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceEventHandoffState {
    Queued,
    Leased,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl SurfaceEventHandoffState {
    const fn from_attempt_state(state: AttemptState) -> Self {
        match state {
            AttemptState::Queued => Self::Queued,
            AttemptState::Leased => Self::Leased,
            AttemptState::Paused => Self::Paused,
            AttemptState::Completed => Self::Completed,
            AttemptState::Failed => Self::Failed,
            AttemptState::Cancelled => Self::Cancelled,
        }
    }

    /// Stable wire spelling, matching the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Ack returned the moment an inbound event is durably committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceEventAck {
    pub correlation_id: String,
    pub attempt_ref: SurfaceEventAttemptRef,
    pub state: SurfaceEventHandoffState,
    /// `true` when this correlation id already had an attempt row.
    pub replayed: bool,
    pub accepted_at: u64,
    pub status_path: String,
}

/// Durable snapshot of an admitted event's handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceEventHandoffStatus {
    pub correlation_id: String,
    pub attempt_ref: SurfaceEventAttemptRef,
    pub state: SurfaceEventHandoffState,
    pub attempt_count: u32,
    pub last_error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Admission outcome: a durable ack, or the typed route rejection that
/// stopped the event before it reached the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SurfaceEventAdmission {
    Accepted(SurfaceEventAck),
    Rejected(InboundSurfaceRouteReceipt),
}

/// Downstream handler a worker invokes for a leased surface event.
pub trait SurfaceEventDispatcher {
    fn dispatch(&self, request: SurfaceEventDispatchRequest<'_>)
    -> SurfaceEventDispatchDisposition;
}

/// Everything a dispatcher needs, already stamped at admission time.
#[derive(Debug)]
pub struct SurfaceEventDispatchRequest<'a> {
    pub event: &'a SurfaceEvent,
    pub route: SurfaceEventDispatchRoute,
    pub agent_ref: &'a str,
    pub correlation_id: &'a str,
    pub idempotency_key: &'a str,
}

/// What a dispatcher decided about one leased attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceEventDispatchDisposition {
    Complete,
    Retry { backoff_until: u64, reason: String },
    Fail { reason: String },
}

/// Result of one worker turn over the surface-event queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceEventWorkerOutcome {
    Empty,
    Completed(SurfaceEventHandoffStatus),
    Retried(SurfaceEventHandoffStatus),
    Failed(SurfaceEventHandoffStatus),
}

impl Vault {
    /// Resolves an inbound adapter payload into an identity-stamped
    /// SurfaceEvent or a typed route rejection receipt.
    pub fn route_inbound_surface_event(
        &self,
        input: InboundSurfaceEventInput,
    ) -> Result<InboundSurfaceRouteReceipt> {
        route_inbound_surface_event(self, input)
    }

    /// Routes an inbound event and, when it routes, commits it to the durable
    /// attempt queue before acking. No dispatcher runs inline: the ack means
    /// "durably ours", and a worker claims the row later.
    pub fn enqueue_inbound_surface_event(
        &self,
        input: InboundSurfaceEventInput,
        now: u64,
    ) -> Result<SurfaceEventAdmission> {
        let receipt = route_inbound_surface_event(self, input)?;
        let Some(event) = receipt.surface_event.clone() else {
            return Ok(SurfaceEventAdmission::Rejected(receipt));
        };
        let record = admit_surface_event_once(self, &event, now)?;
        Ok(SurfaceEventAdmission::Accepted(SurfaceEventAck {
            status_path: surface_event_status_path(&event.correlation_id),
            correlation_id: event.correlation_id,
            attempt_ref: SurfaceEventAttemptRef::from_attempt_id(record.attempt.id),
            state: SurfaceEventHandoffState::from_attempt_state(record.attempt.state),
            replayed: record.replayed,
            accepted_at: now,
        }))
    }

    /// Reads the durable handoff snapshot for one public correlation id.
    pub fn surface_event_handoff_status(
        &self,
        correlation_id: &str,
    ) -> Result<Option<SurfaceEventHandoffStatus>> {
        validate_non_blank(
            correlation_id,
            "surface event correlation id must be non-empty",
        )?;
        let run_id = surface_event_run_id(correlation_id);
        let queue = AttemptQueue::new(self);
        let Some(attempt) = sole_surface_event_attempt(queue.list_run(&run_id)?)? else {
            return Ok(None);
        };
        Ok(Some(handoff_status(correlation_id, &attempt)))
    }

    /// Claims and dispatches the next queued surface event.
    ///
    /// The worker leg is exercised by tests until the surface-serving ticket
    /// owns production wiring; the transitions it drives are the queue's own.
    pub fn dispatch_next_surface_event(
        &self,
        lease_owner: &str,
        now: u64,
        dispatcher: &dyn SurfaceEventDispatcher,
    ) -> Result<SurfaceEventWorkerOutcome> {
        let queue = AttemptQueue::new(self);
        let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
            SURFACE_EVENT_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )?
        else {
            return Ok(SurfaceEventWorkerOutcome::Empty);
        };

        let payload = decode_surface_event_attempt_payload(&attempt.payload)?;
        let disposition = dispatcher.dispatch(SurfaceEventDispatchRequest {
            event: &payload.event,
            route: payload.route,
            agent_ref: &payload.event.agent_ref,
            correlation_id: &payload.event.correlation_id,
            idempotency_key: &payload.dispatch_idempotency_key,
        });

        let correlation_id = payload.event.correlation_id.as_str();
        match disposition {
            SurfaceEventDispatchDisposition::Complete => {
                let outcome = queue.complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now,
                })?;
                let (CompleteOutcome::Completed(record)
                | CompleteOutcome::AlreadyCompleted(record)) = outcome;
                Ok(SurfaceEventWorkerOutcome::Completed(handoff_status(
                    correlation_id,
                    &record,
                )))
            }
            SurfaceEventDispatchDisposition::Retry {
                backoff_until,
                reason,
            } => {
                let RetryOutcome::Retried(record) = queue.retry(RetryAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    backoff_until,
                    last_error: Some(reason),
                    now,
                })?;
                Ok(SurfaceEventWorkerOutcome::Retried(handoff_status(
                    correlation_id,
                    &record,
                )))
            }
            SurfaceEventDispatchDisposition::Fail { reason } => {
                let outcome = queue.fail(FailAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    reason,
                    now,
                })?;
                let (FailOutcome::Failed(record) | FailOutcome::AlreadyFailed(record)) = outcome;
                Ok(SurfaceEventWorkerOutcome::Failed(handoff_status(
                    correlation_id,
                    &record,
                )))
            }
        }
    }
}

/// The one durable row an admitted correlation id resolves to.
struct AdmittedSurfaceEvent {
    attempt: AttemptRecord,
    replayed: bool,
}

/// Commits at most one attempt per public correlation id.
///
/// The run-index lookup and the enqueue share one write transaction, so two
/// concurrent submissions of the same correlation id cannot both insert: LMDB
/// serializes the writers and the loser observes the winner's row.
fn admit_surface_event_once(
    vault: &Vault,
    event: &SurfaceEvent,
    now: u64,
) -> Result<AdmittedSurfaceEvent> {
    let run_id = surface_event_run_id(&event.correlation_id);
    let payload = encode_surface_event_attempt_payload(&SurfaceEventAttemptPayload {
        event: event.clone(),
        route: event.dispatch_route(),
        dispatch_idempotency_key: event.correlation_id.clone(),
    })?;

    let queue = AttemptQueue::new(vault);
    let mut wtxn = vault.store.env.write_txn()?;
    if let Some(existing) = sole_surface_event_attempt(attempts_for_run_in_write_txn(
        vault, &queue, &wtxn, &run_id,
    )?)? {
        // A row already owns this correlation id — including after it reached a
        // terminal state. Replay derives that attempt instead of dispatching a
        // second one; the write txn is dropped without a commit.
        return Ok(AdmittedSurfaceEvent {
            attempt: existing,
            replayed: true,
        });
    }

    let outcome = queue.enqueue_in_txn(
        &mut wtxn,
        EnqueueAttempt {
            kind: SURFACE_EVENT_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(event.correlation_id.clone()),
            run_id: Some(run_id),
            now,
        },
    )?;
    wtxn.commit()?;
    Ok(match outcome {
        EnqueueOutcome::Enqueued(attempt) => AdmittedSurfaceEvent {
            attempt,
            replayed: false,
        },
        EnqueueOutcome::Existing(attempt) => AdmittedSurfaceEvent {
            attempt,
            replayed: true,
        },
    })
}

/// Reads a run's attempt rows inside the caller's write transaction.
///
/// The read must share the admission transaction: a read-transaction lookup
/// followed by a separate write would let a concurrent submitter slip a second
/// row in between.
fn attempts_for_run_in_write_txn(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    wtxn: &heed::RwTxn<'_>,
    run_id: &str,
) -> Result<Vec<AttemptRecord>> {
    let mut records = Vec::new();
    for id_bytes in vault.store.attempt_ids_for_run_in_txn(wtxn, run_id)? {
        let id = AttemptId::from_bytes(&id_bytes)?;
        let record = queue
            .get_in_write_txn(wtxn, id)?
            .ok_or(Error::CorruptedIndex("attempt run index"))?;
        if record.run_id.as_deref() != Some(run_id) {
            return Err(Error::CorruptedIndex("attempt run index"));
        }
        records.push(record);
    }
    Ok(records)
}

/// Resolves a run's attempt rows to the single surface-event row it may hold.
///
/// A row of another kind under the same public correlation id is a typed
/// collision, and more than one row for a once-only run is corruption — never
/// "pick the latest".
fn sole_surface_event_attempt(mut records: Vec<AttemptRecord>) -> Result<Option<AttemptRecord>> {
    if records.len() > 1 {
        return Err(Error::CorruptedIndex("surface event correlation run"));
    }
    let Some(record) = records.pop() else {
        return Ok(None);
    };
    if record.kind != SURFACE_EVENT_ATTEMPT_KIND {
        return Err(Error::InvalidConfig(
            "surface event correlation id is already held by another attempt kind".to_owned(),
        ));
    }
    Ok(Some(record))
}

fn handoff_status(correlation_id: &str, record: &AttemptRecord) -> SurfaceEventHandoffStatus {
    SurfaceEventHandoffStatus {
        correlation_id: correlation_id.to_owned(),
        attempt_ref: SurfaceEventAttemptRef::from_attempt_id(record.id),
        state: SurfaceEventHandoffState::from_attempt_state(record.state),
        attempt_count: record.attempt_count,
        last_error: record.last_error.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

/// Status URL an ack points at, with the correlation id percent-encoded so a
/// provider id carrying `/` or `?` still addresses its own resource.
fn surface_event_status_path(correlation_id: &str) -> String {
    let mut path = String::from(SURFACE_EVENT_STATUS_PATH_PREFIX);
    for byte in correlation_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            path.push(byte as char);
        } else {
            path.push('%');
            path.push(HEX_DIGITS[usize::from(byte >> 4)].to_ascii_uppercase() as char);
            path.push(HEX_DIGITS[usize::from(byte & 0x0f)].to_ascii_uppercase() as char);
        }
    }
    path
}

/// Encodes an attempt payload for durable storage.
pub fn encode_surface_event_attempt_payload(
    payload: &SurfaceEventAttemptPayload,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(payload).map_err(|error| {
        Error::InvalidConfig(format!(
            "surface event attempt payload did not encode: {error}"
        ))
    })
}

/// Decodes a durable attempt payload.
pub fn decode_surface_event_attempt_payload(bytes: &[u8]) -> Result<SurfaceEventAttemptPayload> {
    rmp_serde::from_slice(bytes)
        .map_err(|_| Error::InvalidAttemptQueueRecord("surface event attempt payload"))
}

fn route_inbound_surface_event(
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

    let agent_ref = match identity.binding {
        ChannelIdentityBinding::Agent { agent_ref } => agent_ref,
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

    match identity.state {
        ChannelIdentityState::Active | ChannelIdentityState::Rotating => Ok(routed_receipt(
            input,
            identity_ref,
            agent_ref,
            false,
            claims_not_instructions,
        )),
        ChannelIdentityState::Released | ChannelIdentityState::Quarantine => Ok(routed_receipt(
            input,
            identity_ref,
            agent_ref,
            true,
            claims_not_instructions,
        )),
        ChannelIdentityState::Tombstone => Ok(rejected_receipt(
            input,
            Some(identity_ref),
            Some(agent_ref),
            false,
            claims_not_instructions,
            InboundSurfaceRejectionReason::TombstonedReceivingIdentity,
        )),
        ChannelIdentityState::Requested | ChannelIdentityState::PendingFulfillment => {
            Ok(rejected_receipt(
                input,
                Some(identity_ref),
                Some(agent_ref),
                false,
                claims_not_instructions,
                InboundSurfaceRejectionReason::InactiveReceivingIdentity,
            ))
        }
    }
}

fn routed_receipt(
    input: InboundSurfaceEventInput,
    identity_ref: EntityId,
    agent_ref: EntityId,
    identity_retiring: bool,
    claims_not_instructions: bool,
) -> InboundSurfaceRouteReceipt {
    let surface_event = SurfaceEvent {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        event_id: input.event_id.clone(),
        channel: input.channel.clone(),
        receiving_address_or_handle: input.receiving_address_or_handle.clone(),
        workspace_ref: input.workspace_ref.clone(),
        receiving_identity_ref: identity_ref.to_hex(),
        agent_ref: agent_ref.to_hex(),
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

    InboundSurfaceRouteReceipt {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        receipt_kind: INBOUND_SURFACE_RECEIPT_KIND.to_owned(),
        event_id: input.event_id,
        outcome: InboundSurfaceRouteOutcome::Routed,
        channel: input.channel,
        receiving_address_or_handle: input.receiving_address_or_handle,
        workspace_ref: input.workspace_ref,
        receiving_identity_ref: Some(identity_ref.to_hex()),
        agent_ref: Some(agent_ref.to_hex()),
        counterparty: input.counterparty,
        foreign_inbound: input.foreign_inbound,
        claims_not_instructions,
        identity_retiring,
        rejection_reason: None,
        surface_event: Some(surface_event),
    }
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

/// Longest provider correlation id carried into the queue verbatim.
///
/// The attempt queue caps `run_id` at 128 bytes. A provider id at or under
/// that cap is its own run id; anything longer folds to a `sha256:` digest so
/// admission never rejects an event merely for a long provider id.
const MAX_VERBATIM_CORRELATION_RUN_ID_BYTES: usize = 128;

/// Derives the bounded queue run id for a public correlation id.
///
/// Deterministic in both directions of a replay: the same provider id always
/// yields the same run id, and the public correlation id is never rewritten.
#[must_use]
pub fn surface_event_run_id(correlation_id: &str) -> String {
    if correlation_id.len() <= MAX_VERBATIM_CORRELATION_RUN_ID_BYTES {
        return correlation_id.to_owned();
    }
    let digest = Sha256::digest(correlation_id.as_bytes());
    let mut run_id = String::with_capacity("sha256:".len() + digest.len() * 2);
    run_id.push_str("sha256:");
    for byte in digest {
        run_id.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        run_id.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    run_id
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn validate_non_blank(value: &str, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidConfig(reason.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
