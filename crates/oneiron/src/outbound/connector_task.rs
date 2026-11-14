//! The durable connector-send task substrate.
//! Entry: `ConnectorSendTask`.
//! Defines its own items.

use crate::ports::EntityStoreRead;
use serde::{Deserialize, Serialize};

use super::capability::normalize_key;
use super::intent::OutboundIntent;
use super::send_lookup::EngineSendId;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::calendar::invite::CalendarInvitePayload;
use crate::delivery_window::{DeliveryWindowApnsInterruptionLevel, DeliveryWindowResolvedLevel};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::CONNECTOR_ACTOR;
use crate::error::{Error, RecordError};
use crate::receipt::delivered_send_receipt_for_task;
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_TASK};
use crate::temporal::TimeRange;
use crate::write_envelope::task_body::TaskRole;

/// TASK-body subkind for sends executed by a connector actor.
pub const CONNECTOR_SEND_TASK_SUBKIND: &str = "connector_send";

pub(super) const CONNECTOR_SEND_TASK_SCHEMA_VERSION: u8 = 0;

pub(super) const CONNECTOR_ACTOR_SCHEMA_VERSION: u8 = 0;

pub(super) const CONNECTOR_ACTOR_KIND: &str = "connector_actor";

const CONNECTOR_ASSIGNMENT_WEIGHT: f32 = 1.0;

#[cfg(test)]
std::thread_local! {
    static DELIVERED_PROJECTION_SAW_RECEIPT: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
    static FAILED_PROJECTION_SAW_RECEIPT: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ConnectorSendTaskBody {
    pub(super) role: u8,
    pub(super) schema_version: u8,
    pub(super) subkind: String,
    pub(super) actor_ref: String,
    pub(super) actor_class: String,
    pub(super) verb: String,
    pub(super) channel: String,
    pub(super) target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) counterparty_ref: Option<String>,
    pub(super) on_behalf_of: Option<String>,
    pub(super) content_ref: Option<String>,
    pub(super) idempotency_key: Option<String>,
    pub(super) dedupe_key: Option<String>,
    pub(super) intent_source: String,
    pub(super) trigger_ref: String,
    pub(super) job_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) mention: Option<super::MentionProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) originating_session_ref: Option<String>,
    /// The sticky send executor (FIX 4747): the one machine that may send
    /// this TASK, and the generation it holds. Absent until a machine first
    /// takes it. It is one field of this body, and the body is one value of
    /// the window's `entities` map, so a concurrent write from two machines
    /// resolves by whole-row LWW (higher Lamport, then peer); a raised
    /// generation is always a read-modify-write of the lease it replaces, so
    /// it wins over every lease it saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) send_executor_lease: Option<SendExecutorLease>,
    /// The logical send's one engine send id (FIX 4747), recorded when a
    /// machine first takes the send executor lease, so any machine knows
    /// what to look up at the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) engine_send_id: Option<EngineSendId>,
    /// The lease generation whose sends a lookup that found the send unsent,
    /// or the owner's resend, cleared to go (FIX 4747): a send under it does
    /// not look itself up again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) lookup_cleared_generation: Option<u64>,
    /// The owner's ask a send that may have gone out waits on (FIX 4747).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) uncertain_send: Option<UncertainSendHold>,
    /// Additive synced terminal projection. Absence means outcome unknown or
    /// still in flight; device-local intent rows never enter this body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) outcome: Option<ConnectorSendTaskOutcome>,
    /// Synced terminal reason for a mechanically collapsed send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) suppression: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) utc_offset_minutes: Option<i16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) iana_timezone: Option<String>,
    #[serde(default)]
    pub(super) human_explicit_instant: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
    /// Additive non-APNs resolved level. Absent ⇒ the manifest's interrupt
    /// class stands; the executor never guesses ambient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) resolved_level: Option<DeliveryWindowResolvedLevel>,
    /// CAL-04's frozen five-field iMIP body for a `calendar.invite` schedule.
    ///
    /// Additive and elided when absent, so every pre-change TASK body hydrates
    /// unchanged. It exists because the schedule chokepoint — not the executor
    /// — is where the UID/SEQUENCE transition was checked and committed; the
    /// executor replays this frozen body rather than recomputing any of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) calendar_invite: Option<CalendarInvitePayload>,
    /// The caller's deadline for a provider wait (FIX 8818).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) deadline_at: Option<u64>,
    /// The ambient send the interrupt degrades to (FIX 7962).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ambient_alternative: Option<super::OutboundAmbientAlternative>,
    /// FIX 12100's selection, frozen at the schedule chokepoint: the
    /// executor replays it instead of reselecting without it. Additive and
    /// elided when absent, so every pre-change TASK body hydrates unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) selection: Option<super::OutboundSendSelection>,
    pub(super) occurred_at: u64,
}

/// Terminal delivery projection carried by the synced connector-send TASK.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSendTaskOutcome {
    Delivered,
    Failed,
    Ambiguous,
    /// The send may have gone out, no lookup could tell, and the owner
    /// answered not to resend it (FIX 4747). Nothing sends it again.
    OwnerDeclinedResend,
}

/// A send that may have gone out and that no provider lookup could settle,
/// waiting for the owner's word (FIX 4747; canon ARCH-0023b "Still unknown:
/// ask the owner before any retry"): its TASK sends nothing until he answers
/// the inbox ask it raised.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UncertainSendHold {
    /// When the engine asked the owner, vault clock seconds; the ask's rows
    /// carry it.
    pub asked_at: u64,
    /// The owner answered resend: the TASK's executor sends it once.
    #[serde(default)]
    pub resend_released: bool,
}

#[doc(hidden)]
pub use oneiron_verb_wire::outbound::connector_task::UncertainSendAnswerOutcome;

/// The sticky send executor of one connector-send TASK (FIX 4747; canon
/// ARCH-0023b, pending outbound send): only the machine `node_id` names
/// sends it, and only while the TASK still holds this holder at this
/// `generation`. A handover moves it to another machine at the next
/// `generation`. The holder renews `held_until` while the TASK is its to
/// send; a lease no pass renewed, or one its holder released as it closed,
/// is expired from `held_until` on, and another machine's reaper may take it
/// (FIX 4747 slice 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendExecutorLease {
    /// The holder's stable sync node id (`m:client_id`).
    pub node_id: u64,
    /// Raised by one on every handover; a take from no lease starts at
    /// [`SEND_EXECUTOR_LEASE_FIRST_GENERATION`].
    pub generation: u64,
    /// Until when the holder holds it, vault clock seconds, as the TASK's
    /// other times: expired at and after this instant.
    pub held_until: u64,
}

impl SendExecutorLease {
    /// Whether `other` names this lease's holder at this generation,
    /// whatever either's `held_until`: a renewal or a release keeps the
    /// holding, so the holder's attempt in flight still passes its fence.
    #[must_use]
    pub fn same_holding(self, other: Self) -> bool {
        self.node_id == other.node_id && self.generation == other.generation
    }

    /// Whether the lease is expired at `now`: its holder neither renewed it
    /// past `now` nor holds it any more, so the reaper may take it.
    #[must_use]
    pub fn expired_at(self, now: u64) -> bool {
        now >= self.held_until
    }
}

/// The generation a send executor lease starts at when a machine takes a
/// TASK no machine held. Engine call (CALLS, FIX 4747).
pub(super) const SEND_EXECUTOR_LEASE_FIRST_GENERATION: u64 = 1;

/// How long a send executor lease holds past its holder's next pass over the
/// TASK (FIX 4747 slice 4): the holder renews it on each executor pass that
/// claims, sends, parks or holds the TASK. Engine call (CALLS, FIX 4747):
/// fifteen minutes, so a machine that vanished without its release hands its
/// sends over within one hold, and a pass that runs long never loses its
/// lease while it sends.
pub(super) const SEND_EXECUTOR_LEASE_HOLD_SECS: u64 = 15 * 60;

/// The `held_until` a lease taken or handed over at `now` starts with.
fn send_executor_lease_held_until(now: u64) -> u64 {
    now.saturating_add(SEND_EXECUTOR_LEASE_HOLD_SECS)
}

/// The `held_until` a holder's pass leaves on its lease when the TASK next
/// comes back to it at `next_pass_at`, or `None` while the lease it holds
/// covers that pass. Engine call (CALLS, FIX 4747 slice 4): it renews to
/// `next_pass_at` plus [`SEND_EXECUTOR_LEASE_HOLD_SECS`] once less than half
/// the hold would be left at that pass, so a send that keeps parking writes
/// its TASK at most once a half hold, and a park longer than the hold keeps
/// its lease through the park.
pub(super) fn send_executor_lease_renewal(held_until: u64, next_pass_at: u64) -> Option<u64> {
    let renew_below = next_pass_at.saturating_add(SEND_EXECUTOR_LEASE_HOLD_SECS / 2);
    (held_until < renew_below).then(|| send_executor_lease_held_until(next_pass_at))
}

/// This machine's own lease as it comes back to it at `now` (FIX 4747): an
/// expired one is taken again at the next generation, never renewed, since
/// another machine may have taken the send and sent it while this one was
/// away and sync may not show that yet; the new generation makes this
/// machine's send look itself up at its provider first (slices 2+3), so a
/// woken old executor never sends blind. `None` for a lease still held, which
/// the caller renews as before. Engine call (CALLS, FIX 4747).
fn own_expired_send_executor_lease_retaken(
    lease: SendExecutorLease,
    now: u64,
) -> Option<SendExecutorLease> {
    lease.expired_at(now).then(|| SendExecutorLease {
        node_id: lease.node_id,
        generation: lease.generation.saturating_add(1),
        held_until: send_executor_lease_held_until(now),
    })
}

/// The receipt field a send the fence stood down carries, valued
/// [`SEND_EXECUTOR_STOOD_DOWN`] (FIX 4747).
pub(super) const SEND_EXECUTOR_FENCE_FIELD: &str = "send_executor_fence";

/// The value of [`SEND_EXECUTOR_FENCE_FIELD`], and the execution's
/// `retry_state`, when the fence stood a send down before its transport call.
pub(super) const SEND_EXECUTOR_STOOD_DOWN: &str = "send_executor_stood_down";

/// The lease one attempt of a connector-send TASK took, carried on its
/// dispatch request to the fence before the transport call (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SendExecutorFence {
    pub(crate) task_ref: EntityId,
    pub(crate) lease: SendExecutorLease,
}

/// What taking the send executor lease came to (FIX 4747).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum SendExecutorLeaseTake {
    /// This machine holds the lease; its attempt sends under it.
    Taken(TakenSendExecutorLease),
    /// Another machine holds the lease: this machine stands down and sends
    /// nothing.
    HeldElsewhere(SendExecutorLease),
    /// The TASK permits no new send: delivered, possibly delivered, declined
    /// by the owner, or mechanically suppressed.
    Closed,
    /// This process released its leases as it closes: it takes none, and
    /// its attempt stays pending for the next process or machine (review
    /// #6574).
    Closing,
}

/// The lease a machine took, with what the TASK held beside it in the same
/// write (FIX 4747).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TakenSendExecutorLease {
    pub(super) lease: SendExecutorLease,
    /// The engine send id the TASK records, set by the first take.
    pub(super) engine_send_id: EngineSendId,
    pub(super) outcome: Option<ConnectorSendTaskOutcome>,
    pub(super) lookup_cleared_generation: Option<u64>,
    /// The owner's ask the send still waits on; `None` once he released it.
    pub(super) uncertain_send: Option<UncertainSendHold>,
    /// The owner answered resend and this take spent his release: this
    /// attempt sends once, with no lookup first.
    pub(super) owner_released_resend: bool,
}

/// What the fence read in the TASK right before a transport call (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SendExecutorFenceCheck {
    /// The TASK still holds exactly the lease this attempt took.
    Holds,
    /// The TASK holds another lease, or none: the attempt stands down.
    StoodDown { held: Option<SendExecutorLease> },
}

/// What a handover of a connector-send TASK came to (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendExecutorHandover {
    /// The lease now names the new machine at the next generation.
    Moved(SendExecutorLease),
    /// The new machine already held the lease; it stays as it was.
    AlreadyHeld(SendExecutorLease),
    /// The TASK permits no new send, so no lease moves.
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ConnectorActorBody {
    pub(super) schema_version: u8,
    pub(super) actor_kind: String,
    pub(super) connector_class: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ConnectorSendAttemptPayload {
    pub(crate) task_ref: String,
}

/// Hydrated shared TASK row that represents one scheduled connector send.
///
/// The clock-authority fields are hydrated onto this public row, not hidden
/// behind vault-reading accessors: hosts read the frozen authority straight
/// off `connector_send_tasks()`. All of them decode from additive,
/// serde-defaulted body keys, so a pre-change TASK body hydrates with no
/// timezone rather than failing or fabricating one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorSendTask {
    pub task_ref: EntityId,
    pub assignee_ref: EntityId,
    pub actor_ref: EntityId,
    pub actor_class: EdgeActorClass,
    pub intent: OutboundIntent,
    /// Explicit comm party key, distinct from the transport destination.
    pub counterparty_ref: Option<String>,
    pub originating_session_ref: Option<String>,
    /// The sticky send executor (FIX 4747); `None` until a machine takes it.
    pub send_executor_lease: Option<SendExecutorLease>,
    /// The logical send's engine send id (FIX 4747); `None` until a machine
    /// first takes the send executor lease.
    pub engine_send_id: Option<EngineSendId>,
    /// The owner's ask a send that may have gone out waits on (FIX 4747).
    pub uncertain_send: Option<UncertainSendHold>,
    pub outcome: Option<ConnectorSendTaskOutcome>,
    /// Synced terminal suppression reason, when the engine collapsed a send.
    pub suppression: Option<String>,
    /// Frozen host UTC offset in minutes. `None` ⇒ hostless schedule: the
    /// executor cannot derive a local minute and fails closed.
    pub utc_offset_minutes: Option<i16>,
    /// Frozen IANA label; the delivery door re-resolves it at delivery time.
    pub iana_timezone: Option<String>,
    pub human_explicit_instant: bool,
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
    /// Host-resolved level for a compatibility verb; see
    /// [`DeliveryWindowResolvedLevel`].
    pub resolved_level: Option<DeliveryWindowResolvedLevel>,
    /// CAL-04's frozen five-field iMIP body, when this TASK is a calendar
    /// invite. The executor re-freezes exactly these bytes; it never mints a
    /// UID or bumps a SEQUENCE.
    pub calendar_invite: Option<CalendarInvitePayload>,
    /// The caller's deadline, vault clock seconds: past it the TASK stops
    /// waiting on its provider (FIX 8818). `None` sets none.
    pub deadline_at: Option<u64>,
    /// The ambient send the interrupt degrades to (FIX 7962).
    pub ambient_alternative: Option<super::OutboundAmbientAlternative>,
    /// FIX 12100's selection, frozen at the schedule chokepoint and replayed
    /// by the executor; `None` dispatches as every schedule did before it.
    pub selection: Option<super::OutboundSendSelection>,
    pub occurred_at: u64,
}

/// Deterministic MACHINE assignee for one normalized connector class.
pub fn connector_actor_id(connector_class: &str) -> Result<EntityId, Error> {
    let connector_class = normalize_key(connector_class);
    if connector_class.is_empty() {
        return Err(Error::InvariantViolation(
            "connector class must not be empty",
        ));
    }
    EntityId::derive(CONNECTOR_ACTOR, &[connector_class.as_bytes()])
}

pub(crate) fn connector_send_attempt_payload(task_ref: EntityId) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&ConnectorSendAttemptPayload {
        task_ref: task_ref.to_hex(),
    })
    .map_err(|_| Error::InvariantViolation("connector task payload encode failed"))
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn put_connector_send_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    intent: &OutboundIntent,
    actor_ref: EntityId,
    actor_class: EdgeActorClass,
    originating_session_ref: Option<&str>,
    schedule_context: &crate::delivery_window::OutboundScheduleContext,
    continuation: &super::OutboundScheduleContinuation,
    calendar_invite: Option<&CalendarInvitePayload>,
    counterparty_ref: Option<&str>,
    occurred_at: u64,
) -> Result<(), Error> {
    // Fix list row 17645: a TASK body keeps one target, so a message to
    // several recipients sends at once and is never scheduled to lose them.
    if !intent.recipients.is_empty() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "a connector send task names one recipient",
        )));
    }
    if let Some(party) = counterparty_ref {
        crate::write_envelope::communication_record::validate_key_string(party)?;
        if !super::capability::is_canonical_outbound_verb(&intent.channel, &intent.verb) {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "noncanonical counterparty-bound connector verb",
            )));
        }
    }
    let connector_class = normalize_key(&intent.channel);
    let assignee_ref = connector_actor_id(&connector_class)?;
    let task_body = ConnectorSendTaskBody {
        role: TaskRole::Task.role_byte(),
        schema_version: CONNECTOR_SEND_TASK_SCHEMA_VERSION,
        subkind: CONNECTOR_SEND_TASK_SUBKIND.to_owned(),
        actor_ref: actor_ref.to_hex(),
        actor_class: actor_class.gate_actor_class().to_owned(),
        verb: intent.verb.clone(),
        channel: intent.channel.clone(),
        target: intent.target.clone(),
        counterparty_ref: counterparty_ref.map(str::to_owned),
        on_behalf_of: intent.on_behalf_of.clone(),
        content_ref: intent.content_ref.clone(),
        idempotency_key: intent.idempotency_key.clone(),
        dedupe_key: intent.dedupe_key.clone(),
        intent_source: intent.intent_source.clone(),
        trigger_ref: intent.trigger_ref.clone(),
        job_ref: intent.job_ref.clone(),
        mention: intent.mention.clone(),
        originating_session_ref: originating_session_ref.map(str::to_owned),
        send_executor_lease: None,
        engine_send_id: None,
        lookup_cleared_generation: None,
        uncertain_send: None,
        outcome: None,
        suppression: None,
        utc_offset_minutes: schedule_context.utc_offset_minutes,
        iana_timezone: schedule_context.iana_timezone.clone(),
        human_explicit_instant: schedule_context.human_explicit_instant,
        apns_interruption_level: schedule_context.apns_interruption_level,
        resolved_level: schedule_context.resolved_level,
        calendar_invite: calendar_invite.cloned(),
        deadline_at: continuation.deadline_at,
        ambient_alternative: continuation.ambient_alternative.clone(),
        selection: continuation.selection.clone(),
        occurred_at,
    };
    let task_body = rmp_serde::to_vec_named(&task_body)
        .map_err(|_| Error::InvariantViolation("connector task body encode failed"))?;
    let connector_body = ConnectorActorBody {
        schema_version: CONNECTOR_ACTOR_SCHEMA_VERSION,
        actor_kind: CONNECTOR_ACTOR_KIND.to_owned(),
        connector_class: connector_class.clone(),
    };
    let connector_body = rmp_serde::to_vec_named(&connector_body)
        .map_err(|_| Error::InvariantViolation("connector actor body encode failed"))?;
    let occurred = TimeRange {
        start: occurred_at,
        end: occurred_at,
    };
    let mut batch = vault.batch_in().put(
        &task_ref,
        ENTITY_TYPE_TASK,
        occurred,
        occurred_at,
        &task_body,
    );
    match vault.get_entity_type_in_txn(&*wtxn, &assignee_ref)? {
        None => {
            batch = batch.put(
                &assignee_ref,
                ENTITY_TYPE_MACHINE,
                occurred,
                occurred_at,
                &connector_body,
            );
        }
        Some(ENTITY_TYPE_MACHINE) => {
            let raw = vault
                .store
                .port_entity_record(&*wtxn, &assignee_ref)?
                .map(|row| row.encode())
                .ok_or(Error::CorruptedIndex("connector actor entity"))?;
            if !connector_actor_raw_matches(&raw, &connector_class)? {
                return Err(Error::InvariantViolation(
                    "connector actor id is occupied by a different machine",
                ));
            }
        }
        Some(_) => {
            return Err(Error::InvariantViolation(
                "connector actor id is occupied by another entity type",
            ));
        }
    }
    batch
        .edge(
            &task_ref,
            EdgeKind::AssignedTo,
            &assignee_ref,
            CONNECTOR_ASSIGNMENT_WEIGHT,
        )
        .apply(wtxn)
}

impl Vault {
    /// Hydrates one shared TASK when it is the connector-send subkind and has
    /// the deterministic connector actor assignment required by that subkind.
    pub fn connector_send_task(
        &self,
        task_ref: &EntityId,
    ) -> Result<Option<ConnectorSendTask>, Error> {
        let rtxn = self.store.env.read_txn()?;
        self.connector_send_task_in(&rtxn, task_ref)
    }

    /// [`Self::connector_send_task`] through the caller's transaction, so a
    /// write that acts on the TASK's actor judges the same validated body.
    pub(crate) fn connector_send_task_in(
        &self,
        txn: &heed::RoTxn<'_>,
        task_ref: &EntityId,
    ) -> Result<Option<ConnectorSendTask>, Error> {
        let Some(raw) = self.get_raw_in(txn, task_ref)? else {
            return Ok(None);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("connector task entity header"));
        };
        if header.entity_type != ENTITY_TYPE_TASK {
            return Ok(None);
        }
        let body_bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
        if !has_connector_send_subkind(body_bytes)? {
            return Ok(None);
        }
        if crate::write_envelope::task_body::task_role_from_body_bytes(body_bytes)?
            != TaskRole::Task
        {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "connector send must use the Task role",
            )));
        }
        let body: ConnectorSendTaskBody = rmp_serde::from_slice(body_bytes).map_err(|_| {
            Error::Record(RecordError::InvalidTaskBody("invalid connector send body"))
        })?;
        if body.schema_version != CONNECTOR_SEND_TASK_SCHEMA_VERSION
            || body.subkind != CONNECTOR_SEND_TASK_SUBKIND
        {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "unsupported connector send body version",
            )));
        }
        let actor_ref = EntityId::from_hex(&body.actor_ref).map_err(|_| {
            Error::Record(RecordError::InvalidTaskBody("invalid connector send actor"))
        })?;
        let actor_class = match body.actor_class.as_str() {
            "human" => EdgeActorClass::Human,
            "agent" => EdgeActorClass::Agent,
            "system" => EdgeActorClass::System,
            _ => {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "invalid connector send actor class",
                )));
            }
        };
        if body.counterparty_ref.as_deref().is_some_and(|party| {
            crate::write_envelope::communication_record::validate_key_string(party).is_err()
        }) {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "invalid connector send counterparty",
            )));
        }
        if body.counterparty_ref.is_some()
            && !super::capability::is_canonical_outbound_verb(&body.channel, &body.verb)
        {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "noncanonical counterparty-bound connector verb",
            )));
        }
        let assignee_ref = connector_actor_id(&body.channel).map_err(|_| {
            Error::Record(RecordError::InvalidTaskBody(
                "invalid connector send channel",
            ))
        })?;
        let assigned = crate::ports::EdgeStore::port_edge_neighbors(
            self,
            txn,
            task_ref,
            crate::ports::EdgeDirection::Out,
            None,
            crate::vault::MAX_EDGE_QUERY_RESULTS,
        )?
        .into_iter()
        .any(|edge| edge.kind == EdgeKind::AssignedTo && edge.target == assignee_ref);
        if !assigned || !connector_actor_matches(self, txn, assignee_ref, &body.channel)? {
            return Ok(None);
        }
        Ok(Some(ConnectorSendTask {
            task_ref: *task_ref,
            assignee_ref,
            actor_ref,
            actor_class,
            intent: OutboundIntent {
                actor: body.actor_ref,
                on_behalf_of: body.on_behalf_of,
                verb: body.verb,
                channel: body.channel,
                target: body.target,
                // A connector TASK sends to its one target (fix list row
                // 17645): a message to several is never scheduled.
                recipients: Vec::new(),
                content_ref: body.content_ref,
                idempotency_key: body.idempotency_key,
                dedupe_key: body.dedupe_key,
                intent_source: body.intent_source,
                trigger_ref: body.trigger_ref,
                job_ref: body.job_ref,
                mention: body.mention,
            },
            counterparty_ref: body.counterparty_ref,
            originating_session_ref: body.originating_session_ref,
            send_executor_lease: body.send_executor_lease,
            engine_send_id: body.engine_send_id,
            uncertain_send: body.uncertain_send,
            outcome: body.outcome,
            suppression: body.suppression,
            utc_offset_minutes: body.utc_offset_minutes,
            iana_timezone: body.iana_timezone,
            human_explicit_instant: body.human_explicit_instant,
            apns_interruption_level: body.apns_interruption_level,
            resolved_level: body.resolved_level,
            calendar_invite: body.calendar_invite,
            deadline_at: body.deadline_at,
            ambient_alternative: body.ambient_alternative,
            selection: body.selection,
            occurred_at: body.occurred_at,
        }))
    }

    /// Raw body read. Production paths hydrate the clock-authority fields onto
    /// [`ConnectorSendTask`] instead; this stays for wire-shape assertions.
    #[cfg(test)]
    pub(super) fn connector_send_task_task_body(
        &self,
        task_ref: EntityId,
    ) -> Result<ConnectorSendTaskBody, Error> {
        let raw = self
            .get_raw(&task_ref)?
            .ok_or(Error::Record(RecordError::InvalidTaskBody(
                "missing connector send task",
            )))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("connector task entity header"))?;
        if header.entity_type != ENTITY_TYPE_TASK || raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "invalid connector task header",
            )));
        }
        let body: ConnectorSendTaskBody = rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| {
                Error::Record(RecordError::InvalidTaskBody("invalid connector send body"))
            })?;
        if body.role != 1
            || body.schema_version != CONNECTOR_SEND_TASK_SCHEMA_VERSION
            || body.subkind != CONNECTOR_SEND_TASK_SUBKIND
        {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "unsupported connector send body",
            )));
        }
        Ok(body)
    }

    /// Replaces host clock provenance while a connector TASK is still non-terminal.
    pub fn refresh_connector_send_task_timezone(
        &self,
        task_ref: EntityId,
        utc_offset_minutes: i16,
        iana_timezone: Option<&str>,
        learned_at: u64,
    ) -> Result<ConnectorSendTask, Error> {
        if !(-840..=840).contains(&utc_offset_minutes) {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "utc offset out of range",
            )));
        }
        if iana_timezone.is_some_and(|s| {
            s.trim().is_empty() || s.len() > 255 || s.chars().any(char::is_control)
        }) {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "invalid IANA timezone",
            )));
        }
        // Check terminality in the same write transaction that hydrates the fields.
        update_connector_send_task_body(self, task_ref, learned_at, |body| {
            if body.outcome.is_some() {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "terminal connector task cannot refresh timezone",
                )));
            }
            body.utc_offset_minutes = Some(utc_offset_minutes);
            body.iana_timezone = iana_timezone.map(str::to_owned);
            Ok(())
        })?;
        self.connector_send_task(&task_ref)?
            .ok_or(Error::EntityNotFound)
    }

    /// Replaces the content ref a connector TASK still waiting to send
    /// carries. A TASK that already reached a terminal outcome stays as it is.
    pub(crate) fn replace_connector_send_task_content_ref(
        &self,
        task_ref: EntityId,
        content_ref: Option<&str>,
        learned_at: u64,
    ) -> Result<(), Error> {
        update_connector_send_task_body(self, task_ref, learned_at, |body| {
            if body.outcome.is_some() {
                return Ok(());
            }
            body.content_ref = content_ref.map(str::to_owned);
            Ok(())
        })
    }

    /// Lists the shared TASK rows that are valid connector-send tasks.
    pub fn connector_send_tasks(&self) -> Result<Vec<ConnectorSendTask>, Error> {
        let mut tasks = Vec::new();
        for task_ref in self.entities_by_type(ENTITY_TYPE_TASK)? {
            if let Some(task) = self.connector_send_task(&task_ref)? {
                tasks.push(task);
            }
        }
        Ok(tasks)
    }
}

/// Whether the TASK's synced outcome still permits a new send. A definite
/// failure remains retryable; delivered, ambiguous, owner-declined and
/// mechanically suppressed outcomes must never become new send permits.
/// Engine call (CALLS, FIX 4747): the lease take and the handover share this
/// one rule, so a Failed TASK may still be taken and handed over, as it was
/// retryable before the lease.
fn connector_send_task_permits_send(body: &ConnectorSendTaskBody) -> bool {
    !matches!(
        body.outcome,
        Some(
            ConnectorSendTaskOutcome::Ambiguous
                | ConnectorSendTaskOutcome::Delivered
                | ConnectorSendTaskOutcome::OwnerDeclinedResend
        )
    ) && body.suppression.is_none()
}

/// Takes the TASK's send executor lease for `node_id` (FIX 4747): no lease
/// becomes this node's at the first generation; this node's lease stays its
/// own at its generation, renewed for this pass (FIX 4747 slice 4); another
/// node's lease is not taken, expired or not, and this node stands down:
/// only the reaper takes a lease another node let lapse, in the ruled order.
/// Checked against the CURRENT replicated TASK in one write transaction.
/// The first take records `engine_send_id` on the TASK. Engine call (CALLS,
/// FIX 4747): a take of a send the owner released for one resend spends that
/// release, and clears the lease generation it holds of further lookups.
pub(super) fn take_send_executor_lease(
    vault: &Vault,
    task_ref: EntityId,
    node_id: u64,
    engine_send_id: &EngineSendId,
    now: u64,
) -> Result<SendExecutorLeaseTake, Error> {
    let mut take = SendExecutorLeaseTake::Closed;
    // A closing process released its leases: it takes none again.
    if vault
        .executor_leases_released
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        return Ok(SendExecutorLeaseTake::Closing);
    }
    update_connector_send_task_body(vault, task_ref, now, |body| {
        if !connector_send_task_permits_send(body) {
            return Ok(());
        }
        let held = body.send_executor_lease;
        let lease = match held {
            None => {
                let lease = SendExecutorLease {
                    node_id,
                    generation: SEND_EXECUTOR_LEASE_FIRST_GENERATION,
                    held_until: send_executor_lease_held_until(now),
                };
                body.send_executor_lease = Some(lease);
                lease
            }
            Some(lease) if lease.node_id == node_id => {
                let lease = own_expired_send_executor_lease_retaken(lease, now).unwrap_or(
                    SendExecutorLease {
                        held_until: send_executor_lease_renewal(lease.held_until, now)
                            .unwrap_or(lease.held_until),
                        ..lease
                    },
                );
                body.send_executor_lease = Some(lease);
                lease
            }
            Some(lease) => {
                take = SendExecutorLeaseTake::HeldElsewhere(lease);
                return Ok(());
            }
        };
        let engine_send_id = body
            .engine_send_id
            .get_or_insert_with(|| engine_send_id.clone())
            .clone();
        let owner_released_resend = body.uncertain_send.is_some_and(|hold| hold.resend_released);
        if owner_released_resend {
            body.uncertain_send = None;
            body.lookup_cleared_generation = Some(lease.generation);
        }
        take = SendExecutorLeaseTake::Taken(TakenSendExecutorLease {
            lease,
            engine_send_id,
            outcome: body.outcome,
            lookup_cleared_generation: body.lookup_cleared_generation,
            uncertain_send: body.uncertain_send,
            owner_released_resend,
        });
        Ok(())
    })?;
    Ok(take)
}

/// Records that a lookup found the send unsent under lease `generation`
/// (FIX 4747), while the TASK still holds that generation: a later send
/// under it does not look itself up again.
pub(super) fn mark_send_lookup_cleared(
    vault: &Vault,
    task_ref: EntityId,
    generation: u64,
    now: u64,
) -> Result<(), Error> {
    update_connector_send_task_body(vault, task_ref, now, |body| {
        if body
            .send_executor_lease
            .is_some_and(|lease| lease.generation == generation)
        {
            body.lookup_cleared_generation = Some(generation);
        }
        Ok(())
    })
}

/// Holds the TASK for the owner's word on a send that may have gone out and
/// that no lookup could settle (FIX 4747), in the caller's write. Returns the
/// hold it now carries and whether this call put it, so the owner's ask is
/// raised once; `None` for a TASK that permits no send any more. Engine call
/// (CALLS, FIX 4747): a Failed projection gives way, as the send is
/// uncertain now, not failed.
pub(super) fn hold_uncertain_send_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    now: u64,
) -> Result<Option<(UncertainSendHold, bool)>, Error> {
    let mut held = None;
    update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        if !connector_send_task_permits_send(body) {
            return Ok(());
        }
        if let Some(hold) = body.uncertain_send {
            held = Some((hold, false));
            return Ok(());
        }
        let hold = UncertainSendHold {
            asked_at: now,
            resend_released: false,
        };
        body.uncertain_send = Some(hold);
        body.outcome = None;
        held = Some((hold, true));
        Ok(())
    })?;
    Ok(held)
}

/// Applies the owner's answer to the ask the TASK's held send raised (FIX
/// 4747), in the caller's write: resend releases it for one send, and no
/// resend settles the TASK [`ConnectorSendTaskOutcome::OwnerDeclinedResend`].
/// Only a hold still waiting takes an answer; a second answer, or one for a
/// TASK that settled meanwhile, changes nothing. Returns what it came to and
/// the hold it answered.
pub(super) fn answer_uncertain_send_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    resend: bool,
    now: u64,
) -> Result<(UncertainSendAnswerOutcome, Option<UncertainSendHold>), Error> {
    let mut answered = (UncertainSendAnswerOutcome::AlreadySettled, None);
    update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        let Some(hold) = body.uncertain_send.filter(|hold| !hold.resend_released) else {
            return Ok(());
        };
        if !connector_send_task_permits_send(body) {
            return Ok(());
        }
        if resend {
            body.uncertain_send = Some(UncertainSendHold {
                resend_released: true,
                ..hold
            });
            answered = (UncertainSendAnswerOutcome::ResendReleased, Some(hold));
        } else {
            body.uncertain_send = None;
            body.outcome = Some(ConnectorSendTaskOutcome::OwnerDeclinedResend);
            body.suppression = None;
            answered = (UncertainSendAnswerOutcome::Declined, Some(hold));
        }
        Ok(())
    })?;
    Ok(answered)
}

/// The fence before the bytes (FIX 4747; canon ARCH-0023b "a woken old
/// machine re-checks before any send and stands down"): reads the TASK in a
/// fresh read and holds only while it still names the holder and generation
/// `fence` took. A renewal or a release since keeps that holding; an expired
/// lease no other machine took yet holds too, as no other machine sends it.
/// Every later slice that sends for a connector TASK reuses it.
pub(super) fn check_send_executor_fence(
    vault: &Vault,
    fence: &SendExecutorFence,
) -> Result<SendExecutorFenceCheck, Error> {
    let rtxn = vault.store.env.read_txn()?;
    let held = read_connector_send_task_body_in(vault, &rtxn, fence.task_ref)?.send_executor_lease;
    Ok(if held.is_some_and(|held| held.same_holding(fence.lease)) {
        SendExecutorFenceCheck::Holds
    } else {
        SendExecutorFenceCheck::StoodDown { held }
    })
}

/// Whether the transport call `fence` guards may go. A stand-down writes
/// its one log line here. Engine call (CALLS, FIX 4747): a TASK the fence
/// cannot read stands down too, so an unreadable TASK sends nothing.
pub(super) fn send_executor_fence_permits_send(vault: &Vault, fence: &SendExecutorFence) -> bool {
    match check_send_executor_fence(vault, fence) {
        Ok(SendExecutorFenceCheck::Holds) => true,
        Ok(SendExecutorFenceCheck::StoodDown { held }) => {
            log_send_executor_stand_down(
                fence.task_ref,
                fence.lease.node_id,
                Some(fence.lease.generation),
                held,
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                reason = "send_executor_fence_unread",
                task = %fence.task_ref.to_hex(),
                node_id = fence.lease.node_id,
                attempt_generation = fence.lease.generation,
                %error,
                "a connector send stood down: the fence could not read its TASK"
            );
            false
        }
    }
}

/// The one local log line a stand-down writes: the TASK, this machine's
/// node, the generation its attempt took (none when it took no lease), and
/// the lease the TASK holds now. It names no secret and no body.
pub(super) fn log_send_executor_stand_down(
    task_ref: EntityId,
    node_id: u64,
    attempt_generation: Option<u64>,
    held: Option<SendExecutorLease>,
) {
    tracing::warn!(
        reason = "send_executor_stood_down",
        task = %task_ref.to_hex(),
        node_id,
        attempt_generation = ?attempt_generation,
        held_node_id = ?held.map(|lease| lease.node_id),
        held_generation = ?held.map(|lease| lease.generation),
        "a connector send stood down: this machine does not hold its TASK's send executor lease"
    );
}

/// The lease a handover to `to_node` at `now` leaves on the TASK: `to_node`
/// at the next generation, held for one hold from `now`. Engine call
/// (CALLS, FIX 4747): a handover to the machine that already holds the
/// lease keeps its holder and generation, renewed for one hold from `now`
/// (FIX 4747 slice 4), so that machine's own attempt in flight still passes
/// its fence; once expired it is taken again at the next generation
/// (`own_expired_send_executor_lease_retaken`).
fn send_executor_lease_after_handover(
    held: Option<SendExecutorLease>,
    to_node: u64,
    now: u64,
) -> Result<SendExecutorLease, Error> {
    let held_until = send_executor_lease_held_until(now);
    match held {
        Some(lease) if lease.node_id == to_node => Ok(own_expired_send_executor_lease_retaken(
            lease, now,
        )
        .unwrap_or(SendExecutorLease {
            held_until: lease.held_until.max(held_until),
            ..lease
        })),
        Some(lease) => Ok(SendExecutorLease {
            node_id: to_node,
            generation: lease
                .generation
                .checked_add(1)
                .ok_or(Error::IndexOverflow("send executor lease generation"))?,
            held_until,
        }),
        None => Ok(SendExecutorLease {
            node_id: to_node,
            generation: SEND_EXECUTOR_LEASE_FIRST_GENERATION,
            held_until,
        }),
    }
}

/// The handover seam (FIX 4747; canon ARCH-0023b "a handover moves the
/// pending send's sticky executor to the new machine"): moves the send
/// executor lease of a TASK that still permits a send to `to_node` at the
/// next generation, in the caller's write. The old holder's fence then
/// stands it down, and the approved-but-unsent send goes from `to_node`
/// through the normal executor. It moves only the lease: the caller on the
/// new machine enqueues that machine's local attempt. FIX 4747 slice 4's
/// orphan reaper calls it (`super::send_reaper`); agent-run placement does
/// not yet.
pub(crate) fn hand_over_connector_send_task_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    to_node: u64,
    now: u64,
) -> Result<SendExecutorHandover, Error> {
    let mut handover = SendExecutorHandover::Closed;
    update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        if !connector_send_task_permits_send(body) {
            return Ok(());
        }
        let held = body.send_executor_lease;
        let lease = send_executor_lease_after_handover(held, to_node, now)?;
        handover = if held.is_some_and(|held| held.same_holding(lease)) {
            SendExecutorHandover::AlreadyHeld(lease)
        } else {
            SendExecutorHandover::Moved(lease)
        };
        body.send_executor_lease = Some(lease);
        Ok(())
    })?;
    Ok(handover)
}

/// Renews this machine's send executor lease on `task_ref` through the
/// pass that next comes back to the TASK at `next_pass_at` (FIX 4747 slice
/// 4), in the caller's write: the pass that parks or holds the TASK keeps
/// its lease through the park (`send_executor_lease_renewal`). A TASK this
/// machine does not hold, one that permits no send, and one that does not
/// read as a connector-send TASK are left as they are: a renewal never
/// fails the write that parks the send.
pub(super) fn renew_send_executor_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    next_pass_at: u64,
    now: u64,
) -> Result<(), Error> {
    if vault
        .executor_leases_released
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        return Ok(());
    }
    let Some(node_id) = crate::identity::read_client_id_in_txn(vault, &*wtxn)? else {
        return Ok(());
    };
    let Some(raw) = vault.store.port_entity_record(&*wtxn, &task_ref)? else {
        return Ok(());
    };
    let Ok(body) = decode_connector_send_task_body(raw.entity_type, &raw.body) else {
        return Ok(());
    };
    let renewal = body
        .send_executor_lease
        .filter(|lease| lease.node_id == node_id && connector_send_task_permits_send(&body))
        .and_then(|lease| {
            own_expired_send_executor_lease_retaken(lease, now).or_else(|| {
                send_executor_lease_renewal(lease.held_until, next_pass_at).map(|held_until| {
                    SendExecutorLease {
                        held_until,
                        ..lease
                    }
                })
            })
        });
    let Some(renewed) = renewal else {
        return Ok(());
    };
    update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        body.send_executor_lease = Some(renewed);
        Ok(())
    })
}

/// Releases this machine's (`node_id`) send executor lease on `task_ref`
/// as it closes (FIX 4747 slice 4), in the caller's write: the lease keeps
/// its holder and generation and is held until `now`, so another machine's
/// reaper may take it at once. `false` for a TASK this machine does not
/// hold, one that permits no send, or a lease already expired at `now`.
pub(super) fn release_send_executor_lease_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    node_id: u64,
    now: u64,
) -> Result<bool, Error> {
    let mut released = false;
    update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        if !connector_send_task_permits_send(body) {
            return Ok(());
        }
        if let Some(lease) = body.send_executor_lease.as_mut()
            && lease.node_id == node_id
            && !lease.expired_at(now)
        {
            lease.held_until = now;
            released = true;
        }
        Ok(())
    })?;
    Ok(released)
}

/// The send executor lease `task_ref` holds, read in `txn` (FIX 4747 slice
/// 4); `None` while no machine took it.
pub(super) fn send_executor_lease_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<SendExecutorLease>, Error> {
    Ok(read_connector_send_task_body_in(vault, txn, task_ref)?.send_executor_lease)
}

/// Every connector-send TASK that still permits a send and that a machine
/// took, with the lease it holds, read in `txn` (FIX 4747 slice 4): what the
/// release and the reaper judge. A TASK body that does not decode as the
/// current connector-send version is passed over.
pub(super) fn open_send_executor_leases_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, SendExecutorLease)>, Error> {
    let mut leases = Vec::new();
    for task_ref in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_TASK, None)?
    {
        let task_ref = task_ref?;
        let Some(raw) = vault.store.port_entity_record(txn, &task_ref)? else {
            continue;
        };
        if !matches!(has_connector_send_subkind(&raw.body), Ok(true)) {
            continue;
        }
        let Ok(body) = decode_connector_send_task_body(raw.entity_type, &raw.body) else {
            continue;
        };
        if let Some(lease) = body
            .send_executor_lease
            .filter(|_| connector_send_task_permits_send(&body))
        {
            leases.push((task_ref, lease));
        }
    }
    Ok(leases)
}

pub(super) fn project_connector_send_task_outcome(
    vault: &Vault,
    task_ref: EntityId,
    outcome: ConnectorSendTaskOutcome,
    now: u64,
) -> Result<(), Error> {
    #[cfg(test)]
    if outcome == ConnectorSendTaskOutcome::Delivered {
        let receipt_exists = send_receipt_exists_for_task(vault, task_ref)?;
        DELIVERED_PROJECTION_SAW_RECEIPT.with(|observed| observed.set(Some(receipt_exists)));
    }
    #[cfg(test)]
    if outcome == ConnectorSendTaskOutcome::Failed {
        let receipt_exists = vault.store.get_send_receipt_by_task(&task_ref)?.is_some();
        FAILED_PROJECTION_SAW_RECEIPT.with(|observed| observed.set(Some(receipt_exists)));
    }
    update_connector_send_task_body(vault, task_ref, now, |body| {
        body.outcome = Some(outcome);
        body.suppression = None;
        Ok(())
    })
}

/// The synced suppression of a send the owner took back inside its
/// undo-send window (DEC-0006 #undo-send).
pub(super) const UNDO_SEND_SUPPRESSION: &str = "undo_send";

/// Settles the TASK of a send the owner took back inside its undo-send
/// window (DEC-0006 #undo-send), in the caller's write: failed, with the
/// synced reason [`UNDO_SEND_SUPPRESSION`], so no machine takes it to send
/// again ([`connector_send_task_permits_send`]).
pub(super) fn project_connector_send_task_undone_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    now: u64,
) -> Result<(), Error> {
    update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        body.outcome = Some(ConnectorSendTaskOutcome::Failed);
        body.suppression = Some(UNDO_SEND_SUPPRESSION.to_owned());
        Ok(())
    })
}

pub(super) fn project_connector_send_task_suppression_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    now: u64,
    delivered_won: bool,
) -> Result<(), Error> {
    update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        if delivered_won || body.outcome == Some(ConnectorSendTaskOutcome::Delivered) {
            body.outcome = Some(ConnectorSendTaskOutcome::Delivered);
            body.suppression = None;
        } else {
            body.outcome = Some(ConnectorSendTaskOutcome::Failed);
            body.suppression = Some("dedupe".to_owned());
        }
        Ok(())
    })
}

#[cfg(test)]
pub(super) fn reset_delivered_projection_receipt_observation() {
    DELIVERED_PROJECTION_SAW_RECEIPT.with(|observed| observed.set(None));
}

#[cfg(test)]
pub(super) fn delivered_projection_receipt_observation() -> Option<bool> {
    DELIVERED_PROJECTION_SAW_RECEIPT.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(super) fn reset_failed_projection_receipt_observation() {
    FAILED_PROJECTION_SAW_RECEIPT.with(|observed| observed.set(None));
}

#[cfg(test)]
pub(super) fn failed_projection_receipt_observation() -> Option<bool> {
    FAILED_PROJECTION_SAW_RECEIPT.with(std::cell::Cell::get)
}

fn update_connector_send_task_body(
    vault: &Vault,
    task_ref: EntityId,
    now: u64,
    update: impl FnOnce(&mut ConnectorSendTaskBody) -> Result<(), Error>,
) -> Result<(), Error> {
    vault.with_write_txn_grouped(|wtxn| {
        update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, update)
    })
}

/// Read the synced terminal in the same writer that settles this attempt.
pub(super) fn connector_send_task_outcome_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<ConnectorSendTaskOutcome>, Error> {
    Ok(read_connector_send_task_body_in(vault, wtxn, task_ref)?.outcome)
}

/// The stored connector-send TASK body, read in `txn`.
fn read_connector_send_task_body_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<ConnectorSendTaskBody, Error> {
    let raw = vault
        .store
        .port_entity_record(txn, &task_ref)?
        .ok_or(Error::EntityNotFound)?;
    decode_connector_send_task_body(raw.entity_type, &raw.body)
}

/// Decodes a stored connector-send TASK body of the current version.
fn decode_connector_send_task_body(
    entity_type: u8,
    body: &[u8],
) -> Result<ConnectorSendTaskBody, Error> {
    if entity_type != ENTITY_TYPE_TASK {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "connector send entity is not a TASK",
        )));
    }
    let body: ConnectorSendTaskBody = rmp_serde::from_slice(body)
        .map_err(|_| Error::Record(RecordError::InvalidTaskBody("invalid connector send body")))?;
    if body.schema_version != CONNECTOR_SEND_TASK_SCHEMA_VERSION
        || body.subkind != CONNECTOR_SEND_TASK_SUBKIND
        || body.role != TaskRole::Task.role_byte()
    {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "unsupported connector send body version",
        )));
    }
    Ok(body)
}

pub(super) fn project_connector_send_task_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    outcome: ConnectorSendTaskOutcome,
    now: u64,
) -> Result<(), Error> {
    #[cfg(test)]
    if matches!(
        outcome,
        ConnectorSendTaskOutcome::Delivered | ConnectorSendTaskOutcome::Failed
    ) {
        let receipt_exists = vault
            .store
            .get_send_receipt_by_task_in_txn(wtxn, &task_ref)?
            .is_some();
        if outcome == ConnectorSendTaskOutcome::Delivered {
            DELIVERED_PROJECTION_SAW_RECEIPT.with(|observed| observed.set(Some(receipt_exists)));
        } else {
            FAILED_PROJECTION_SAW_RECEIPT.with(|observed| observed.set(Some(receipt_exists)));
        }
    }
    update_connector_send_task_body_in_txn(vault, wtxn, task_ref, now, |body| {
        body.outcome = Some(outcome);
        body.suppression = None;
        Ok(())
    })
}

fn update_connector_send_task_body_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    now: u64,
    update: impl FnOnce(&mut ConnectorSendTaskBody) -> Result<(), Error>,
) -> Result<(), Error> {
    let raw = vault
        .store
        .port_entity_record(&*wtxn, &task_ref)?
        .ok_or(Error::EntityNotFound)?;
    let mut body = decode_connector_send_task_body(raw.entity_type, &raw.body)?;
    update(&mut body)?;
    let encoded = rmp_serde::to_vec_named(&body)
        .map_err(|_| Error::InvariantViolation("connector task body encode failed"))?;
    // A no-op update writes NOTHING. The executor re-takes its lease on
    // every claim, so a send that keeps parking (a gate hold waiting on a
    // person, a window edge) would otherwise rewrite an identical body and
    // bump the entity's learned time once per poll — a growing trail of
    // writes that says the TASK changed when it did not. Comparing the
    // encoded bytes against what is stored makes the retry loop leave the
    // row byte-identical, while any real projection — the terminal
    // outcome, a timezone refresh, a node taking the send executor lease, a
    // handover — still differs in bytes and writes exactly once. A lease
    // renewal writes only once less than half its hold is left
    // (`send_executor_lease_renewal`), so a send that keeps parking still
    // writes its TASK at most once a half hold.
    if raw.body == encoded[..] {
        return Ok(());
    }
    vault
        .batch_in()
        .put(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: body.occurred_at,
                end: body.occurred_at,
            },
            now,
            &encoded,
        )
        .apply(wtxn)
}

fn has_connector_send_subkind(body: &[u8]) -> Result<bool, Error> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(body)).map_err(|_| {
        Error::Record(RecordError::InvalidTaskBody(
            "body is not valid MessagePack",
        ))
    })?;
    Ok(value.as_map().is_some_and(|entries| {
        entries.iter().any(|(key, value)| {
            key.as_str() == Some("subkind") && value.as_str() == Some(CONNECTOR_SEND_TASK_SUBKIND)
        })
    }))
}

pub(super) fn connector_actor_matches(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor_ref: EntityId,
    connector_class: &str,
) -> Result<bool, Error> {
    let Some(raw) = vault.get_raw_in(txn, &actor_ref)? else {
        return Ok(false);
    };
    connector_actor_raw_matches(&raw, connector_class)
}

fn connector_actor_raw_matches(raw: &[u8], connector_class: &str) -> Result<bool, Error> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex("connector actor entity header"));
    };
    if header.entity_type != ENTITY_TYPE_MACHINE {
        return Ok(false);
    }
    let body: ConnectorActorBody = rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("connector actor body"))?;
    Ok(body.schema_version == CONNECTOR_ACTOR_SCHEMA_VERSION
        && body.actor_kind == CONNECTOR_ACTOR_KIND
        && body.connector_class == normalize_key(connector_class))
}

pub(super) fn send_receipt_exists_for_task(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<bool, Error> {
    Ok(delivered_send_receipt_for_task(vault, task_ref)?.is_some())
}
