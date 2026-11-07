//! The durable connector-send task substrate.
//! Entry: `ConnectorSendTask`.
//! Defines its own items.

use crate::ports::EntityStoreRead;
use serde::{Deserialize, Serialize};

use super::capability::normalize_key;
use super::intent::OutboundIntent;
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
}

/// The sticky send executor of one connector-send TASK (FIX 4747; canon
/// ARCH-0023b, pending outbound send): only the machine `node_id` names
/// sends it, and only while the TASK still holds this exact lease. A
/// handover moves it to another machine at the next `generation`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendExecutorLease {
    /// The holder's stable sync node id (`m:client_id`).
    pub node_id: u64,
    /// Raised by one on every handover; a take from no lease starts at
    /// [`SEND_EXECUTOR_LEASE_FIRST_GENERATION`].
    pub generation: u64,
}

/// The generation a send executor lease starts at when a machine takes a
/// TASK no machine held. Engine call (CALLS, FIX 4747).
pub(super) const SEND_EXECUTOR_LEASE_FIRST_GENERATION: u64 = 1;

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SendExecutorLeaseTake {
    /// This machine holds the lease; its attempt sends under it.
    Taken(SendExecutorLease),
    /// Another machine holds the lease: this machine stands down and sends
    /// nothing.
    HeldElsewhere(SendExecutorLease),
    /// The TASK permits no new send: delivered, possibly delivered, or
    /// mechanically suppressed.
    Closed,
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
/// failure remains retryable; delivered, ambiguous and mechanically
/// suppressed outcomes must never become new send permits. Engine call
/// (CALLS, FIX 4747): the lease take and the handover share this one rule,
/// so a Failed TASK may still be taken and handed over, as it was retryable
/// before the lease.
fn connector_send_task_permits_send(body: &ConnectorSendTaskBody) -> bool {
    !matches!(
        body.outcome,
        Some(ConnectorSendTaskOutcome::Ambiguous | ConnectorSendTaskOutcome::Delivered)
    ) && body.suppression.is_none()
}

/// Takes the TASK's send executor lease for `node_id` (FIX 4747): no lease
/// becomes this node's at the first generation; this node's lease stays as
/// it is; another node's lease is not taken, and this node stands down.
/// Checked against the CURRENT replicated TASK in one write transaction.
pub(super) fn take_send_executor_lease(
    vault: &Vault,
    task_ref: EntityId,
    node_id: u64,
    now: u64,
) -> Result<SendExecutorLeaseTake, Error> {
    let mut take = SendExecutorLeaseTake::Closed;
    update_connector_send_task_body(vault, task_ref, now, |body| {
        if !connector_send_task_permits_send(body) {
            return Ok(());
        }
        let held = body.send_executor_lease;
        take = match held {
            None => {
                let lease = SendExecutorLease {
                    node_id,
                    generation: SEND_EXECUTOR_LEASE_FIRST_GENERATION,
                };
                body.send_executor_lease = Some(lease);
                SendExecutorLeaseTake::Taken(lease)
            }
            Some(lease) if lease.node_id == node_id => SendExecutorLeaseTake::Taken(lease),
            Some(lease) => SendExecutorLeaseTake::HeldElsewhere(lease),
        };
        Ok(())
    })?;
    Ok(take)
}

/// The fence before the bytes (FIX 4747; canon ARCH-0023b "a woken old
/// machine re-checks before any send and stands down"): reads the TASK in a
/// fresh read and holds only while it still names exactly the lease
/// `fence` took. Every later slice that sends for a connector TASK reuses
/// it.
pub(super) fn check_send_executor_fence(
    vault: &Vault,
    fence: &SendExecutorFence,
) -> Result<SendExecutorFenceCheck, Error> {
    let rtxn = vault.store.env.read_txn()?;
    let held = read_connector_send_task_body_in(vault, &rtxn, fence.task_ref)?.send_executor_lease;
    Ok(if held == Some(fence.lease) {
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

/// The lease a handover to `to_node` leaves on the TASK: `to_node` at the
/// next generation. Engine call (CALLS, FIX 4747): a handover to the
/// machine that already holds the lease keeps it unchanged, so that
/// machine's own attempt in flight still passes its fence.
fn send_executor_lease_after_handover(
    held: Option<SendExecutorLease>,
    to_node: u64,
) -> Result<SendExecutorLease, Error> {
    match held {
        Some(lease) if lease.node_id == to_node => Ok(lease),
        Some(lease) => Ok(SendExecutorLease {
            node_id: to_node,
            generation: lease
                .generation
                .checked_add(1)
                .ok_or(Error::IndexOverflow("send executor lease generation"))?,
        }),
        None => Ok(SendExecutorLease {
            node_id: to_node,
            generation: SEND_EXECUTOR_LEASE_FIRST_GENERATION,
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
/// orphan reaper and the placement order call it.
#[allow(
    dead_code,
    reason = "FIX 4747 slice 4: the orphan reaper and the placement order call it"
)]
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
        let lease = send_executor_lease_after_handover(body.send_executor_lease, to_node)?;
        handover = if body.send_executor_lease == Some(lease) {
            SendExecutorHandover::AlreadyHeld(lease)
        } else {
            body.send_executor_lease = Some(lease);
            SendExecutorHandover::Moved(lease)
        };
        Ok(())
    })?;
    Ok(handover)
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
    // handover — still differs in bytes and writes exactly once.
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
