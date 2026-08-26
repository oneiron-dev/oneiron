use serde::{Deserialize, Serialize};

use super::capability::normalize_key;
use super::intent::OutboundIntent;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::delivery_window::{DeliveryWindowApnsInterruptionLevel, DeliveryWindowResolvedLevel};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::habit::TaskRole;
use crate::receipt::delivered_send_receipt_for_task;
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_TASK};
use crate::temporal::TimeRange;

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
    pub(super) on_behalf_of: Option<String>,
    pub(super) content_ref: Option<String>,
    pub(super) idempotency_key: Option<String>,
    pub(super) dedupe_key: Option<String>,
    pub(super) intent_source: String,
    pub(super) trigger_ref: String,
    pub(super) job_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) originating_session_ref: Option<String>,
    /// Additive synced execution marker. Absence means no visible attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) attempt_started_node_id: Option<u64>,
    /// Additive synced terminal projection. Absence means outcome unknown or
    /// still in flight; device-local intent rows never enter this body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) outcome: Option<ConnectorSendTaskOutcome>,
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
    pub(super) occurred_at: u64,
}

/// Terminal delivery projection carried by the synced connector-send TASK.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSendTaskOutcome {
    Delivered,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ConnectorActorBody {
    pub(super) schema_version: u8,
    pub(super) actor_kind: String,
    pub(super) connector_class: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ConnectorSendAttemptPayload {
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
    pub originating_session_ref: Option<String>,
    pub attempt_started_node_id: Option<u64>,
    pub outcome: Option<ConnectorSendTaskOutcome>,
    /// Frozen host UTC offset in minutes. `None` ⇒ hostless schedule: the
    /// executor cannot derive a local minute and fails closed.
    pub utc_offset_minutes: Option<i16>,
    /// Provenance label only. Execution never consults a timezone database.
    pub iana_timezone: Option<String>,
    pub human_explicit_instant: bool,
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
    /// Host-resolved level for a compatibility verb; see
    /// [`DeliveryWindowResolvedLevel`].
    pub resolved_level: Option<DeliveryWindowResolvedLevel>,
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
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.connector_actor.v0\0");
    hash.update(connector_class.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes)
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
    schedule_context: &crate::memory::OutboundScheduleContext,
    occurred_at: u64,
) -> Result<(), Error> {
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
        on_behalf_of: intent.on_behalf_of.clone(),
        content_ref: intent.content_ref.clone(),
        idempotency_key: intent.idempotency_key.clone(),
        dedupe_key: intent.dedupe_key.clone(),
        intent_source: intent.intent_source.clone(),
        trigger_ref: intent.trigger_ref.clone(),
        job_ref: intent.job_ref.clone(),
        originating_session_ref: originating_session_ref.map(str::to_owned),
        attempt_started_node_id: None,
        outcome: None,
        utc_offset_minutes: schedule_context.utc_offset_minutes,
        iana_timezone: schedule_context.iana_timezone.clone(),
        human_explicit_instant: schedule_context.human_explicit_instant,
        apns_interruption_level: schedule_context.apns_interruption_level,
        resolved_level: schedule_context.resolved_level,
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
                .entities
                .get(&*wtxn, assignee_ref.as_bytes())?
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
        let Some(raw) = self.get_raw(task_ref)? else {
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
        if crate::habit::task_role_from_body_bytes(body_bytes)? != TaskRole::Task {
            return Err(Error::InvalidTaskBody(
                "connector send must use the Task role",
            ));
        }
        let body: ConnectorSendTaskBody = rmp_serde::from_slice(body_bytes)
            .map_err(|_| Error::InvalidTaskBody("invalid connector send body"))?;
        if body.schema_version != CONNECTOR_SEND_TASK_SCHEMA_VERSION
            || body.subkind != CONNECTOR_SEND_TASK_SUBKIND
        {
            return Err(Error::InvalidTaskBody(
                "unsupported connector send body version",
            ));
        }
        let actor_ref = EntityId::from_hex(&body.actor_ref)
            .map_err(|_| Error::InvalidTaskBody("invalid connector send actor"))?;
        let actor_class = match body.actor_class.as_str() {
            "human" => EdgeActorClass::Human,
            "agent" => EdgeActorClass::Agent,
            "system" => EdgeActorClass::System,
            _ => {
                return Err(Error::InvalidTaskBody("invalid connector send actor class"));
            }
        };
        let assignee_ref = connector_actor_id(&body.channel)?;
        let assigned = self
            .edges_out(task_ref)?
            .into_iter()
            .any(|edge| edge.kind == EdgeKind::AssignedTo && edge.target == assignee_ref);
        if !assigned || !connector_actor_matches(self, assignee_ref, &body.channel)? {
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
            },
            originating_session_ref: body.originating_session_ref,
            attempt_started_node_id: body.attempt_started_node_id,
            outcome: body.outcome,
            utc_offset_minutes: body.utc_offset_minutes,
            iana_timezone: body.iana_timezone,
            human_explicit_instant: body.human_explicit_instant,
            apns_interruption_level: body.apns_interruption_level,
            resolved_level: body.resolved_level,
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
            .ok_or(Error::InvalidTaskBody("missing connector send task"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("connector task entity header"))?;
        if header.entity_type != ENTITY_TYPE_TASK || raw.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(Error::InvalidTaskBody("invalid connector task header"));
        }
        let body: ConnectorSendTaskBody = rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::InvalidTaskBody("invalid connector send body"))?;
        if body.role != 1
            || body.schema_version != CONNECTOR_SEND_TASK_SCHEMA_VERSION
            || body.subkind != CONNECTOR_SEND_TASK_SUBKIND
        {
            return Err(Error::InvalidTaskBody("unsupported connector send body"));
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
            return Err(Error::InvalidTaskBody("utc offset out of range"));
        }
        if iana_timezone.is_some_and(|s| {
            s.trim().is_empty() || s.len() > 255 || s.chars().any(char::is_control)
        }) {
            return Err(Error::InvalidTaskBody("invalid IANA timezone"));
        }
        // Check terminality in the same write transaction that hydrates the fields.
        update_connector_send_task_body(self, task_ref, learned_at, |body| {
            if body.outcome.is_some() {
                return Err(Error::InvalidTaskBody(
                    "terminal connector task cannot refresh timezone",
                ));
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

pub(super) fn mark_connector_send_task_attempt_started(
    vault: &Vault,
    task_ref: EntityId,
    node_id: u64,
    now: u64,
) -> Result<(), Error> {
    update_connector_send_task_body(vault, task_ref, now, |body| {
        body.attempt_started_node_id = Some(node_id);
        body.outcome = None;
        Ok(())
    })
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
    vault.with_write_txn(|wtxn| {
        let raw = vault
            .store
            .entities
            .get(&*wtxn, task_ref.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("connector task entity header"))?;
        if header.entity_type != ENTITY_TYPE_TASK {
            return Err(Error::InvalidTaskBody(
                "connector send entity is not a TASK",
            ));
        }
        let mut body: ConnectorSendTaskBody =
            rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| Error::InvalidTaskBody("invalid connector send body"))?;
        if body.schema_version != CONNECTOR_SEND_TASK_SCHEMA_VERSION
            || body.subkind != CONNECTOR_SEND_TASK_SUBKIND
            || body.role != TaskRole::Task.role_byte()
        {
            return Err(Error::InvalidTaskBody(
                "unsupported connector send body version",
            ));
        }
        update(&mut body)?;
        let encoded = rmp_serde::to_vec_named(&body)
            .map_err(|_| Error::InvariantViolation("connector task body encode failed"))?;
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
    })
}

fn has_connector_send_subkind(body: &[u8]) -> Result<bool, Error> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(body))
        .map_err(|_| Error::InvalidTaskBody("body is not valid MessagePack"))?;
    Ok(value.as_map().is_some_and(|entries| {
        entries.iter().any(|(key, value)| {
            key.as_str() == Some("subkind") && value.as_str() == Some(CONNECTOR_SEND_TASK_SUBKIND)
        })
    }))
}

pub(super) fn connector_actor_matches(
    vault: &Vault,
    actor_ref: EntityId,
    connector_class: &str,
) -> Result<bool, Error> {
    let Some(raw) = vault.get_raw(&actor_ref)? else {
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
