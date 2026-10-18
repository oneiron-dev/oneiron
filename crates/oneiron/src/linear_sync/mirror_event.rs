//! The mirror's durable event rows and each TASK's mirror control (OF-427).
//!
//! One row per consumed webhook delivery, sent push, mapping edit and title
//! edit, keyed by a direction byte and a 32-byte digest: the delivery id's
//! digest inbound, the operation id outbound, the TASK and intent key of a
//! mapping edit, the TASK, actor and report key of a title edit. A row is the
//! replay identity of what made it and its evidence; no gate or proof reads
//! it. A second table orders one TASK's rows by time for the provenance read.
//!
//! The control row qualifies the link: whether the TASK is opted out of the
//! mirror and the revision every mapping edit compares and moves (C6). No
//! row is the default, mirrored at revision zero.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};

use super::model::{LinearFieldConflict, LinearIssueRef, LinearMirrorReceipt, LinearWriteActor};
use super::webhook::LinearExternalActor;

/// The first byte of an event key: what made the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventDirection {
    /// A verified webhook delivery.
    IssueToTask = 1,
    /// A push the scheduler sent.
    TaskToIssue = 2,
    /// A mapping edit (link, unlink, mirror).
    MappingEdit = 3,
    /// A public title edit on `tasks.update`.
    TaskEdit = 4,
}

impl EventDirection {
    /// The row's stable wire token.
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::IssueToTask => "issue_to_task",
            Self::TaskToIssue => "task_to_issue",
            Self::MappingEdit => "mapping_edit",
            Self::TaskEdit => "task_edit",
        }
    }
}

/// A direction byte and a 32-byte digest.
pub(crate) type EventKey = [u8; 33];

const DELIVERY_DOMAIN: &[u8] = b"oneiron:linear-mirror-delivery:v1";
const MAPPING_DOMAIN: &[u8] = b"oneiron:linear-mirror-mapping:v1";
const TASK_EDIT_DOMAIN: &[u8] = b"oneiron:linear-mirror-task-edit:v1";
const BODY_DOMAIN: &[u8] = b"oneiron:linear-mirror-body:v1";

const EVENTS: SideTable<EventKey, LinearMirrorEvent, Named> =
    SideTable::new(&side_table::LINEAR_MIRROR_EVENT);
const BY_TASK: SideTable<(EntityId, u64, EventKey), (), Raw> =
    SideTable::new(&side_table::LINEAR_MIRROR_EVENT_BY_TASK);
const CONTROLS: SideTable<EntityId, LinearMirrorControl, Named> =
    SideTable::new(&side_table::LINEAR_MIRROR_CONTROL);

/// One stored mirror event, as the provenance read returns it. Refs and
/// digests are lowercase hex; the external actor is the provider's own
/// evidence, never a vault actor, writer or owner (C3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearMirrorEvent {
    /// `issue_to_task`, `task_to_issue`, `mapping_edit` or `task_edit`.
    pub direction: String,
    /// The TASK the event changed or names; `None` for an ignored delivery.
    pub task_ref: Option<String>,
    /// The issue the event names.
    pub issue: Option<LinearIssueRef>,
    /// The `Linear-Delivery` id of a webhook.
    pub delivery_id: Option<String>,
    /// The mirror operation id the event applied or sent.
    pub operation_id: Option<String>,
    /// Digest of the request the event's key names: a webhook's raw body,
    /// an edit's request.
    pub body_digest: Option<String>,
    /// The archived provider body of a webhook.
    pub payload_ref: Option<String>,
    /// The provider's actor of a webhook.
    pub external_actor: Option<LinearExternalActor>,
    /// The provider's webhook id.
    pub webhook_id: Option<String>,
    /// The provider's organization id.
    pub organization_id: Option<String>,
    /// The provider's `webhookTimestamp`, kept as evidence only.
    pub webhook_timestamp_ms: Option<u64>,
    /// The mirrored fields a webhook says it changed.
    pub changed_fields: Vec<String>,
    /// What happened: `applied`, `conflict`, `noop`, `ignored`, `admitted`,
    /// `linked`, `link`, `unlink`, `mirror` or `edited`.
    pub status: String,
    /// The fields both sides moved.
    pub conflicts: Vec<LinearFieldConflict>,
    /// The verified vault writer of a push or an edit.
    pub writer_actor: Option<String>,
    /// That writer's actor class.
    pub writer_class: Option<String>,
    /// The gate decision that admitted a push.
    pub gate_ref: Option<String>,
    /// The JSON receipt the event answered, which a replay answers again.
    pub receipt: Option<String>,
    /// The vault clock when the event was recorded.
    pub at: u64,
}

impl LinearMirrorEvent {
    /// A row of `direction` with `status` and nothing else known yet.
    pub(crate) fn blank(direction: EventDirection, status: &str, at: u64) -> Self {
        Self {
            direction: direction.token().to_owned(),
            task_ref: None,
            issue: None,
            delivery_id: None,
            operation_id: None,
            body_digest: None,
            payload_ref: None,
            external_actor: None,
            webhook_id: None,
            organization_id: None,
            webhook_timestamp_ms: None,
            changed_fields: Vec::new(),
            status: status.to_owned(),
            conflicts: Vec::new(),
            writer_actor: None,
            writer_class: None,
            gate_ref: None,
            receipt: None,
            at,
        }
    }

    /// Names `actor` of `class` as the row's verified writer.
    pub(crate) fn written_by(&mut self, actor: EntityId, class: EdgeActorClass) {
        self.writer_actor = Some(actor.to_hex());
        self.writer_class = Some(class.gate_actor_class().to_owned());
    }
}

/// One mirror operation's outcome, as a receipt and a row carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinearMirrorRecord {
    /// `linked`, `applied`, `noop` or `conflict`.
    pub status: String,
    /// `task_to_issue` or `issue_to_task`.
    pub direction: String,
    /// The stable operation id, in hex.
    pub operation_id: String,
    /// The fields both sides moved.
    pub conflicts: Vec<LinearFieldConflict>,
    /// The mirror's own stamp of the operation.
    pub mirrored_at: u64,
}

impl From<&LinearMirrorReceipt> for LinearMirrorRecord {
    fn from(receipt: &LinearMirrorReceipt) -> Self {
        Self {
            status: receipt.status.as_str().to_owned(),
            direction: receipt.direction.as_str().to_owned(),
            operation_id: bytes_to_hex_lower(&receipt.operation_id),
            conflicts: receipt.conflicts.clone(),
            mirrored_at: receipt.mirrored_at,
        }
    }
}

/// One TASK's mirror control (C6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinearMirrorControl {
    /// The scheduler pushes nothing for an opted-out TASK.
    pub(crate) opted_out: bool,
    /// Compared and moved by every mapping edit.
    pub(crate) mapping_revision: u64,
    /// The intent key of the last mapping edit.
    pub(crate) last_intent_key: Option<String>,
    /// The JSON receipt of the last mapping edit.
    pub(crate) last_receipt: Option<String>,
    /// Who made the last mapping edit, in hex.
    pub(crate) by: Option<String>,
    /// The vault clock of the last mapping edit.
    pub(crate) at: u64,
}

fn keyed(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// The key of one row: its direction byte, then its digest.
pub(crate) fn event_key(direction: EventDirection, digest: &[u8; 32]) -> EventKey {
    let mut key = [0; 33];
    key[0] = direction as u8;
    key[1..].copy_from_slice(digest);
    key
}

/// The key of one webhook delivery.
pub(crate) fn delivery_key(delivery_id: &str) -> EventKey {
    event_key(
        EventDirection::IssueToTask,
        &keyed(DELIVERY_DOMAIN, &[delivery_id.as_bytes()]),
    )
}

/// The key of one sent push: its operation id.
pub(crate) fn outbound_key(operation_id: &[u8; 32]) -> EventKey {
    event_key(EventDirection::TaskToIssue, operation_id)
}

/// The key of one mapping edit: its TASK and intent key.
pub(crate) fn mapping_key(task: EntityId, intent_key: &str) -> EventKey {
    event_key(
        EventDirection::MappingEdit,
        &keyed(MAPPING_DOMAIN, &[task.as_bytes(), intent_key.as_bytes()]),
    )
}

/// The key of one title edit: its TASK, actor and qualified report key.
pub(crate) fn task_edit_key(task: EntityId, actor: EntityId, report_key: &str) -> EventKey {
    event_key(
        EventDirection::TaskEdit,
        &keyed(
            TASK_EDIT_DOMAIN,
            &[task.as_bytes(), actor.as_bytes(), report_key.as_bytes()],
        ),
    )
}

/// The hex digest an edit's request is compared by on a replay.
pub(crate) fn request_digest(parts: &[&[u8]]) -> String {
    bytes_to_hex_lower(&keyed(BODY_DOMAIN, parts))
}

fn task_of(row: &LinearMirrorEvent) -> Option<EntityId> {
    row.task_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
}

/// The row `key` holds.
pub(crate) fn event_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &EventKey,
) -> Result<Option<LinearMirrorEvent>> {
    EVENTS.get(vault, txn, key)
}

/// Writes `row` under `key` with its TASK's time index, replacing what the
/// key held and that row's index entry.
pub(crate) fn put_event_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &EventKey,
    row: &LinearMirrorEvent,
) -> Result<()> {
    if let Some(old) = EVENTS.get(vault, txn, key)?
        && let Some(task) = task_of(&old)
    {
        BY_TASK.delete(vault, txn, &(task, old.at, *key))?;
    }
    EVENTS.put(vault, txn, key, row)?;
    if let Some(task) = task_of(row) {
        BY_TASK.put(vault, txn, &(task, row.at, *key), &())?;
    }
    Ok(())
}

/// Where a provenance page resumes: the time and key of the last row it read.
pub(crate) type EventCursor = (u64, EventKey);

/// One page of `task`'s rows, newest first, strictly before `after`, and
/// where the next page resumes when more rows remain.
pub(crate) fn task_events_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    after: Option<EventCursor>,
    limit: usize,
) -> Result<(Vec<(EventKey, LinearMirrorEvent)>, Option<EventCursor>)> {
    let low = (task, 0, [0; 33]);
    let keys: Vec<EventCursor> = match after {
        Some((at, key)) => {
            let high = (task, at, key);
            BY_TASK
                .iter_rev_range(vault, txn, Bound::Included(&low), Bound::Excluded(&high))?
                .take(limit.saturating_add(1))
                .map(|row| row.map(|((_, at, key), ())| (at, key)))
                .collect::<Result<_>>()?
        }
        None => BY_TASK
            .iter_rev_from(vault, txn, task.as_bytes())?
            .take(limit.saturating_add(1))
            .map(|row| row.map(|((_, at, key), ())| (at, key)))
            .collect::<Result<_>>()?,
    };
    let more = keys.len() > limit;
    let mut rows = Vec::with_capacity(keys.len().min(limit));
    let mut last = None;
    for (at, key) in keys.into_iter().take(limit) {
        let row = EVENTS
            .get(vault, txn, &key)?
            .ok_or(Error::CorruptedIndex("linear mirror event index"))?;
        last = Some((at, key));
        rows.push((key, row));
    }
    Ok((rows, if more { last } else { None }))
}

/// `task`'s control row, or the default when it has none.
pub(crate) fn control_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<LinearMirrorControl> {
    Ok(CONTROLS.get(vault, txn, &task)?.unwrap_or_default())
}

pub(crate) fn put_control_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    control: &LinearMirrorControl,
) -> Result<()> {
    CONTROLS.put(vault, txn, &task, control)
}

/// Drops a deleted TASK's control row in its delete's transaction. Its event
/// rows stay, so a consumed delivery is never applied again.
pub(crate) fn forget_mirror_control_in(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
) -> Result<()> {
    CONTROLS.delete(store, txn, &task)?;
    Ok(())
}

/// Whether `task` is opted out of the mirror (C6).
pub(crate) fn mirror_opted_out_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<bool> {
    Ok(control_in(vault, txn, task)?.opted_out)
}

fn writer_parts(writer: LinearWriteActor) -> (String, Option<String>) {
    (
        writer.actor_ref.to_hex(),
        EdgeActorClass::try_from_u8(writer.actor_class)
            .map(|class| class.gate_actor_class().to_owned()),
    )
}

/// The admitted half of one push's row (C9), in its admission's
/// transaction: the gate ref [`Vault::authorize_linear_effect`] returned and
/// the verified writer. A retried admission keeps the first gate ref.
pub(crate) fn note_outbound_admitted_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &super::LinearEffectRequest,
    writer: LinearWriteActor,
    gate_ref: &str,
) -> Result<()> {
    let key = outbound_key(&request.operation_id);
    if EVENTS
        .get(vault, txn, &key)?
        .is_some_and(|row| row.gate_ref.is_some())
    {
        return Ok(());
    }
    let mut row = LinearMirrorEvent::blank(
        EventDirection::TaskToIssue,
        "admitted",
        vault.now_recorded_at(),
    );
    row.task_ref = Some(request.task_ref.to_hex());
    row.issue.clone_from(&request.issue);
    row.operation_id = Some(bytes_to_hex_lower(&request.operation_id));
    let (actor, class) = writer_parts(writer);
    row.writer_actor = Some(actor);
    row.writer_class = class;
    row.gate_ref = Some(gate_ref.to_owned());
    put_event_in(vault, txn, &key, &row)
}

/// Records one push a scheduler pass sent (C9) under its operation id,
/// keeping the gate ref and writer its admission recorded; `writer` names
/// the dirty revision's writer when no admission row did.
pub(crate) fn record_outbound(
    vault: &Vault,
    receipt: &LinearMirrorReceipt,
    writer: Option<LinearWriteActor>,
) -> Result<()> {
    let key = outbound_key(&receipt.operation_id);
    let record = LinearMirrorRecord::from(receipt);
    let json = serde_json::to_string(&record)
        .map_err(|_| Error::InvariantViolation("linear mirror receipt encoding"))?;
    vault.with_write_txn_grouped(|txn| {
        let mut row = EVENTS.get(vault, txn, &key)?.unwrap_or_else(|| {
            LinearMirrorEvent::blank(EventDirection::TaskToIssue, "", vault.now_recorded_at())
        });
        row.task_ref = Some(receipt.task_ref.to_hex());
        row.issue = Some(receipt.issue.clone());
        row.operation_id = Some(record.operation_id.clone());
        row.status.clone_from(&record.status);
        row.conflicts.clone_from(&receipt.conflicts);
        if row.writer_actor.is_none()
            && let Some(writer) = writer
        {
            let (actor, class) = writer_parts(writer);
            row.writer_actor = Some(actor);
            row.writer_class = class;
        }
        row.receipt = Some(json.clone());
        put_event_in(vault, txn, &key, &row)
    })
}

/// Forgets `actor` as the writer every event row names, in its erase's
/// transaction (FIX 3520).
pub(crate) fn erase_mirror_event_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let hex = actor.to_hex();
    let rows = EVENTS.scan(vault, txn)?;
    for (key, mut row) in rows {
        if row.writer_actor.as_deref() != Some(hex.as_str()) {
            continue;
        }
        row.writer_actor = None;
        row.writer_class = None;
        EVENTS.put(vault, txn, &key, &row)?;
    }
    Ok(())
}

/// Forgets `actor` as the last mapping editor every control row names, in
/// its erase's transaction (FIX 3520).
pub(crate) fn erase_mirror_control_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let hex = actor.to_hex();
    let controls = CONTROLS.scan(vault, txn)?;
    for (task, mut control) in controls {
        if control.by.as_deref() != Some(hex.as_str()) {
            continue;
        }
        control.by = None;
        CONTROLS.put(vault, txn, &task, &control)?;
    }
    Ok(())
}
