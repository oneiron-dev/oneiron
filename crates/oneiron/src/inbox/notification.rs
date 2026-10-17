//! OF-221: background events as NOTIFICATION records (type 42).
//!
//! A background event — an agent or Dreamer run settling, a Dreamer finding,
//! an inbound connector event, a finished import — lands as one typed
//! NOTIFICATION entity. No node type and no edge type is added, nothing is
//! appended to a transcript and no model completion is queued: the inbox
//! pages these rows ([`super::list`]), and a conversation receives only an
//! `Attached` edge, and only when the event finishes work that conversation
//! started.
//!
//! The body is a named MessagePack map whose delivery and seen/ack keys are
//! the ones the context board already reads (`recipient`, `seen_by`,
//! `acked_by`), so every reader decides delivery one way. A row's id derives
//! from its producer and event identity: a replayed event finds its row and
//! never rewrites it, so seen and acknowledged state survives every replay.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_NOTIFICATION};
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Domain separator for a notification's producer-derived id.
const NOTIFICATION_ID_DOMAIN: &[u8] = b"oneiron:inbox-notification:v1";

/// Stored weight of the conversation → notification link: `Attached`'s
/// default prior.
const LINK_WEIGHT: f32 = 0.8;

/// Producer name of a settled background job.
pub const NOTIFICATION_PRODUCER_JOB: &str = "attempt_queue";
/// Producer name of a Dreamer maintenance finding.
pub const NOTIFICATION_PRODUCER_FINDING: &str = "dreamer.finding";
/// Producer name of an inbound connector event.
pub const NOTIFICATION_PRODUCER_CONNECTOR: &str = "connector_event";
/// Producer name of a finished docs import.
pub const NOTIFICATION_PRODUCER_DOCS_IMPORT: &str = "docs_import";

/// Queue kinds whose settled rows surface, beside root Dreamer-runner rows
/// (agent dispatch, workflows, connector wakes, scheduled Dreamer work).
/// Internal maintenance kinds — consolidation tiers, delivery retries,
/// polls — settle silently.
const SURFACED_JOB_KINDS: &[&str] = &[
    crate::dispatch_byoa::BYOA_ATTEMPT_KIND,
    crate::surface_event::SURFACE_EVENT_ATTEMPT_KIND,
    crate::wave_orchestration::WAVE_PLAN_ATTEMPT_KIND,
];

/// What happened. A job's kind names its real outcome: a failed, cancelled
/// or abandoned job never reads as completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    JobCompleted,
    JobFailed,
    JobCancelled,
    JobAbandoned,
    Finding,
    EventReceived,
    ImportFinished,
    /// A built proactivity digest; `source.result` names its id.
    Digest,
    /// A decision waiting on its recipient; `source.producer` names what
    /// asks and `source.result` the thing to answer.
    Ask,
}

impl NotificationKind {
    /// The kind a queue row's terminal state reports; `None` for a row that
    /// has not settled (queued, scheduled, paused, leased or landing).
    #[must_use]
    pub const fn for_job(state: AttemptState) -> Option<Self> {
        match state {
            AttemptState::Completed => Some(Self::JobCompleted),
            AttemptState::Failed => Some(Self::JobFailed),
            AttemptState::Cancelled => Some(Self::JobCancelled),
            AttemptState::Abandoned => Some(Self::JobAbandoned),
            _ => None,
        }
    }
}

/// Where a notification came from: its producer, the producer's stable event
/// identity, and the persisted job, run and result it reports on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationSource {
    pub producer: String,
    /// The producer's own identity for the event; with `producer` it derives
    /// the row id.
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
}

/// The stored NOTIFICATION body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationBody {
    pub kind: NotificationKind,
    pub source: NotificationSource,
    /// The records the event is about (the finding, the realized TASK, the
    /// imported conversation), as entity ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_refs: Vec<String>,
    /// The one caller it is for. Absent: every caller whose read admits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// When the event happened. The envelope's `learned_at` is when the row
    /// was last recorded, and moves on every mark; this never does.
    pub created_at: u64,
    /// The conversation whose request started the work, as its admission
    /// boundary stamped it. Never a conversation the work merely read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_conversation: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seen_by: BTreeMap<String, bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub acked_by: BTreeMap<String, bool>,
}

/// One event for [`Vault::record_notification_in_txn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationEvent {
    pub kind: NotificationKind,
    pub source: NotificationSource,
    pub subject_refs: Vec<EntityId>,
    pub recipient: Option<EntityId>,
    pub created_at: u64,
    pub origin_conversation: Option<EntityId>,
}

/// Encodes a notification body as its named MessagePack map.
pub fn encode_notification_body(body: &NotificationBody) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(body).map_err(|_| Error::InvariantViolation("notification body encode"))
}

/// Decodes a stored notification body. A body that is not this typed map is
/// refused, never read loosely.
pub fn decode_notification_body(raw: &[u8]) -> Result<NotificationBody> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("notification body"))
}

/// The row id a producer's event lands under.
fn notification_id(source: &NotificationSource) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        NOTIFICATION_ID_DOMAIN,
        &[source.producer.as_bytes(), source.event.as_bytes()],
    )
}

impl Vault {
    /// Whether `reader` saw or acked the NOTIFICATION `source` names, in the
    /// caller's snapshot; `None` when no such row is live. For trusted loops
    /// that settle a delivery's read (OF-499: the weave lens's read rate).
    pub(crate) fn notification_seen_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &NotificationSource,
        reader: &EntityId,
    ) -> Result<Option<bool>> {
        let id = notification_id(source)?;
        match live_entity_row_in_txn(&self.store, txn, &id)? {
            LiveEntityRow::Live { entity_type, body } if entity_type == ENTITY_TYPE_NOTIFICATION => {
                let body = decode_notification_body(&body)?;
                let reader = reader.to_hex();
                Ok(Some(
                    body.acked_by.get(&reader) == Some(&true)
                        || body.seen_by.get(&reader) == Some(&true),
                ))
            }
            _ => Ok(None),
        }
    }

    /// Records `event` as a NOTIFICATION in the caller's transaction and
    /// returns its id. A replay finds the row it wrote first and returns it
    /// untouched, seen and acknowledged state included; a deleted row stays
    /// deleted.
    pub(crate) fn record_notification_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        event: &NotificationEvent,
    ) -> Result<EntityId> {
        Ok(self.stage_notification_in_txn(txn, event)?.0)
    }

    /// [`Self::record_notification_in_txn`], also saying whether this call
    /// wrote the row.
    fn stage_notification_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        event: &NotificationEvent,
    ) -> Result<(EntityId, bool)> {
        let id = notification_id(&event.source)?;
        match live_entity_row_in_txn(&self.store, &*txn, &id)? {
            LiveEntityRow::Absent => {}
            LiveEntityRow::DeletedShell => return Ok((id, false)),
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_NOTIFICATION => {
                return Ok((id, false));
            }
            LiveEntityRow::Live { .. } => {
                return Err(Error::InvariantViolation(
                    "notification id occupied by another kind",
                ));
            }
        }
        let body = NotificationBody {
            kind: event.kind,
            source: event.source.clone(),
            subject_refs: event.subject_refs.iter().map(EntityId::to_hex).collect(),
            recipient: event.recipient.as_ref().map(EntityId::to_hex),
            created_at: event.created_at,
            origin_conversation: event.origin_conversation.as_ref().map(EntityId::to_hex),
            seen_by: BTreeMap::new(),
            acked_by: BTreeMap::new(),
        };
        self.put_notification_in_txn(txn, &id, &body)?;
        Ok((id, true))
    }

    /// Writes `body` under `id` at this vault's recorded-at time, which it
    /// returns. The occurred range is the event's own time.
    pub(crate) fn put_notification_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &NotificationBody,
    ) -> Result<u64> {
        let bytes = encode_notification_body(body)?;
        let learned_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        self.batch_in()
            .put(
                id,
                ENTITY_TYPE_NOTIFICATION,
                TimeRange {
                    start: body.created_at,
                    end: body.created_at,
                },
                learned_at,
                &bytes,
            )
            .apply(txn)?;
        Ok(learned_at)
    }

    /// Attaches `notification` to the conversation that started its work: one
    /// existing `Attached` edge, conversation → notification. It moves no
    /// HEAD, adds no TURN and grants no read. A conversation that is not a
    /// live CONVERSATION gets no edge.
    pub(crate) fn attach_notification_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        conversation: EntityId,
        notification: EntityId,
    ) -> Result<()> {
        match live_entity_row_in_txn(&self.store, &*txn, &conversation)? {
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_CONVERSATION => {}
            _ => return Ok(()),
        }
        self.batch_in()
            .edge(
                &conversation,
                EdgeKind::Attached,
                &notification,
                LINK_WEIGHT,
            )
            .apply(txn)
    }

    /// Surfaces one settled queue row: a root Dreamer-runner row (agent runs,
    /// workflows, connector wakes, scheduled Dreamer work) or a row of a
    /// surfaced kind. A child step settles inside its root's run and is not
    /// surfaced; a row that has not settled is not either. Only a completed
    /// row whose dispatch carries a stamped origin conversation is linked to
    /// it; a failed, cancelled or abandoned one is recorded as exactly that.
    pub(crate) fn record_job_notification_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<Option<EntityId>> {
        let Some(kind) = NotificationKind::for_job(record.state) else {
            return Ok(None);
        };
        let (job_kind, origin) =
            if record.kind == crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
                let Ok(payload) =
                    crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
                else {
                    return Ok(None);
                };
                if payload.parent_attempt.is_some() {
                    return Ok(None);
                }
                let origin = crate::agent_dispatch::dispatch_origin_conversation(&payload);
                (payload.attempt_type, origin)
            } else if SURFACED_JOB_KINDS.contains(&record.kind.as_str()) {
                (record.kind.clone(), None)
            } else {
                return Ok(None);
            };
        let attempt = bytes_to_hex_lower(record.id.as_bytes());
        let event = NotificationEvent {
            kind,
            source: NotificationSource {
                producer: NOTIFICATION_PRODUCER_JOB.to_owned(),
                event: format!("{attempt}:{}", record.state.as_str()),
                job_kind: Some(job_kind),
                attempt: Some(attempt),
                run: record.run_id.clone(),
                result: record
                    .result_ref
                    .as_ref()
                    .map(|result| result.as_str().to_owned()),
            },
            subject_refs: record
                .task_ref
                .as_deref()
                .and_then(|task| EntityId::from_hex(task).ok())
                .into_iter()
                .collect(),
            recipient: None,
            created_at: record.updated_at,
            origin_conversation: origin,
        };
        let (id, fresh) = self.stage_notification_in_txn(txn, &event)?;
        if fresh
            && kind == NotificationKind::JobCompleted
            && let Some(conversation) = origin
        {
            self.attach_notification_in_txn(txn, conversation, id)?;
        }
        Ok(Some(id))
    }

    /// Surfaces one Dreamer finding: the CLAIM it landed stays the evidence;
    /// this row only points at it. Autonomous findings link no conversation.
    pub(crate) fn record_finding_notification_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        finding: EntityId,
        subject: EntityId,
        now: u64,
    ) -> Result<EntityId> {
        self.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Finding,
                source: NotificationSource {
                    producer: NOTIFICATION_PRODUCER_FINDING.to_owned(),
                    event: finding.to_hex(),
                    ..NotificationSource::default()
                },
                subject_refs: vec![finding, subject],
                recipient: None,
                created_at: now,
                origin_conversation: None,
            },
        )
    }

    /// Surfaces one inbound connector event as received by one subscription.
    /// The work it wakes surfaces again when that job settles; a receiving
    /// agent or subscription is never an originating conversation.
    pub(crate) fn record_connector_notification_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        subscription: EntityId,
        event_id: &str,
        attempt: Option<[u8; 16]>,
        now: u64,
    ) -> Result<EntityId> {
        self.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::EventReceived,
                source: NotificationSource {
                    producer: NOTIFICATION_PRODUCER_CONNECTOR.to_owned(),
                    event: format!("{}:{event_id}", subscription.to_hex()),
                    attempt: attempt.map(|attempt| bytes_to_hex_lower(&attempt)),
                    ..NotificationSource::default()
                },
                subject_refs: vec![subscription],
                recipient: None,
                created_at: now,
                origin_conversation: None,
            },
        )
    }

    /// Surfaces one finished docs import, in the transaction that lands it.
    /// `request` is the import's own identity and `assets` the asset ids its
    /// receipt names. An import links no conversation: what it imported is
    /// its subject, never the conversation that asked for it.
    pub(crate) fn record_import_notification_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: EntityId,
        assets: &[String],
        now: u64,
    ) -> Result<EntityId> {
        self.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::ImportFinished,
                source: NotificationSource {
                    producer: NOTIFICATION_PRODUCER_DOCS_IMPORT.to_owned(),
                    event: request.to_hex(),
                    ..NotificationSource::default()
                },
                subject_refs: assets
                    .iter()
                    .filter_map(|asset| EntityId::from_hex(asset).ok())
                    .collect(),
                recipient: None,
                created_at: now,
                origin_conversation: None,
            },
        )
    }
}
