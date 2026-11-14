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
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::deletion::ActorErasureWriter;
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_NOTIFICATION};
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::attempt_hold::BUDGET_HOLD_ACTOR;
use crate::store::attempt_id::AttemptId;
use crate::store::attempt_inputs::AttemptInterventionKind;
use crate::store::attempt_state::AttemptState;
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
/// Producer name of a queue row held at its spend cap (FIX 6148).
const NOTIFICATION_PRODUCER_BUDGET_HOLD: &str = "attempt_queue.budget_hold";
/// Why a budget-held row waits, as its notice says it.
const BUDGET_HOLD_NOTICE_DETAIL: &str =
    "held at its spend cap; a run-tree resume takes it up from its checkpoint";

/// Queue kinds whose settled rows surface, beside root Dreamer-runner rows
/// (agent dispatch, workflows, connector wakes, scheduled Dreamer work).
/// Internal maintenance kinds — consolidation tiers, delivery retries,
/// polls — settle silently.
const SURFACED_JOB_KINDS: &[&str] = &[
    crate::store::dispatch_attempt_kind::BYOA_ATTEMPT_KIND,
    crate::store::dispatch_attempt_kind::SURFACE_EVENT_ATTEMPT_KIND,
    crate::store::dreamer_attempt_kind::WAVE_PLAN_ATTEMPT_KIND,
];

#[doc(hidden)]
pub use oneiron_records::inbox::notification::{
    NotificationBody, NotificationKind, NotificationSource,
};

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
pub(crate) fn notification_id(source: &NotificationSource) -> Result<EntityId> {
    crate::store::code_snapshot::entity_id_from_hash_material(
        NOTIFICATION_ID_DOMAIN,
        &[source.producer.as_bytes(), source.event.as_bytes()],
    )
}

/// Takes the hard-erased actor out of every Finding notice that names them,
/// in its own writer: out of its subjects (FIX 5269) and its seen and
/// acknowledged marks, and, where they were its recipient or a segment of its
/// event key, replaced there by one fresh opaque id this erase mints (FIX
/// 14749). The recipient never becomes `None`, which would deliver the
/// notice to everyone: the opaque id names no one, so no one is delivered
/// it. The notice keeps the id its old event minted. Held notices stay
/// untouched; only changed, unheld rows retire their old revisions and
/// capture the record that materialization stored.
pub(crate) fn scrub_finding_notification_actor_in_txn(
    erase: &mut ActorErasureWriter<'_, '_>,
) -> Result<()> {
    let (vault, txn, actor) = erase.parts();
    let erased = actor.to_hex();
    let mut opaque: Option<String> = None;
    let mut count = ScanCount::start(
        &vault.store,
        &*txn,
        EngineScan::TypeIndexRows,
        &[ENTITY_TYPE_NOTIFICATION],
    )?;
    let mut ids = Vec::new();
    for row in vault
        .store
        .port_entity_ids_by_type(&*txn, ENTITY_TYPE_NOTIFICATION, None)?
    {
        count.row();
        ids.push(row?);
    }
    count.finish(vault);
    for id in ids {
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*txn, &id)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let Ok(mut body) = decode_notification_body(&body) else {
            continue;
        };
        if body.kind != NotificationKind::Finding
            || body.source.producer != NOTIFICATION_PRODUCER_FINDING
        {
            continue;
        }
        let before = body.subject_refs.len();
        body.subject_refs.retain(|subject| subject != &erased);
        let mut changed = body.subject_refs.len() != before;
        changed |= body.seen_by.remove(&erased).is_some();
        changed |= body.acked_by.remove(&erased).is_some();
        let names_recipient = body.recipient.as_deref() == Some(erased.as_str());
        let names_event = body
            .source
            .event
            .split(':')
            .any(|segment| segment == erased);
        if names_recipient || names_event {
            let fresh = match opaque.clone() {
                Some(fresh) => fresh,
                None => {
                    let fresh = vault.store.clock.entity_id()?.to_hex();
                    opaque = Some(fresh.clone());
                    fresh
                }
            };
            if names_recipient {
                body.recipient = Some(fresh.clone());
            }
            if names_event {
                let event = body
                    .source
                    .event
                    .split(':')
                    .map(|segment| {
                        if segment == erased {
                            fresh.as_str()
                        } else {
                            segment
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(":");
                body.source.event = event;
            }
            changed = true;
        }
        if !changed || crate::store::legal_hold::held_in_txn(&vault.store, txn, id.as_bytes())? {
            continue;
        }
        vault.put_notification_in_txn(txn, &id, &body)?;
        let stored = vault
            .store
            .port_entity_record(&*txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        if stored.entity_type != ENTITY_TYPE_NOTIFICATION
            || decode_notification_body(&stored.body)? != body
        {
            return Err(Error::InvariantViolation(
                "notification actor erasure did not materialize",
            ));
        }
        crate::vault::entity_revision::remove_entity_revisions(&vault.store, txn, &id)?;
        crate::vault::entity_revision::capture_entity_revision(
            &vault.store,
            txn,
            &id,
            &stored.encode(),
        )?;
    }
    Ok(())
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
            LiveEntityRow::Live { entity_type, body }
                if entity_type == ENTITY_TYPE_NOTIFICATION =>
            {
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
    /// returns. The occurred range is the event's own time. The live queries
    /// that follow notifications wake once `txn` commits (FIX 3084): its
    /// owner sends the signal then, and a raw-transaction owner sends it
    /// after its own commit.
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
        crate::batch::queue_notification_change(self, txn);
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
            if record.kind == crate::store::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND {
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
                detail: None,
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

    /// Tells the vault's live Owners that `attempt` is held at its spend cap
    /// (FIX 6148): one Ask NOTIFICATION in each Owner's inbox, keyed by the
    /// attempt, its hold's Pause event and the Owner, whose result names the
    /// attempt a run-tree resume takes up. It reads the committed row again:
    /// a row the budget does not hold now is told nothing. A replay finds the
    /// rows it wrote, seen and acknowledged state included, and a deleted
    /// notice stays deleted. No Admin or Delegate is told.
    ///
    /// # Errors
    /// Storage errors.
    pub fn notify_attempt_budget_hold(&self, attempt: AttemptId, now: u64) -> Result<()> {
        self.with_write_txn_grouped(|txn| self.notify_attempt_budget_hold_in_txn(txn, attempt, now))
    }

    /// Transaction-composable [`Self::notify_attempt_budget_hold`] (FIX
    /// 7210): the same notices, keyed and addressed alike, written in `txn`,
    /// which reads the row as `txn` holds it, so a hold in the same writer is
    /// told with its own commit.
    ///
    /// # Errors
    /// Storage errors.
    pub(crate) fn notify_attempt_budget_hold_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        now: u64,
    ) -> Result<()> {
        let Some(record) = AttemptQueue::new(self).get_in_txn(&*txn, attempt)? else {
            return Ok(());
        };
        if !record.budget_hold() {
            return Ok(());
        }
        let Some(pause) = record.events.iter().rev().find(|event| {
            event.kind == AttemptInterventionKind::Pause && event.actor == BUDGET_HOLD_ACTOR
        }) else {
            return Ok(());
        };
        let reference = bytes_to_hex_lower(attempt.as_bytes());
        let subject_refs: Vec<EntityId> = record
            .task_ref
            .as_deref()
            .and_then(|task| EntityId::from_hex(task).ok())
            .into_iter()
            .collect();
        for owner in crate::policy_model::owners_in_txn(self, &*txn)? {
            self.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_BUDGET_HOLD.to_owned(),
                        event: format!("{reference}:{}:{}", pause.sequence, owner.to_hex()),
                        job_kind: Some(record.kind.clone()),
                        attempt: Some(reference.clone()),
                        run: record.run_id.clone(),
                        result: Some(reference.clone()),
                        detail: Some(BUDGET_HOLD_NOTICE_DETAIL.to_owned()),
                    },
                    subject_refs: subject_refs.clone(),
                    recipient: Some(owner),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    }
}
