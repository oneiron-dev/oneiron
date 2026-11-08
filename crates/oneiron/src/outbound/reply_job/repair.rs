//! Repays completed replies' owed witnesses without reopening their sends.

use super::*;
use crate::attempt_queue::AttemptState;
use crate::blob_artifact::BlobArtifactVersion;
use crate::memory::{MemoryError, MemoryResult};
use crate::outbound::{ConnectorReply, ConnectorReplyBody, OutboundDispatchOutcome};
use crate::outbound_intent_ledger::{
    ConnectorIntentBinding, IntentResolution, call_row_erased_in_txn,
    read_intent_for_attempt_in_txn,
};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

struct RepairSource {
    attempt: AttemptRecord,
    job: ConnectorReplyJob,
    artifact: EntityId,
    head: BlobArtifactVersion,
    bytes: Vec<u8>,
    result: ConnectorReplyJobResult,
    origin: SurfaceConnectorPayload,
    inbound: String,
    reply_ref: String,
    kept: ConnectorReplyBody,
    reply: String,
    deferred: bool,
    reply_delivered: bool,
}

impl Vault {
    /// Replays only the witnesses owed by completed replies, including archived
    /// attempts. The host supplies its existing answerability predicate, outside
    /// every writer. The attempt, send, model spend and queue metadata never move.
    pub fn repair_connector_reply_witnesses(
        &self,
        reply_ref: &str,
        now: u64,
        answerable: impl Fn(&ConnectorReplyJob) -> Result<bool>,
    ) -> MemoryResult<usize> {
        let records = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            AttemptQueue::new(self).kind_rows_in_txn(&txn, CONNECTOR_REPLY_JOB_KIND)?
        };
        let mut repaired = 0;
        for record in records {
            let result = (|| -> MemoryResult<bool> {
                let Some(source) = self.connector_witness_repair_source(&record, reply_ref)? else {
                    return Ok(false);
                };
                if !answerable(&source.job)? {
                    return Ok(false);
                }
                self.repair_connector_reply_witness(&source, now)
            })();
            match result {
                Ok(true) => repaired += 1,
                Ok(false) => {}
                Err(error) => {
                    // A repair never delays another job on an error, nor logs
                    // provider text or the stored free-text owed reason.
                    tracing::warn!(attempt = ?record.id, code = %error.code,
                        "connector reply witness remains owed");
                }
            }
        }
        Ok(repaired)
    }

    fn connector_witness_repair_source(
        &self,
        attempt: &AttemptRecord,
        reply_ref: &str,
    ) -> Result<Option<RepairSource>> {
        if attempt.state != AttemptState::Completed {
            return Ok(None);
        }
        let Ok(job) = serde_json::from_slice::<ConnectorReplyJob>(&attempt.payload) else {
            return Ok(None);
        };
        if job.event.payload.is_null() {
            return Ok(None);
        }
        let artifact = connector_reply_result_id(attempt.id)?;
        let expected_ref = format!("{CONNECTOR_REPLY_RESULT_PREFIX}{}", artifact.to_hex());
        if attempt.result_ref.as_ref().map(AttemptResultRef::as_str) != Some(expected_ref.as_str())
        {
            return Ok(None);
        }
        let txn = self.store.env.read_txn()?;
        if self.get_blob_artifact_in_txn(&txn, &artifact)?.is_none() {
            return Ok(None);
        }
        let Some(head) =
            crate::blob_artifact::read_blob_artifact_head_in_txn(&self.store, &txn, &artifact)?
        else {
            return Ok(None);
        };
        if self
            .blob_artifact_version_metadata_in_txn(&txn, &artifact, head.version)?
            .as_ref()
            != Some(&head)
        {
            return Err(Error::CorruptedIndex("connector reply result head"));
        }
        let Some(bytes) = self.read_blob_artifact_version_in_txn(&txn, &artifact, head.version)?
        else {
            return Ok(None);
        };
        // An unreadable/undecodable head is never replaced from an older result.
        let Ok(result) = serde_json::from_slice::<ConnectorReplyJobResult>(&bytes) else {
            return Ok(None);
        };
        if result.stage != ConnectorReplyStage::Dispatched || result.witness_repair.is_none() {
            return Ok(None);
        }
        let Ok(origin) = SurfaceConnectorPayload::from_connector_event(&job.event) else {
            return Ok(None);
        };
        let Some(payload_ref) = origin.payload_ref.as_deref() else {
            return Ok(None);
        };
        let Some(inbound) =
            self.read_provider_event_text_in_txn(&txn, &origin.channel, payload_ref)?
        else {
            return Ok(None);
        };
        let Some(kept) =
            self.connector_reply_body_in_txn(&txn, &job.event.event_id, job.agent, reply_ref)?
        else {
            return Ok(None);
        };
        if result.body_ref.as_deref() != Some(kept.content_ref.as_str()) {
            return Ok(None);
        }
        let Some(reply) = self.connector_reply_body_text_in_txn(&txn, &kept.content_ref)? else {
            return Ok(None);
        };
        let deferred =
            result.outcome.as_deref() == Some(OutboundDispatchOutcome::Deferred.as_str());
        let reply_delivered = if deferred {
            self.connector_deferred_reply_delivered_in_txn(&txn, &job, reply_ref, &kept)
                .unwrap_or(false)
        } else {
            result.outcome.as_deref() == Some(OutboundDispatchOutcome::DeliveredToChannel.as_str())
        };
        Ok(Some(RepairSource {
            attempt: attempt.clone(),
            job,
            artifact,
            head,
            bytes,
            result,
            origin,
            inbound,
            reply_ref: reply_ref.to_owned(),
            kept,
            reply,
            deferred,
            reply_delivered,
        }))
    }

    fn connector_deferred_reply_delivered_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        job: &ConnectorReplyJob,
        reply_ref: &str,
        kept: &ConnectorReplyBody,
    ) -> Result<bool> {
        let reply = ConnectorReply {
            agent: job.agent,
            reply_ref: reply_ref.to_owned(),
            verb: "send".to_owned(),
            content_ref: kept.content_ref.clone(),
            occurred_at: kept.written_at,
        };
        let request = crate::outbound::connector_reply_request(&job.event, &reply)?.request;
        let identity = request
            .ledger_identity_ref
            .as_deref()
            .unwrap_or(&request.intent_ref);
        let attempt = crate::outbound::outbound_dispatch_attempt_id(identity)
            .map_err(|_| Error::InvariantViolation("connector reply logical send"))?;
        if call_row_erased_in_txn(self, txn, attempt, 0)? {
            return Ok(false);
        }
        let Some(record) = read_intent_for_attempt_in_txn(self, txn, attempt, 0)
            .map_err(|_| Error::CorruptedIndex("connector reply intent lookup"))?
        else {
            return Ok(false);
        };
        let binding = ConnectorIntentBinding {
            intent: &request.intent,
            actor_ref: job.agent,
            actor_class: &request.actor.actor_class,
            counterparty_ref: request.counterparty_ref.as_deref(),
            originating_session_ref: request.originating_session_ref.as_deref(),
            calendar_invite: request.calendar_invite.as_ref(),
        };
        binding
            .verify(&record)
            .map_err(|_| Error::CorruptedIndex("connector reply frozen intent binding"))?;
        Ok(IntentResolution::from_record(&record)
            .map_err(|_| Error::CorruptedIndex("connector reply intent resolution"))?
            == IntentResolution::Delivered)
    }

    fn connector_witness_repair_source_matches_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &RepairSource,
    ) -> Result<bool> {
        let Some(current) = AttemptQueue::new(self).get_in_write_txn(txn, source.attempt.id)?
        else {
            return Ok(false);
        };
        if current.kind != CONNECTOR_REPLY_JOB_KIND
            || current.state != AttemptState::Completed
            || current.attempt_count != source.attempt.attempt_count
            || current.payload != source.attempt.payload
            || current.result_ref != source.attempt.result_ref
        {
            return Ok(false);
        }
        for id in source.job.named_ids().into_iter().chain([source.artifact]) {
            if self.local_hard_delete_marker_exists_in_txn(txn, &id)? {
                return Ok(false);
            }
        }
        if self
            .get_blob_artifact_in_txn(txn, &source.artifact)?
            .is_none()
            || crate::blob_artifact::read_blob_artifact_head_in_txn(
                &self.store,
                txn,
                &source.artifact,
            )?
            .as_ref()
                != Some(&source.head)
            || self
                .read_blob_artifact_version_in_txn(txn, &source.artifact, source.head.version)?
                .as_deref()
                != Some(source.bytes.as_slice())
        {
            return Ok(false);
        }
        let Some(payload_ref) = source.origin.payload_ref.as_deref() else {
            return Ok(false);
        };
        if self
            .read_provider_event_text_in_txn(txn, &source.origin.channel, payload_ref)?
            .as_deref()
            != Some(source.inbound.as_str())
            || self
                .connector_reply_body_in_txn(
                    txn,
                    &source.job.event.event_id,
                    source.job.agent,
                    &source.reply_ref,
                )?
                .as_ref()
                != Some(&source.kept)
            || self
                .connector_reply_body_text_in_txn(txn, &source.kept.content_ref)?
                .as_deref()
                != Some(source.reply.as_str())
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn repair_connector_reply_witness(
        &self,
        source: &RepairSource,
        now: u64,
    ) -> MemoryResult<bool> {
        let check = |txn: &mut heed::RwTxn<'_>, conversation: EntityId| -> MemoryResult<()> {
            if !self.connector_witness_repair_source_matches_in_txn(txn, source)? {
                return Err(MemoryError::from(Error::EntityNotFound));
            }
            self.issue_connector_witness_read_grant_in_txn(
                txn,
                source.job.agent,
                conversation,
                now,
            )?;
            Ok(())
        };
        let inbound = self.witness_connector_inbound_with_effect(
            source.job.agent,
            &source.origin,
            &source.inbound,
            now,
            check,
        )?;
        let conversation = inbound
            .refs
            .first()
            .and_then(|reference| EntityId::from_hex(reference).ok())
            .ok_or_else(|| {
                MemoryError::from(Error::InvariantViolation(
                    "connector witness has no conversation",
                ))
            })?;
        let mut refs = inbound.refs;
        let mut expected_messages = 1;
        if source.reply_delivered {
            let reply_check = |txn: &mut heed::RwTxn<'_>, conversation: EntityId| {
                if source.deferred
                    && !self.connector_deferred_reply_delivered_in_txn(
                        txn,
                        &source.job,
                        &source.reply_ref,
                        &source.kept,
                    )?
                {
                    return Err(MemoryError::from(Error::EntityNotFound));
                }
                check(txn, conversation)
            };
            let reply = self.witness_connector_reply_with_effect(
                source.job.agent,
                &source.origin,
                &source.reply_ref,
                &source.reply,
                source.kept.written_at,
                now,
                reply_check,
            )?;
            if reply.refs.first().map(String::as_str) != Some(conversation.to_hex().as_str()) {
                return Err(MemoryError::from(Error::InvariantViolation(
                    "connector witness conversations differ",
                )));
            }
            refs.extend(reply.refs);
            expected_messages += 1;
        }
        refs.sort();
        refs.dedup();
        // A crash before this writer leaves the original owed head. Replays
        // re-verify the same deterministic turns, never the original send.
        Ok(self.with_write_txn_grouped(|txn| {
            if !self.connector_witness_repair_source_matches_in_txn(txn, source)? {
                return Ok(false);
            }
            if source.deferred
                && source.reply_delivered
                && !self.connector_deferred_reply_delivered_in_txn(
                    txn,
                    &source.job,
                    &source.reply_ref,
                    &source.kept,
                )?
            {
                return Ok(false);
            }
            let mut messages = 0;
            for reference in &refs {
                let id = EntityId::from_hex(reference)?;
                if self.local_hard_delete_marker_exists_in_txn(txn, &id)? {
                    return Ok(false);
                }
                let crate::vault::LiveEntityRow::Live { entity_type, .. } =
                    crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?
                else {
                    return Ok(false);
                };
                match entity_type {
                    ENTITY_TYPE_CONVERSATION if id == conversation => {}
                    ENTITY_TYPE_TURN => {}
                    ENTITY_TYPE_MESSAGE => {
                        let Some(raw) = self.store.port_entity_raw(txn, &id)? else {
                            return Ok(false);
                        };
                        let Some(scope) = crate::federation::record_scope::scope_for_blob(
                            &self.store,
                            txn,
                            id,
                            &raw,
                        )?
                        else {
                            return Ok(false);
                        };
                        if !self.connector_witness_read_grant_allows_in_txn(
                            txn,
                            source.job.agent,
                            conversation,
                            &scope,
                        )? {
                            return Ok(false);
                        }
                        messages += 1;
                    }
                    _ => return Ok(false),
                }
            }
            if messages != expected_messages {
                return Ok(false);
            }
            let mut repaired = source.result.clone();
            for reference in &refs {
                if !repaired.witness_refs.contains(reference) {
                    repaired.witness_refs.push(reference.clone());
                }
            }
            repaired.witness_repair = if source.deferred && !source.reply_delivered {
                Some("reply: deferred".to_owned())
            } else {
                None
            };
            if repaired == source.result {
                return Ok(false);
            }
            let bytes = serde_json::to_vec(&repaired)
                .map_err(|_| Error::InvariantViolation("connector reply result did not encode"))?;
            self.append_blob_artifact_version_in_txn(
                txn,
                &source.artifact,
                &bytes,
                &BlobVersionProvenance::AgentRun {
                    run_ref: connector_reply_job_key(source.job.agent, &source.job.event.event_id),
                },
                WriteActor::new(source.job.agent, EdgeActorClass::Agent),
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            Ok(true)
        })?)
    }
}
