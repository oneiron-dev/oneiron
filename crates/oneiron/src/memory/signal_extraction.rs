//! Typed signal extraction over the production Dreamer partition queue.
use super::{ClaimView, DreamerAttemptView, Memory, MemoryError, MemoryResult};
use crate::claim::{ClaimReadStatus, ClaimSource, PointRead};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::{
    decode_partition_payload, decode_verified_citations, enqueue_partition_plans_in_txn,
    read_partition_turns_in_txn, read_watermark_in_txn,
};
use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use crate::store::consolidation_scope::DreamerConsolidationScope;
use crate::{EdgeActorClass, EntityId, Error};
use serde::{Deserialize, Serialize};

mod attachments;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::signal_extraction::{
    ProspectiveQueryHint, SignalExtractionMessage, SignalExtractionRequest,
    SignalExtractionResultRequest, SignalExtractionSource, SignalExtractionTicket,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignalExtractionResult {
    /// Completion is the queue's completed state, never inferred from outputs.
    pub job: DreamerAttemptView,
    pub claims: Vec<SignalExtractionClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignalExtractionClaim {
    /// The stored claim, including its host-stamped source and made_by.
    pub claim: ClaimView,
    pub sources: Vec<SignalExtractionSource>,
    pub prospective_queries: Vec<ProspectiveQueryHint>,
}

impl Memory<'_> {
    /// The owner requests work, not writes: the production executor calls
    /// extraction_request, verifies citations, resolves conflicts and promotes.
    pub fn signal_extraction_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &SignalExtractionRequest,
    ) -> MemoryResult<SignalExtractionTicket> {
        if input.turn_refs.is_empty() {
            return Err(MemoryError::bad_request(
                "signal extraction requires witnessed turns",
            ));
        }
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let ids = input
            .turn_refs
            .iter()
            .map(|reference| self.resolve_ref_in_lane(&lane, reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        let jobs = self.with_verified_actor_write_txn(|txn| {
            self.extraction_owner(owner.revalidate_in_txn(self.vault, txn)?)?;
            for id in &ids {
                if !lane.is_entity_readable_in(txn, id)? {
                    return Err(Error::EntityNotFound.into());
                }
                self.read_producer_in(txn, *id)?;
            }
            let scope = DreamerConsolidationScope::Meso;
            let turns = read_partition_turns_in_txn(self.vault, txn, scope, &ids)?;
            for turn in &turns {
                let conversation = turn.conversation.ok_or_else(|| {
                    MemoryError::bad_request("an extraction turn requires its conversation")
                })?;
                if !lane.is_entity_readable_in(txn, &conversation)? {
                    return Err(Error::EntityNotFound.into());
                }
                self.read_producer_in(txn, conversation)?;
            }
            let watermark = read_watermark_in_txn(self.vault, txn, scope)?;
            Ok(enqueue_partition_plans_in_txn(
                self.vault,
                txn,
                scope,
                &ids,
                &watermark,
                None,
                self.vault.now_recorded_at(),
            )?)
        })?;
        Ok(SignalExtractionTicket {
            job_refs: jobs
                .into_iter()
                .map(|(_, outcome)| {
                    let status = match outcome {
                        EnqueueDreamerAttemptOutcome::Enqueued(status)
                        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
                    };
                    crate::entity_id::bytes_to_hex_lower(status.attempt.id.as_bytes())
                })
                .collect(),
        })
    }

    /// Reads accepted outputs and their stored citations, never the extractor's
    /// unchecked JSON. Every claim, hint, source and MESSAGE meets this handle's
    /// own recorded read lane before its ref is served.
    pub fn signal_extraction_result_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &SignalExtractionResultRequest,
    ) -> MemoryResult<Option<SignalExtractionResult>> {
        self.extraction_owner(owner.revalidate(self.vault)?)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let id = super::outbound::parse_job_ref(&input.job_ref)?;
        let Some(status) = DreamerRunnerStore::new(self.vault).status(id)? else {
            return Ok(None);
        };
        if status.payload.attempt_type != DreamerConsolidationScope::Meso.as_str() {
            return Err(MemoryError::bad_request(
                "job is not a signal extraction partition",
            ));
        }
        let turns = decode_partition_payload(&status.payload.input)?.turn_ids();
        if !lane.all_refs_readable(&turns)? {
            return Err(Error::EntityNotFound.into());
        }
        self.produced_from(turns);
        let job = self
            .dreamer_attempt_status(&input.job_ref)?
            .ok_or_else(|| MemoryError::not_found("extraction job no longer exists"))?;
        let ids = crate::dreamer_consolidation::nightly_merge::extraction_outputs(self.vault, id)?;
        let reads: Vec<_> = ids.into_iter().map(PointRead::id).collect();
        let projected = lane
            .read_projected(&reads, None, |txn, rows| {
                let mut accepted = Vec::new();
                for row in rows.into_iter().flatten() {
                    let Some(bytes) = row.body.as_deref() else {
                        continue;
                    };
                    let body = crate::claim::decode_claim_body(bytes, true)?;
                    if crate::batch::export::claim_reads_as_secret(&body) {
                        continue;
                    }
                    let candidate_evidence = match body.evidence.as_ref() {
                        Some(rmpv::Value::Map(entries)) => entries.iter().find_map(|(key, value)| {
                            (key.as_str()
                                == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY))
                            .then_some(value)
                        }),
                        _ => None,
                    };
                    let mut citations = candidate_evidence
                        .filter(|value| {
                            matches!(value, rmpv::Value::Map(fields)
                            if fields.iter().any(|(key, _)| key.as_str() == Some("locators")))
                        })
                        .map(decode_verified_citations)
                        .transpose()?
                        .unwrap_or_default();
                    let source_ids = citations
                        .iter()
                        .flat_map(|(locator, _, messages)| {
                            std::iter::once(locator.source_id)
                                .chain(messages.iter().map(|message| message.message))
                        })
                        .collect::<Vec<_>>();
                    let policy = lane.live_policy_manifest_in(txn)?;
                    let mut sources_readable = true;
                    for source in &source_ids {
                        if !lane.is_ref_readable_with_policy_in(txn, &policy, source)? {
                            sources_readable = false;
                            break;
                        }
                    }
                    if !sources_readable {
                        continue;
                    }
                    self.produced_from(source_ids);
                    self.produced_from([row.id]);
                    attachments::append(self, &lane, txn, row.id, &mut citations);
                    let sources = citations
                        .into_iter()
                        .map(|(locator, hash, messages)| SignalExtractionSource {
                            source_ref: locator.source_id.to_hex(),
                            claim_ref: locator.claim_id.map(|id| id.to_hex()),
                            byte_range: locator.byte_range,
                            content_hash: crate::entity_id::bytes_to_hex_lower(&hash),
                            messages: messages
                                .into_iter()
                                .map(|message| SignalExtractionMessage {
                                    message_ref: message.message.to_hex(),
                                    byte_range: (message.start, message.end),
                                    revision: crate::entity_id::bytes_to_hex_lower(&message.revision),
                                })
                                .collect(),
                        })
                        .collect::<Vec<_>>();
                    accepted.push((row, body, sources));
                }
                Ok::<_, MemoryError>(accepted)
            })?
            .value;
        let mut claims = Vec::new();
        for (row, body, sources) in projected {
            let hint_reads: Vec<_> = self
                .vault
                .claims_for_subject(&row.id)?
                .into_iter()
                .map(PointRead::id)
                .collect();
            let mut prospective_queries = Vec::new();
            for hint in lane.read(&hint_reads, None)?.value.into_iter().flatten() {
                let Some(bytes) = hint.body.as_deref() else {
                    continue;
                };
                let hint_body = crate::claim::decode_claim_body(bytes, true)?;
                let Some(value) = crate::claim::canonical_lexical_query_hint(&hint.id, &hint_body)?
                else {
                    continue;
                };
                if value.target != row.id || hint_body.source != Some(ClaimSource::Generated) {
                    continue;
                }
                self.produced_from([hint.id]);
                prospective_queries.push(ProspectiveQueryHint {
                    hint_ref: hint.id.to_hex(),
                    target_ref: row.id.to_hex(),
                    query: value.query,
                    source: ClaimSource::Generated.as_str().to_owned(),
                });
            }
            claims.push(SignalExtractionClaim {
                claim: self.served_claim_view(&row.id, &body)?,
                sources,
                prospective_queries,
            });
        }
        Ok(Some(SignalExtractionResult { job, claims }))
    }

    fn extraction_owner(&self, person: EntityId) -> MemoryResult<()> {
        if person != self.actor || self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "signal extraction requires the owner's own handle",
                &[],
            ));
        }
        Ok(())
    }
}
