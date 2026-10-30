//! Typed indexed commitment birth, observation and explicit lifecycle effects.
mod types;
pub use types::*;

use super::{Memory, MemoryError, MemoryResult};
use crate::claim::{ClaimApprovalStatus, ClaimReadStatus, ClaimSource, ScopedRead};
use crate::commitment::{self, CommitmentRecord, FulfillmentSource};
use crate::commitment_schedule::{
    CommitmentInstanceOutcome, CommitmentSchedulePayload, CommitmentSeriesWriteOutcome, Schedule,
    ScheduleError,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::entity_id::EntityId;
use crate::{Error, TimeRange};
use rmpv::Value;
use serde::{Serialize, de::DeserializeOwned};

fn shape<T: DeserializeOwned>(value: serde_json::Value) -> MemoryResult<T> {
    serde_json::from_value(value).map_err(|error| MemoryError::bad_request(error.to_string()))
}

fn wire(value: &impl Serialize) -> MemoryResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| MemoryError::bad_request("commitment wire shape"))
}

fn token(value: &impl Serialize) -> MemoryResult<String> {
    shape(wire(value)?)
}

fn schedule_error(error: ScheduleError) -> MemoryError {
    match error {
        ScheduleError::Engine(error) => error.into(),
        other => MemoryError::bad_request(other.to_string()),
    }
}

fn unavailable() -> MemoryError {
    MemoryError::not_found("commitment is unknown or withheld")
}

fn owner_in(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> MemoryResult<()> {
    if owner.revalidate_in_txn(memory.vault, txn)? != memory.actor
        || memory.actor_class != crate::EdgeActorClass::Human
    {
        return Err(MemoryError::new(
            super::MEMORY_CODE_FORBIDDEN,
            "commitment lifecycle acts as the authenticated owner",
            &["Present the owner's own verified credential."],
        ));
    }
    Ok(())
}

fn evidence_refs(body: &crate::claim::ClaimBody) -> MemoryResult<Vec<EntityId>> {
    let Some(Value::Map(entries)) = &body.evidence else {
        return Ok(Vec::new());
    };
    let Some((_, evidence)) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
    else {
        return Ok(Vec::new());
    };
    Ok(
        crate::dreamer_consolidation::decode_consolidation_evidence(evidence)?
            .map(|evidence| evidence.refs)
            .unwrap_or_default(),
    )
}

fn evidence_value(refs: &[EntityId], source: ClaimSource) -> Value {
    encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: refs.to_vec(),
        chain: Vec::new(),
        source_meet: source,
    })
}

impl CommitmentCreateRequest {
    fn record(&self, memory: &Memory<'_>) -> MemoryResult<CommitmentRecord> {
        let kind = commitment::CommitmentObligorKind::parse(&token(&self.obligor.kind)?)
            .ok_or_else(|| MemoryError::bad_request("commitment obligor kind"))?;
        let strength = commitment::CommitmentStrength::parse(&token(&self.strength)?)
            .ok_or_else(|| MemoryError::bad_request("commitment strength"))?;
        let birth = commitment::CommitmentBirthKind::parse(&token(&self.birth_provenance.kind)?)
            .ok_or_else(|| MemoryError::bad_request("commitment birth kind"))?;
        let schedule: Schedule = shape(wire(&self.schedule)?)?;
        Ok(CommitmentRecord::new(
            commitment::CommitmentObligor::new(kind, memory.resolve_ref(&self.obligor.entity_ref)?),
            memory.resolve_ref(&self.beneficiary)?,
            commitment::CommitmentContent::new(
                &self.content.text,
                self.content.payload_ref.clone(),
            )?,
            CommitmentSchedulePayload::series(schedule, self.lead_seconds)
                .encode()
                .map_err(schedule_error)?,
            strength,
            commitment::CommitmentStatus::Open,
            commitment::CommitmentBirthProvenance::new(birth, &self.birth_provenance.reference)?,
        )?)
    }
}

impl Memory<'_> {
    fn commitment_record_in(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> MemoryResult<(crate::claim::ClaimBody, CommitmentRecord)> {
        if lane.graph_ask_raw_in_txn(txn, id)?.is_none() {
            return Err(unavailable());
        }
        // `id` stays the commitment's identity; its current status and body
        // sit at the head of its status chain.
        let head = self.vault.commitment_head_in_txn(txn, id)?;
        let body = self
            .vault
            .get_claim_in_txn(txn, &head)?
            .ok_or_else(unavailable)?;
        let record = commitment::decode_commitment_claim(&body)?.ok_or_else(unavailable)?;
        self.produced_from([*id]);
        Ok((body, record))
    }

    fn commitment_view_in(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> MemoryResult<CommitmentView> {
        let (body, record) = self.commitment_record_in(lane, txn, id)?;
        let payload =
            CommitmentSchedulePayload::decode(&record.schedule).map_err(schedule_error)?;
        let raw = self.vault.get_raw_in(txn, id)?.ok_or_else(unavailable)?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("commitment claim header"))?;
        let refs = evidence_refs(&body)?;
        let readable = lane.entities_readable_in_txn(txn, &refs)?;
        let evidence_turn_refs: Vec<String> = refs
            .into_iter()
            .zip(readable)
            .filter_map(|(id, admitted)| admitted.then(|| id.to_hex()))
            .collect();
        let status: CommitmentStatus = shape(serde_json::json!(record.status.as_str()))?;
        let fulfillment_source = match &body.evidence {
            Some(Value::Map(entries)) => entries
                .iter()
                .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
                .and_then(|(_, value)| value.as_map())
                .and_then(|entries| {
                    entries
                        .iter()
                        .find(|(key, _)| key.as_str() == Some("fulfillment_source"))
                })
                .map(|(_, value)| {
                    shape(crate::batch::export::served_messagepack_json(value.clone()))
                })
                .transpose()?,
            _ => None,
        };
        let receipt = CommitmentLifecycleReceipt {
            fulfillment_source,
            commitment_ref: id.to_hex(),
            status,
            learned_at: header.learned_at,
            evidence_turn_refs: evidence_turn_refs.clone(),
        };
        Ok(CommitmentView {
            commitment_ref: id.to_hex(),
            obligor: CommitmentObligor {
                kind: shape(serde_json::json!(record.obligor.kind.as_str()))?,
                entity_ref: record.obligor.entity_ref.to_hex(),
            },
            beneficiary: record.beneficiary.to_hex(),
            content: CommitmentContent {
                text: record.content.text,
                payload_ref: record.content.payload_ref,
            },
            schedule: shape(wire(&payload.schedule)?)?,
            lead_seconds: payload.lead_seconds,
            strength: shape(serde_json::json!(record.strength.as_str()))?,
            status,
            birth_provenance: CommitmentBirthProvenance {
                kind: shape(serde_json::json!(record.birth_provenance.kind.as_str()))?,
                reference: record.birth_provenance.reference,
            },
            series_ref: payload.series_ref.map(|id| id.to_hex()),
            occurrence: payload.occurrence.map(|occurrence| CommitmentOccurrence {
                due_at: occurrence.due_at,
                window_start: occurrence.window.start,
                window_end: occurrence.window.end,
                ordinal: occurrence.ordinal,
            }),
            occurred_at: header.occurred_start,
            learned_at: header.learned_at,
            evidence_turn_refs,
            receipt,
        })
    }

    fn commitment_evidence_in(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        refs: &[EntityId],
    ) -> MemoryResult<()> {
        if refs.is_empty() {
            return Err(MemoryError::bad_request(
                "commitment evidence must name at least one TURN",
            ));
        }
        let readable = lane.entities_readable_in_txn(txn, refs)?;
        for (id, readable) in refs.iter().zip(readable) {
            if !readable
                || self.vault.get_entity_type_in_txn(txn, id)?
                    != Some(crate::registry::ENTITY_TYPE_TURN)
            {
                return Err(MemoryError::bad_request(
                    "commitment evidence must name readable TURNs",
                ));
            }
        }
        self.produced_from(refs.iter().copied());
        Ok(())
    }

    /// An authored promise is a series, indexed by the existing projector in
    /// this same transaction. It neither approves nor schedules a reminder.
    pub fn commitments_create_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentCreateRequest,
    ) -> MemoryResult<CommitmentCreateReceipt> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let record = input.record(self)?;
        let id = super::support::id_from_optional_hex(self.vault, input.id.as_deref())?;
        let evidence = input
            .evidence_turn_refs
            .iter()
            .map(|reference| self.resolve_ref(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        let learned_at = input
            .learned_at
            .unwrap_or_else(|| self.vault.store.clock.now_recorded_at());
        if input.occurred_at > learned_at {
            return Err(MemoryError::bad_request(
                "commitment occurrence must not follow learning",
            ));
        }
        let source = self.claim_source("user_stated")?;
        let envelope = self.claim_envelope(
            source,
            "vault.commitments.create",
            ClaimApprovalStatus::Auto,
        )?;
        self.with_verified_actor_write_txn(|txn| {
            owner_in(self, txn, owner)?;
            self.commitment_evidence_in(&lane, txn, &evidence)?;
            if lane
                .entities_readable_in_txn(txn, &[record.obligor.entity_ref, record.beneficiary])?
                .iter()
                .any(|readable| !readable)
            {
                return Err(MemoryError::not_found(
                    "commitment party is unknown or withheld",
                ));
            }
            let index = self
                .vault
                .put_commitment_series_in_txn(
                    txn,
                    &id,
                    &record,
                    &envelope,
                    TimeRange {
                        start: input.occurred_at,
                        end: input.occurred_at,
                    },
                    learned_at,
                    Some(evidence_value(&evidence, source)),
                )
                .map_err(schedule_error)?;
            let index = match index {
                CommitmentSeriesWriteOutcome::Indexed {
                    project_at,
                    next_due,
                } => CommitmentIndexOutcome::Indexed {
                    project_at,
                    next_due,
                },
                CommitmentSeriesWriteOutcome::StoredRrule { route } => {
                    CommitmentIndexOutcome::StoredRrule {
                        route: route.to_owned(),
                    }
                }
                CommitmentSeriesWriteOutcome::StoredAwaitingApproval => {
                    CommitmentIndexOutcome::StoredAwaitingApproval
                }
            };
            Ok(CommitmentCreateReceipt {
                commitment: self.commitment_view_in(&lane, txn, &id)?,
                index,
            })
        })
    }

    pub fn commitments_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentRefRequest,
    ) -> MemoryResult<CommitmentView> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let id = self.resolve_ref(&input.commitment_ref)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        owner_in(self, &txn, owner)?;
        self.commitment_view_in(&lane, &txn, &id)
    }

    fn commitment_instances_in(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> MemoryResult<Vec<EntityId>> {
        let (_, record) = self.commitment_record_in(lane, txn, id)?;
        let payload =
            CommitmentSchedulePayload::decode(&record.schedule).map_err(schedule_error)?;
        if payload.is_instance() {
            return Ok(vec![*id]);
        }
        Ok(self
            .vault
            .commitment_series_history_in_txn(txn, id)
            .map_err(schedule_error)?
            .into_iter()
            .map(|entry| entry.instance_ref)
            .collect())
    }

    /// The existing membership projection includes closed occurrences too.
    pub fn commitments_instances_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentRefRequest,
    ) -> MemoryResult<Vec<CommitmentView>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let id = self.resolve_ref(&input.commitment_ref)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        owner_in(self, &txn, owner)?;
        self.commitment_instances_in(&lane, &txn, &id)?
            .iter()
            .filter_map(|id| match self.commitment_view_in(&lane, &txn, id) {
                Err(error) if error.code == super::MEMORY_CODE_NOT_FOUND => None,
                result => Some(result),
            })
            .collect()
    }

    /// Observe real timer proposals without firing, acknowledging or approving
    /// a due phase. The phase key is also the existing run approval's run id.
    pub fn commitments_proposals_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentRefRequest,
    ) -> MemoryResult<Vec<CommitmentWakeProposal>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let id = self.resolve_ref(&input.commitment_ref)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        owner_in(self, &txn, owner)?;
        let mut proposals = Vec::new();
        for instance in self.commitment_instances_in(&lane, &txn, &id)? {
            if lane.graph_ask_raw_in_txn(&txn, &instance)?.is_none() {
                continue;
            }
            for proposal in self.vault.claims_for_subject_in_txn(&txn, &instance)? {
                if lane.graph_ask_raw_in_txn(&txn, &proposal)?.is_none() {
                    continue;
                }
                let Some(body) = self.vault.get_claim_in_txn(&txn, &proposal)? else {
                    continue;
                };
                if body.predicate != crate::commitment_wake::PREDICATE_COMMITMENT_WAKE_PROPOSAL {
                    continue;
                }
                let mut value = crate::batch::export::served_messagepack_json(body.value);
                let map = value
                    .as_object_mut()
                    .ok_or(Error::CorruptedIndex("commitment wake proposal"))?;
                map.insert("instance_ref".into(), serde_json::json!(instance.to_hex()));
                map.insert("proposal_ref".into(), serde_json::json!(proposal.to_hex()));
                map.insert("approval".into(), serde_json::json!(body.approval.as_str()));
                proposals.push(shape(value)?);
                self.produced_from([instance, proposal]);
            }
        }
        Ok(proposals)
    }

    pub fn commitments_fulfill_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentFulfillRequest,
    ) -> MemoryResult<CommitmentView> {
        let close = CommitmentCloseRequest {
            commitment_ref: input.commitment_ref,
            evidence_turn_refs: input.evidence_turn_refs,
        };
        self.commitments_close_as(
            owner,
            close,
            CommitmentInstanceOutcome::Fulfilled,
            Some(input.source),
            "vault.commitments.fulfill",
        )
    }

    pub fn commitments_release_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentCloseRequest,
    ) -> MemoryResult<CommitmentView> {
        self.commitments_close_as(
            owner,
            input,
            CommitmentInstanceOutcome::Released,
            None,
            "vault.commitments.release",
        )
    }

    pub fn commitments_supersede_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentCloseRequest,
    ) -> MemoryResult<CommitmentView> {
        self.commitments_close_as(
            owner,
            input,
            CommitmentInstanceOutcome::Superseded,
            None,
            "vault.commitments.supersede",
        )
    }

    fn commitments_close_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CommitmentCloseRequest,
        outcome: CommitmentInstanceOutcome,
        fulfillment: Option<CommitmentFulfillmentSource>,
        verb: &str,
    ) -> MemoryResult<CommitmentView> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let id = self.resolve_ref(&input.commitment_ref)?;
        let evidence = input
            .evidence_turn_refs
            .iter()
            .map(|reference| self.resolve_ref(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        let fulfillment = fulfillment
            .map(|source| -> MemoryResult<FulfillmentSource> {
                Ok(match source {
                    CommitmentFulfillmentSource::UserDone => FulfillmentSource::UserDone,
                    CommitmentFulfillmentSource::ChecklistTick => FulfillmentSource::ChecklistTick,
                    CommitmentFulfillmentSource::BriefCompletion { brief_ref } => {
                        FulfillmentSource::BriefCompletion {
                            brief_ref: self.resolve_ref(&brief_ref)?,
                        }
                    }
                })
            })
            .transpose()?;
        let source = self.claim_source("user_stated")?;
        let envelope = self.claim_envelope(source, verb, ClaimApprovalStatus::Auto)?;
        let now = self.vault.store.clock.now_recorded_at();
        self.with_verified_actor_write_txn(|txn| {
            owner_in(self, txn, owner)?;
            self.commitment_evidence_in(&lane, txn, &evidence)?;
            let (_, record) = self.commitment_record_in(&lane, txn, &id)?;
            let payload =
                CommitmentSchedulePayload::decode(&record.schedule).map_err(schedule_error)?;
            if !payload.is_instance() {
                return Err(MemoryError::bad_request(
                    "close a materialized commitment instance",
                ));
            }
            let evidence = Some(evidence_value(&evidence, source));
            if let Some(fulfillment) = fulfillment {
                if let FulfillmentSource::BriefCompletion { brief_ref } = fulfillment {
                    if lane.graph_ask_raw_in_txn(txn, &brief_ref)?.is_none() {
                        return Err(MemoryError::not_found(
                            "fulfilling brief is unknown or withheld",
                        ));
                    }
                    self.produced_from([brief_ref]);
                }
                crate::commitment_lifecycle::fulfill_commitment_from_in_txn(
                    self.vault,
                    txn,
                    &id,
                    fulfillment,
                    &envelope,
                    now,
                    evidence,
                )?;
            } else {
                crate::commitment_lifecycle::close_commitment_in_txn(
                    self.vault, txn, &id, &envelope, now, outcome, evidence,
                )?;
            }
            self.commitment_view_in(&lane, txn, &id)
        })
    }
}
