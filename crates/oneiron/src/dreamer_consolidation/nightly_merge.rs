//! Nightly fan-in over child proposals. Mechanical identity links and open
//! conflicts never ask a model to rethink a child's judgement. Narrative
//! generation sees only the proposals, not source transcripts or prior prose.

use super::executor::ConsolidationExecutor;
use super::roles::{DREAMER_NARRATIVE_ROLE, RoleCall};
use super::step_charge::StepChargeTally;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ScopedReadActorKey, claim_evidence_taint,
};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerConsolidationScope, DreamerParkCause,
    DreamerRunnerStore,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext, DurableStepError,
    LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, Scope, StepOutcome,
    TierPrecedence, call_as_step,
};
use crate::side_table::{self, Named, SideTable};
use crate::{
    ClaimCandidate, EntityId, Error, Result, SourceLineage, TimeRange, Vault, WriteEnvelope,
    WriteProvenance,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const ATTEMPT: &str = "dreamer.nightly.merge";
const OUTPUT: SideTable<AttemptId, Vec<EntityId>, Named> =
    SideTable::new(&side_table::DREAMER_NIGHTLY_OUTPUT);
const MERGED: SideTable<AttemptId, MergeResult, Named> =
    SideTable::new(&side_table::DREAMER_NIGHTLY_MERGED);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MergeInput {
    children: Vec<AttemptId>,
    instruction: String,
    retry_secs: u64,
}

#[derive(Serialize, Deserialize)]
struct MergeResult {
    outputs: Vec<EntityId>,
    completed_units: u64,
    step_hashes: Vec<[u8; 32]>,
}

pub(crate) fn record_outputs(vault: &Vault, attempt: AttemptId, ids: &[EntityId]) -> Result<()> {
    let Some(record) = AttemptQueue::new(vault).get(attempt)? else {
        return Err(invalid());
    };
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)?;
    if record.kind != DreamerConsolidationScope::Macro.attempt_kind()
        || payload.parent_attempt.is_none()
    {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        let mut outputs = OUTPUT.get(&vault.store, txn, &attempt)?.unwrap_or_default();
        outputs.extend(ids);
        outputs.sort_unstable();
        outputs.dedup();
        OUTPUT.put(&vault.store, txn, &attempt, &outputs)
    })
}

pub(crate) fn enqueue_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: &DreamerAdmittedAttempt,
    children: Vec<AttemptId>,
    now: u64,
) -> Result<()> {
    if children.is_empty() {
        return Ok(());
    }
    let policy = crate::dreamer_wake::recipes::policy_in_txn(vault, txn)?;
    let input = serde_json::to_string(&MergeInput {
        children,
        instruction: policy.narrative_instruction,
        retry_secs: policy.rung_retry_secs,
    })
    .map_err(|_| invalid())?;
    let dedupe = format!("{ATTEMPT}:{}", blake3::hash(input.as_bytes()).to_hex());
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Macro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: ATTEMPT.into(),
            input: input.into(),
            parent_attempt: Some(parent.status.attempt.id),
        },
        Some(dedupe),
        parent.status.attempt.run_id.clone(),
        now,
    )?;
    Ok(())
}

struct Proposal {
    id: EntityId,
    raw: Vec<u8>,
    body: ClaimBody,
}

impl ConsolidationExecutor<'_> {
    pub(super) async fn run_nightly_merge(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if self.scope.is_some() {
            return Err(invalid());
        }
        let input: MergeInput =
            serde_json::from_str(attempt.status.payload.input.as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        let key = ScopedReadActorKey::with_actor_class(
            self.actor.entity_ref().to_hex(),
            self.actor.actor_class().gate_actor_class(),
        )
        .ok_or_else(invalid)?;
        ctx.vault.store.authorization_now()?;
        let read = ctx.vault.scoped_read(key);
        let proposals = {
            let txn = ctx.vault.store.env.read_txn()?;
            if let Some(result) = MERGED.get(&ctx.vault.store, &txn, &attempt.status.attempt.id)? {
                let mut paid = !result.step_hashes.is_empty();
                for hash in &result.step_hashes {
                    paid &= DreamerRunnerStore::new(ctx.vault)
                        .checkpoint_step_charged(attempt.status.attempt.id, hash)?;
                }
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units: if paid { 0 } else { result.completed_units },
                });
            }
            let mut ids = BTreeSet::new();
            for id in &input.children {
                let child = AttemptQueue::new(ctx.vault)
                    .get_in_txn(&txn, *id)?
                    .ok_or_else(invalid)?;
                if !child.state.is_terminal() {
                    return Ok(DreamerAttemptExecution::Deferred {
                        completed_units: 0,
                        retry_at: (ctx.now_ms / 1_000).saturating_add(input.retry_secs),
                    });
                }
                ids.extend(OUTPUT.get(&ctx.vault.store, &txn, id)?.unwrap_or_default());
            }
            let mut proposals = Vec::new();
            for id in ids {
                let Some(raw) = read.entity_raw_live_in(&txn, &id)? else {
                    continue;
                };
                let Some(body) = ctx.vault.get_claim_in_txn(&txn, &id)? else {
                    continue;
                };
                if body.lifecycle == ClaimLifecycleStatus::Active
                    && body.approval != ClaimApprovalStatus::Rejected
                    && !body.stale
                {
                    proposals.push(Proposal { id, raw, body });
                }
            }
            proposals
        };
        // Exposure axes never merge. Each narrative is a bounded summary of
        // this scope's proposal set, not evidence for any new belief.
        let mut groups = BTreeMap::new();
        for proposal in &proposals {
            let body = &proposal.body;
            let scope_key =
                super::support::encode_value(body.scope.as_ref().unwrap_or(&Value::Nil))?;
            groups
                .entry((
                    body.world,
                    body.scope_facet,
                    body.rel,
                    body.scope_project,
                    scope_key,
                ))
                .or_insert_with(Vec::new)
                .push(proposal);
        }
        let mut drafts = Vec::new();
        let mut charges = StepChargeTally::default();
        for members in groups.values() {
            let first = &members[0].body;
            let mut identity: BTreeMap<Vec<u8>, Vec<&Proposal>> = BTreeMap::new();
            for member in members {
                let topic = super::conflict::topic_key(member.body.scope.as_ref())?;
                let encoded = super::support::encode_value(&Value::Array(vec![
                    Value::Binary(member.body.subject.encode()),
                    member.body.predicate.clone().into(),
                    topic.map_or(Value::Nil, Value::Binary),
                ]))?;
                identity.entry(encoded).or_default().push(member);
            }
            for cohort in identity.values().filter(|cohort| cohort.len() > 1) {
                let same = cohort
                    .iter()
                    .all(|member| member.body.value == cohort[0].body.value);
                if same {
                    for peer in cohort.iter().skip(1) {
                        let candidate = ClaimCandidate::new(
                            crate::claim::PREDICATE_COREFERENCE_STATUS,
                            ClaimSubject::Edge {
                                source: cohort[0].id,
                                kind: crate::edge::EdgeKind::SameAs,
                                target: peer.id,
                            },
                            Value::from(crate::claim::COREFERENCE_STATUS_PROPOSED),
                            1.0,
                        );
                        drafts.push(scoped_draft(candidate, first, &cohort));
                    }
                } else {
                    let value = Value::Map(vec![
                        ("predicate".into(), cohort[0].body.predicate.clone().into()),
                        (
                            "candidates".into(),
                            Value::Array(
                                cohort
                                    .iter()
                                    .map(|p| Value::Binary(p.id.as_bytes().to_vec()))
                                    .collect(),
                            ),
                        ),
                    ]);
                    let candidate = ClaimCandidate::new(
                        crate::claim::PREDICATE_CONFLICT_OPEN,
                        cohort[0].body.subject,
                        value,
                        1.0,
                    );
                    drafts.push(scoped_draft(candidate, first, &cohort));
                }
            }
            let call = RoleCall::resolve(
                &self.roles,
                DREAMER_NARRATIVE_ROLE,
                self.backend,
                &self.model,
                &self.inference.binding,
                self.inference.extraction_egress,
            );
            let locality = match call.inference.selected_locality() {
                Some(locality) => locality,
                None => return Ok(charges.park("nightly narrative needs locality")),
            };
            let mut scope = Scope::default();
            scope.world = first.world;
            scope.relationship = first.rel;
            scope.project = Some(first.scope_project);
            let mut text = String::new();
            for member in members {
                scope.readable.insert(super::resources::document_version(
                    member.id,
                    &member.raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                ));
                let value = super::value_projection::rmpv_to_json(&member.body.value);
                text.push_str(&format!(
                    "{} subject={} approval={} {} {}\n",
                    member.id.to_hex(),
                    crate::entity_id::bytes_to_hex_lower(&member.body.subject.encode()),
                    member.body.approval.as_str(),
                    member.body.predicate,
                    value
                ));
            }
            let mut request = LlmRequest {
                model: call.model.clone(),
                envelope: CallEnvelope {
                    seat_effort: None,
                    scope,
                    purpose: CallPurpose::Extraction,
                    class: CallClass::BestEffort,
                    tier: TierPrecedence::for_purpose(
                        &CallPurpose::Extraction,
                        ModelTierRef("consolidation".into()),
                    ),
                    response_format: ResponseFormat::Text,
                    locality,
                }
                .with_purpose_defaults(),
                messages: vec![
                    LlmMessage {
                        role: LlmMessageRole::System,
                        content: vec![ContentPart::Text {
                            text: input.instruction.clone(),
                        }],
                    },
                    LlmMessage {
                        role: LlmMessageRole::User,
                        content: vec![ContentPart::Text { text }],
                    },
                ],
                tools: Vec::new(),
                params: BTreeMap::new(),
                provider_options: BTreeMap::new(),
            };
            request = match ctx.vault.authorize_model_role(
                DREAMER_NARRATIVE_ROLE,
                request,
                &call.inference,
            ) {
                Ok(request) => request.into_request(),
                Err(error) => return Ok(charges.park(&error.to_string())),
            };
            if let Err(error) = super::roles::bind_reasoning(ctx.vault, call.backend, &mut request)
            {
                return Ok(charges.park(&error.to_string()));
            }
            let hash = match request.canonical_hash() {
                Ok(hash) => hash,
                Err(_) => return Ok(charges.park("nightly narrative hash failed")),
            };
            let step = DurableStepContext {
                vault: ctx.vault,
                attempt_id: attempt.status.attempt.id,
                run_id: attempt.status.attempt.run_id.clone(),
                envelope_actor: self.actor,
                subject: first.scope_project,
                deadline: Some(ctx.deadline),
                now_ms: ctx.now_ms,
            };
            let response = match call_as_step(&step, call.backend, self.guard, request).await {
                Ok(StepOutcome::Finished {
                    response,
                    failure_policy,
                    ..
                }) => {
                    charges.record_terminal(
                        ctx.vault,
                        attempt.status.attempt.id,
                        hash,
                        &response.usage,
                    )?;
                    if failure_policy.is_some() {
                        return charges.park_on_fallback(
                            ctx.vault,
                            attempt.status.attempt.id,
                            hash,
                            "nightly narrative requires generation",
                            &response,
                        );
                    }
                    response
                }
                Ok(StepOutcome::Trapped { .. }) => {
                    return Ok(charges
                        .park_for("durable step trapped for resume", DreamerParkCause::Signal));
                }
                Err(DurableStepError::SpentFinalizeRefused { usage })
                | Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.checkpoint());
                }
                Err(error) => {
                    return Ok(
                        charges.park_for(&error.to_string(), DreamerParkCause::of_step(&error))
                    );
                }
            };
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
            let narrative: String = response
                .message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect();
            if narrative.trim().is_empty() {
                return Ok(charges.park("empty nightly narrative"));
            }
            let candidate = ClaimCandidate::new(
                "dreamer.arc.summary",
                ClaimSubject::Entity(first.scope_project),
                narrative.into(),
                1.0,
            );
            drafts.push(scoped_draft(candidate, first, members));
        }
        let now = ctx.now_ms / 1_000;
        let commit = ctx.vault.with_write_txn_grouped(|txn| {
            for proposal in &proposals {
                if read.entity_raw_live_in(txn, &proposal.id)?.as_ref() != Some(&proposal.raw) {
                    return Err(Error::ConcurrentWrite(
                        "nightly proposal changed before merge",
                    ));
                }
            }
            let mut outputs = Vec::new();
            for (index, draft) in drafts.into_iter().enumerate() {
                let (candidate, meet) = draft?;
                let id = crate::codebase::entity_id_from_hash_material(
                    b"oneiron:nightly:merge:v1",
                    &[
                        attempt.status.attempt.id.as_bytes(),
                        &(index as u64).to_be_bytes(),
                    ],
                )?;
                let requested = if candidate.predicate() == crate::claim::PREDICATE_CONFLICT_OPEN {
                    ClaimApprovalStatus::Proposed
                } else {
                    ClaimApprovalStatus::Auto
                };
                let mut envelope = WriteEnvelope::with_lineage(
                    self.actor,
                    meet,
                    WriteProvenance::new(Value::Map(vec![
                        ("surface".into(), "dreamer".into()),
                        (
                            "run".into(),
                            attempt
                                .status
                                .attempt
                                .run_id
                                .clone()
                                .unwrap_or_else(|| {
                                    crate::entity_id::bytes_to_hex_lower(
                                        attempt.status.attempt.id.as_bytes(),
                                    )
                                })
                                .into(),
                        ),
                    ]))?,
                    requested,
                    SourceLineage::of(ClaimSource::Generated).with(meet),
                );
                ctx.vault.sign_retained_machine_claim_in_txn(
                    txn,
                    &id,
                    &candidate,
                    &mut envelope,
                )?;
                ctx.vault
                    .batch_in()
                    .claim_candidate(
                        &id,
                        candidate,
                        &envelope,
                        TimeRange {
                            start: now,
                            end: now,
                        },
                        now,
                    )
                    .apply_recording_gate_decisions(txn)?;
                outputs.push(id);
            }
            MERGED.put(
                &ctx.vault.store,
                txn,
                &attempt.status.attempt.id,
                &MergeResult {
                    outputs,
                    completed_units: charges.units,
                    step_hashes: charges.step_hashes.clone(),
                },
            )
        });
        match commit {
            Ok(()) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
            }),
            Err(error) => Ok(charges.park(&error.to_string())),
        }
    }
}

fn scoped_draft(
    candidate: ClaimCandidate,
    body: &ClaimBody,
    members: &[&Proposal],
) -> Result<(ClaimCandidate, ClaimSource)> {
    let meet = members.iter().fold(ClaimSource::Generated, |meet, member| {
        super::source_meet(
            meet,
            claim_evidence_taint(&member.body)
                .or(member.body.source)
                .unwrap_or(ClaimSource::Generated),
        )
    });
    let mut candidate = candidate
        .with_scope_stamps(body.scope_facet, body.scope_project)
        .with_evidence(Value::Map(vec![(
            "refs".into(),
            Value::Array(
                members
                    .iter()
                    .map(|member| Value::Binary(member.id.as_bytes().to_vec()))
                    .collect(),
            ),
        )]));
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(rel) = body.rel {
        candidate = candidate.with_relationship(rel);
    }
    if let Some(scope) = &body.scope {
        candidate = candidate.with_scope(scope.clone());
    }
    Ok((candidate.with_evidence_taint(meet)?, meet))
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid nightly merge input".into())
}
