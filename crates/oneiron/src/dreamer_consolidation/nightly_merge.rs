//! Nightly fan-in over child proposals. Mechanical identity links and open
//! conflicts never ask a model to rethink a child's judgement. Narrative
//! generation sees only the proposals, not source transcripts or prior prose.

use super::call_labels::{CallLabel, CallLabelMap, LabelKind};
use super::executor::ConsolidationExecutor;
use super::roles::{DREAMER_NARRATIVE_ROLE, RoleCall};
use super::step_charge::StepChargeTally;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ScopedReadActorKey, claim_evidence_taint,
};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerAttemptStatus, DreamerConsolidationScope,
    DreamerParkCause, DreamerRunnerStore,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext, DurableStepError,
    LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, ModelTierRef, ResponseFormat, Scope,
    StepOutcome, TierPrecedence, call_as_step_checked,
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
    /// The listed children's retry chunks this merge read (FIX 7495), so no
    /// later merge under the same parent reads them again.
    #[serde(default)]
    chunks: Vec<AttemptId>,
}

pub(crate) fn record_outputs(vault: &Vault, attempt: AttemptId, ids: &[EntityId]) -> Result<()> {
    if AttemptQueue::new(vault).get(attempt)?.is_none() {
        return Err(invalid());
    }
    vault.with_write_txn_grouped(|txn| {
        let mut outputs = OUTPUT.get(&vault.store, txn, &attempt)?.unwrap_or_default();
        outputs.extend(ids);
        outputs.sort_unstable();
        outputs.dedup();
        OUTPUT.put(&vault.store, txn, &attempt, &outputs)
    })
}

/// The existing extraction and merge result ledgers in the caller's snapshot.
pub(crate) fn outputs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Vec<EntityId>> {
    let mut outputs = OUTPUT.get(&vault.store, txn, &attempt)?.unwrap_or_default();
    if let Some(merged) = MERGED.get(&vault.store, txn, &attempt)? {
        outputs.extend(merged.outputs);
    }
    outputs.sort_unstable();
    outputs.dedup();
    Ok(outputs)
}

/// Outputs already accepted by the promotion sink for this attempt.
pub(crate) fn extraction_outputs(vault: &Vault, attempt: AttemptId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    Ok(OUTPUT
        .get(&vault.store, &txn, &attempt)?
        .unwrap_or_default())
}

pub(crate) fn enqueue_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: &DreamerAttemptStatus,
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
            parent_attempt: Some(parent.attempt.id),
        },
        Some(dedupe),
        parent.attempt.run_id.clone(),
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
        let (proposals, chunks) = {
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
            // A listed child's retry chunks fan in beside it (FIX 7495).
            let chunks = retry_chunks_in_txn(ctx.vault, &txn, &attempt.status, &input.children);
            let mut ids = BTreeSet::new();
            for id in input.children.iter().chain(&chunks) {
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
            (proposals, chunks)
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
                // A missing locality, a request that did not hash and an
                // empty narrative wait on no owner act: each resumes after
                // its retry delay (OF-193a).
                None => {
                    return Ok(charges
                        .park_for("nightly narrative needs locality", DreamerParkCause::Retry));
                }
            };
            let mut scope = Scope::default();
            scope.world = first.world;
            scope.relationship = first.rel;
            scope.project = Some(first.scope_project);
            // Each proposal and subject by this call's own labels (FIX
            // 7506): the claims `C<n>` in the order they render, then each
            // subject entity `P<n>`; an edge by its endpoints and kind.
            let mut labels = CallLabelMap::default();
            for member in members {
                labels.assign(LabelKind::Claim, member.id);
            }
            let mut text = String::new();
            for member in members {
                scope.readable.insert(super::resources::document_version(
                    member.id,
                    &member.raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                ));
                let value = super::value_projection::rmpv_to_json(&member.body.value);
                let claim = labels.assign(LabelKind::Claim, member.id);
                let subject = subject_label(&mut labels, &member.body.subject);
                text.push_str(&format!(
                    "{claim} subject={subject} approval={} {} {value}\n",
                    member.body.approval.as_str(),
                    member.body.predicate,
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
            labels.bind_request(&mut request, None);
            request = match ctx.vault.authorize_model_role(
                DREAMER_NARRATIVE_ROLE,
                request,
                &call.inference,
            ) {
                Ok(request) => request.into_request(),
                Err(error) => return Ok(charges.park_on_error(&error)),
            };
            if let Err(error) = super::roles::bind_reasoning(ctx.vault, call.backend, &mut request)
            {
                return Ok(charges.park_on_error(&error));
            }
            let hash = match request.canonical_hash() {
                Ok(hash) => hash,
                Err(_) => {
                    return Ok(
                        charges.park_for("nightly narrative hash failed", DreamerParkCause::Retry)
                    );
                }
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
            let response = match call_as_step_checked(
                &step,
                call.backend,
                self.guard,
                request,
                &check_narrative_reply,
            )
            .await
            {
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
                            NARRATIVE_FALLBACK,
                            &response,
                        );
                    }
                    response
                }
                Ok(StepOutcome::Trapped { .. }) => {
                    return Ok(charges
                        .park_for("durable step trapped for resume", DreamerParkCause::Signal));
                }
                Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.checkpoint());
                }
                // A reply the check refused was paid and never memoized: it
                // is asked again after its retry delay (FIX 7431).
                Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.park_for(&errors.join("; "), DreamerParkCause::Retry));
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
            let narrative = match narrative_text(&response) {
                Ok(narrative) => narrative,
                // Only a memo stored before the check can be empty: it goes,
                // and the Retry asks again (FIX 7431).
                Err(reason) => {
                    return charges.park_refused_reply(
                        ctx.vault,
                        attempt.status.attempt.id,
                        hash,
                        reason,
                    );
                }
            };
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
                    chunks,
                },
            )
        });
        match commit {
            Ok(()) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
            }),
            // A proposal that moved before the merge commits again on resume;
            // a gate only an owner act opens keeps the private park.
            Err(error) => Ok(charges.park_on_error(&error)),
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
    if let Some(scope) = crate::claim::without_initial_weight(body.scope.clone()) {
        candidate = candidate.with_scope(scope);
    }
    Ok((candidate.with_evidence_taint(meet)?, meet))
}

/// The retry chunks of `listed` (FIX 7495): the partition attempts a listed
/// child's selection retry owed as its siblings (`wake_plan/chunks.rs`),
/// under this merge's parent and in a listed child's partition. One that
/// another merge under that parent lists, or has read, is that merge's. A
/// lineage that does not read leaves the listed children alone, as before:
/// nothing here refuses a merge.
fn retry_chunks_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    merge: &DreamerAttemptStatus,
    listed: &[AttemptId],
) -> Vec<AttemptId> {
    let Some(parent) = merge.payload.parent_attempt else {
        return Vec::new();
    };
    chunks_under_in_txn(vault, txn, merge.attempt.id, parent, listed).unwrap_or_else(|error| {
        tracing::warn!(
            merge = %crate::entity_id::bytes_to_hex_lower(merge.attempt.id.as_bytes()),
            kind = ?error.kind(),
            "nightly merge retry chunks did not read; it fans in its listed children"
        );
        Vec::new()
    })
}

/// [`retry_chunks_in_txn`] over `parent`'s run-tree children.
fn chunks_under_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    merge: AttemptId,
    parent: AttemptId,
    listed: &[AttemptId],
) -> Result<Vec<AttemptId>> {
    let queue = AttemptQueue::new(vault);
    let mut partitions = BTreeSet::new();
    for id in listed {
        if let Some(record) = queue.get_in_txn(txn, *id)?
            && let Ok(payload) =
                crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
            && let Ok((key, _, _)) = super::partition::decode_partition_payload(&payload.input)
        {
            partitions.insert(key);
        }
    }
    let mut claimed: BTreeSet<AttemptId> = listed.iter().copied().collect();
    let mut candidates = Vec::new();
    for sibling in DreamerRunnerStore::new(vault).child_attempts_in_txn(txn, parent)? {
        if sibling == merge {
            continue;
        }
        let Some(record) = queue.get_in_txn(txn, sibling)? else {
            continue;
        };
        let Ok(payload) = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)
        else {
            continue;
        };
        if payload.attempt_type == ATTEMPT {
            if let Some(input) = payload
                .input
                .as_str()
                .and_then(|raw| serde_json::from_str::<MergeInput>(raw).ok())
            {
                claimed.extend(input.children);
            }
            if let Some(result) = MERGED.get(&vault.store, txn, &sibling)? {
                claimed.extend(result.chunks);
            }
        } else if payload.attempt_type == DreamerConsolidationScope::Macro.as_str()
            && super::partition::decode_partition_payload(&payload.input)
                .is_ok_and(|(key, _, _)| partitions.contains(&key))
        {
            candidates.push(sibling);
        }
    }
    candidates.retain(|id| !claimed.contains(id));
    Ok(candidates)
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid nightly merge input".into())
}

/// Why a narrative step parks on a deterministic fallback.
const NARRATIVE_FALLBACK: &str = "nightly narrative requires generation";
/// Why a narrative reply is refused: it holds no text.
const EMPTY_NARRATIVE: &str = "empty nightly narrative";

/// A narrative reply's text, refused when blank. The step's check and the
/// landing read it alike (FIX 7431).
fn narrative_text(response: &LlmResponse) -> std::result::Result<String, &'static str> {
    let narrative = super::step_charge::reply_text(response);
    if narrative.trim().is_empty() {
        Err(EMPTY_NARRATIVE)
    } else {
        Ok(narrative)
    }
}

/// The narrative step's check (FIX 7431). A deterministic fallback parks at
/// the site, as before, unless its park would resume as a Retry: that one is
/// refused here, paid and never memoized, so the Retry asks the model again.
/// Any other reply is refused when blank.
fn check_narrative_reply(response: &LlmResponse) -> std::result::Result<(), String> {
    if super::step_charge::retry_fallback(response) {
        return Err(NARRATIVE_FALLBACK.to_owned());
    }
    if crate::llm::fallback_failure_class(response).is_some() {
        return Ok(());
    }
    narrative_text(response).map(|_| ()).map_err(str::to_owned)
}

/// A proposal's subject as its narrative call names it: an entity by its
/// label (a proposal's own `C<n>` when it is one, else `P<n>`), an edge as
/// `<kind>(<source>,<target>)` over its endpoints' labels.
fn subject_label(labels: &mut CallLabelMap, subject: &ClaimSubject) -> String {
    let mut label = |id: EntityId| -> CallLabel {
        labels
            .label(LabelKind::Claim, id)
            .unwrap_or_else(|| labels.assign(LabelKind::Entity, id))
    };
    match *subject {
        ClaimSubject::Entity(id) => label(id).to_string(),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => {
            let (source, target) = (label(source), label(target));
            format!("{}({source},{target})", kind.name())
        }
    }
}
