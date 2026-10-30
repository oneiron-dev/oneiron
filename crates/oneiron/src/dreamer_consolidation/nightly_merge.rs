//! Nightly fan-in over child proposals. Mechanical identity links and open
//! conflicts never ask a model to rethink a child's judgement. Narrative
//! generation sees only the proposals, not source transcripts or prior prose.
//! Semantic links across children are judged after the merge lands, by its
//! own link continuations (OF-498d, `super::nightly_links`), proposals only.

use super::call_labels::{CallLabelMap, LabelKind};
use super::executor::ConsolidationExecutor;
use super::nightly_links::NightlyLinkProposal;
use super::roles::{DREAMER_NARRATIVE_ROLE, RoleCall};
use super::step_charge::StepChargeTally;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedRead as ClaimRead,
    ScopedReadActorKey,
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
use crate::write_envelope::WriteActor;
use crate::{ClaimCandidate, EntityId, Error, Result, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod chunks;
mod narrative_labels;
mod write;
pub(super) use super::call_labels::subject_label;
use chunks::retry_chunks_in_txn;
pub(super) use write::{Draft, NightlyWrite, landed_units_in_txn, recheck_in_txn, scoped_draft};

pub(crate) const ATTEMPT: &str = "dreamer.nightly.merge";
/// The domain the merge's own claims derive their ids under.
const MERGE_IDS: &[u8] = b"oneiron:nightly:merge:v1";
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

/// What one nightly attempt landed, in the result ledger: the merge's, or
/// one of its link continuations' (OF-498d).
#[derive(Serialize, Deserialize)]
pub(super) struct MergeResult {
    pub(super) outputs: Vec<EntityId>,
    pub(super) completed_units: u64,
    pub(super) step_hashes: Vec<[u8; 32]>,
    /// The listed children's retry chunks this merge read (FIX 7495), so no
    /// later merge under the same parent reads them again.
    #[serde(default)]
    pub(super) chunks: Vec<AttemptId>,
    /// Every pair a link continuation judged, whatever its verdict, each
    /// same-as with the proposal claim it wrote (OF-498d); none for a merge.
    pub(super) links: Vec<NightlyLinkProposal>,
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

/// One child proposal a nightly attempt reads: its live raw bytes and body,
/// and every child whose outputs hold it, in order (OF-498d).
pub(super) struct Proposal {
    pub(super) id: EntityId,
    pub(super) raw: Vec<u8>,
    pub(super) body: ClaimBody,
    pub(super) children: Vec<AttemptId>,
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
        let read = merge_read(ctx.vault, self.actor)?;
        let (proposals, chunks) = {
            let txn = ctx.vault.store.env.read_txn()?;
            if let Some((completed_units, step_hashes)) =
                landed_units_in_txn(ctx.vault, &txn, attempt.status.attempt.id)?
            {
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units,
                    step_hashes,
                });
            }
            // A listed child's retry chunks fan in beside it (FIX 7495).
            let chunks = retry_chunks_in_txn(ctx.vault, &txn, &attempt.status, &input.children);
            let fan_in: Vec<AttemptId> = input.children.iter().chain(&chunks).copied().collect();
            let Some(proposals) = proposals_in_txn(ctx.vault, &txn, &read, &fan_in)? else {
                return Ok(DreamerAttemptExecution::Deferred {
                    completed_units: 0,
                    retry_at: (ctx.now_ms / 1_000).saturating_add(input.retry_secs),
                    step_hashes: Vec::new(),
                });
            };
            (proposals, chunks)
        };
        // Exposure axes never merge. Each narrative is a bounded summary of
        // this scope's proposal set, not evidence for any new belief.
        let groups = exposure_groups(&proposals)?;
        // The proposals that lead a cross-child pair: each one's pairs are
        // judged after this merge lands, by a link continuation (OF-498d).
        let anchors = super::nightly_links::anchors(&groups)?;
        let mut drafts = Vec::new();
        let mut charges = StepChargeTally::default();
        for members in &groups {
            let first = &members[0].body;
            let mut identity: BTreeMap<Vec<u8>, Vec<&Proposal>> = BTreeMap::new();
            for member in members {
                let key = match identity_key(&member.body) {
                    Ok(key) => key,
                    Err(error) => {
                        return super::residency::spent_or_deferred(error, ctx, &charges);
                    }
                };
                identity.entry(key).or_default().push(member);
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
            let keyless = call.inference.selected_keyless();
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
            scope.relationship.clone_from(&first.rel);
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
                    host_keyless: keyless,
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
                host_segments: None,
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
                    memoized,
                    failure_policy,
                    ..
                }) => {
                    if let Err(error) = charges.record_terminal(
                        ctx.vault,
                        attempt.status.attempt.id,
                        hash,
                        &response.usage,
                    ) {
                        if !memoized {
                            charges.record_usage(&response.usage);
                        }
                        return super::residency::spent_or_deferred(error, ctx, &charges);
                    }
                    if failure_policy.is_some() {
                        return match charges.park_on_fallback(
                            ctx.vault,
                            attempt.status.attempt.id,
                            hash,
                            NARRATIVE_FALLBACK,
                            &response,
                        ) {
                            Ok(parked) => Ok(parked),
                            Err(error) => super::residency::spent_or_deferred(error, ctx, &charges),
                        };
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
                    return match charges.park_refused_reply(
                        ctx.vault,
                        attempt.status.attempt.id,
                        hash,
                        reason,
                    ) {
                        Ok(parked) => Ok(parked),
                        Err(error) => super::residency::spent_or_deferred(error, ctx, &charges),
                    };
                }
            };
            // A call's labels mean nothing past it: the stored text names
            // what each stood for (FIX 7576).
            let names = match narrative_labels::durable_names(ctx.vault, &read, &labels, members) {
                Ok(names) => names,
                Err(error) => return Ok(charges.park_on_error(&error)),
            };
            let narrative = narrative_labels::durable_text(&narrative, &names);
            let candidate = ClaimCandidate::new(
                "dreamer.arc.summary",
                ClaimSubject::Entity(first.scope_project),
                narrative.into(),
                1.0,
            );
            drafts.push(scoped_draft(candidate, first, members));
        }
        let now = ctx.now_ms / 1_000;
        let writer = NightlyWrite {
            vault: ctx.vault,
            actor: self.actor,
            attempt: &attempt.status,
            ids: MERGE_IDS,
            now,
        };
        let read_back: Vec<&Proposal> = proposals.iter().collect();
        let commit = ctx.vault.with_write_txn_grouped(|txn| {
            let _hold = crate::dreamer_consolidation::stage_log::WriterHold::start("nightly merge");
            recheck_in_txn(&read, txn, &read_back)?;
            let outputs = writer.claims_in_txn(txn, drafts)?;
            writer.result_in_txn(
                txn,
                &MergeResult {
                    outputs,
                    completed_units: charges.units,
                    step_hashes: charges.step_hashes.clone(),
                    chunks,
                    links: Vec::new(),
                },
            )?;
            // Each cross-child pair is judged after these outputs land, by a
            // continuation the night's wake never waits on (OF-498d).
            super::nightly_links::enqueue_in_txn(ctx.vault, txn, &attempt.status, &anchors, now)
        });
        match commit {
            Ok(()) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
                step_hashes: charges.step_hashes.clone(),
            }),
            // A proposal that moved before the merge commits again on resume;
            // a gate only an owner act opens keeps the private park.
            Err(error) => Ok(charges.park_on_error(&error)),
        }
    }
}

/// The Dreamer's own scoped read, as a nightly attempt reads its proposals.
pub(super) fn merge_read(vault: &Vault, actor: WriteActor) -> Result<ClaimRead<'_>> {
    let key = ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or_else(invalid)?;
    vault.store.authorization_now()?;
    Ok(vault.scoped_read(key))
}

/// Each proposal the `children` output that the Dreamer reads live and that
/// stands (active, not rejected, not stale), in id order, with every child
/// whose outputs hold it: what a merge fans in, and what its link
/// continuations pair (OF-498d). None while one of the children is not
/// finished.
pub(super) fn proposals_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ClaimRead<'_>,
    children: &[AttemptId],
) -> Result<Option<Vec<Proposal>>> {
    let mut ids: BTreeMap<EntityId, BTreeSet<AttemptId>> = BTreeMap::new();
    for id in children {
        let child = AttemptQueue::new(vault)
            .get_in_txn(txn, *id)?
            .ok_or_else(invalid)?;
        if !child.state.is_terminal() {
            return Ok(None);
        }
        for output in OUTPUT.get(&vault.store, txn, id)?.unwrap_or_default() {
            ids.entry(output).or_default().insert(*id);
        }
    }
    let mut proposals = Vec::new();
    for (id, origins) in ids {
        let Some(raw) = read.entity_raw_live_in(txn, &id)? else {
            continue;
        };
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if body.lifecycle == ClaimLifecycleStatus::Active
            && body.approval != ClaimApprovalStatus::Rejected
            && !body.stale
        {
            proposals.push(Proposal {
                id,
                raw,
                body,
                children: origins.into_iter().collect(),
            });
        }
    }
    Ok(Some(proposals))
}

/// `proposals` by exposure, in key order: world, facet, relationship,
/// project and scope. Exposure axes never merge.
pub(super) fn exposure_groups(proposals: &[Proposal]) -> Result<Vec<Vec<&Proposal>>> {
    let mut groups: BTreeMap<_, Vec<&Proposal>> = BTreeMap::new();
    for proposal in proposals {
        let body = &proposal.body;
        let scope_key = super::support::encode_value(body.scope.as_ref().unwrap_or(&Value::Nil))?;
        groups
            .entry((
                body.world,
                body.scope_facet,
                body.rel.clone(),
                body.scope_project,
                scope_key,
            ))
            .or_default()
            .push(proposal);
    }
    Ok(groups.into_values().collect())
}

/// A proposal's exact identity: its subject, predicate and topic. The merge
/// compares the proposals of one identity mechanically.
pub(super) fn identity_key(body: &ClaimBody) -> Result<Vec<u8>> {
    let topic = super::conflict::topic_key(body.scope.as_ref())?;
    super::support::encode_value(&Value::Array(vec![
        Value::Binary(body.subject.encode()),
        body.predicate.clone().into(),
        topic.map_or(Value::Nil, Value::Binary),
    ]))
}

/// What a landed merge read (OF-498d): its listed children with the retry
/// chunks it fanned in beside them, and its retry delay. Its link
/// continuations read the same children.
pub(super) struct MergedSnapshot {
    pub(super) children: Vec<AttemptId>,
    pub(super) retry_secs: u64,
}

/// The [`MergedSnapshot`] of the landed merge `merge`, from its queued input
/// and its result.
pub(super) fn merged_snapshot_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    merge: AttemptId,
) -> Result<MergedSnapshot> {
    let record = AttemptQueue::new(vault)
        .get_in_txn(txn, merge)?
        .ok_or_else(invalid)?;
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != ATTEMPT {
        return Err(invalid());
    }
    let input: MergeInput =
        serde_json::from_str(payload.input.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let result = MERGED.get(&vault.store, txn, &merge)?.ok_or_else(invalid)?;
    let mut children = input.children;
    children.extend(result.chunks);
    Ok(MergedSnapshot {
        children,
        retry_secs: input.retry_secs,
    })
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
