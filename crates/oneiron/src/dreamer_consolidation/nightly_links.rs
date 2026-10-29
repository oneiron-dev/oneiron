//! Semantic links across one night's children, PROPOSALS ONLY (OF-498d).
//!
//! The nightly merge lands its exact-key, conflict and narrative outputs as
//! before. In that same commit it queues one link continuation for each of
//! its proposals that leads a cross-child pair ([`pairs`]): the first is a
//! run-tree root of its own and the rest go under it, so the night's wake
//! settles without them and nothing the merge or its children wrote waits on
//! them. Each continuation reads the merge's own snapshot again (its listed
//! children and the retry chunks it fanned in), judges every pair its
//! proposal leads through the host's ladder with the shared typed read, and
//! lands like the merge: a same-as verdict writes a proposed SameAs status
//! claim between the two proposals with the merge's approval (Auto), and
//! every verdict, no-link and unresolved too, is kept in its result. No
//! graph edge is applied, no exposure widens and no approval hold is added.

mod pairs;

use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::call_labels::CallLabelMap;
use super::executor::{ConsolidationExecutor, ScopedRead};
use super::nightly_merge::{
    Draft, MergeResult, NightlyWrite, Proposal, exposure_groups, landed_units_in_txn, merge_read,
    merged_snapshot_in_txn, proposals_in_txn, recheck_in_txn, scoped_draft,
};
use super::roles::DREAMER_VERDICT_ROLE;
use super::step_charge::StepChargeTally;
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimSubject;
use crate::dreamer_consolidation::KeptDecision;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerAttemptStatus, DreamerConsolidationScope,
    DreamerParkCause, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::llm::decision::{AskTo, DecisionRung, EvidenceVersion, HumanAskReason};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, DurableStepContext, DurableStepError, LlmRequest,
    ModelTierRef, ResponseFormat, Scope, TierPrecedence,
};
use crate::{ClaimCandidate, EntityId, Error, Result, Vault};

use pairs::{Anchored, NightlyLinkQuestion, NightlyLinkVerdict, anchored, link_calls};
pub(super) use pairs::{NightlyLinkProposal, anchors};

/// The link continuation's attempt type.
pub(super) const ATTEMPT: &str = "dreamer.nightly.links";
/// The domain a continuation's proposal claims derive their ids under.
const LINK_IDS: &[u8] = b"oneiron:nightly:links:v1";
/// Why a continuation parks on a reply its read refused.
const LINKS_REFUSED: &str = "nightly link reading schema refused";
/// Why a continuation parks on a pack that came back short.
const LINKS_UNREAD: &str = "nightly link reading unread";

/// One continuation's work: the merge whose snapshot it pairs, and the
/// proposal whose pairs it judges.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinksInput {
    merge: AttemptId,
    anchor: EntityId,
}

/// Queues `merge`'s link continuations in its own commit: one for each
/// proposal of `anchors`. The first is a run-tree root of its own and the
/// rest go under it, so the night's wake never waits on them. Nothing queues
/// when no proposal leads a pair.
pub(super) fn enqueue_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    merge: &DreamerAttemptStatus,
    anchors: &[EntityId],
    now: u64,
) -> Result<()> {
    let store = DreamerRunnerStore::new(vault);
    let mut root = None;
    for anchor in anchors {
        let input = serde_json::to_string(&LinksInput {
            merge: merge.attempt.id,
            anchor: *anchor,
        })
        .map_err(|_| invalid())?;
        let dedupe = format!(
            "{ATTEMPT}:{}:{}",
            crate::entity_id::bytes_to_hex_lower(merge.attempt.id.as_bytes()),
            anchor.to_hex()
        );
        let outcome = store.enqueue_kind_in_txn(
            txn,
            DreamerConsolidationScope::Macro.attempt_kind(),
            DreamerAttemptPayload {
                attempt_type: ATTEMPT.into(),
                input: input.into(),
                parent_attempt: root,
            },
            Some(dedupe),
            merge.attempt.run_id.clone(),
            now,
        )?;
        if root.is_none() {
            root = Some(match outcome {
                EnqueueDreamerAttemptOutcome::Enqueued(status)
                | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
            });
        }
    }
    Ok(())
}

impl ConsolidationExecutor<'_> {
    /// One link continuation: its proposal's pairs, each judged in calls
    /// whose state stays within the ladder's bound, then landed in one
    /// commit with every verdict. A proposal that no longer stands, or leads
    /// no pair now, lands with none. A trap, a refused reading or a moved
    /// proposal parks this continuation alone, to resume.
    pub(super) async fn run_nightly_links(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if self.scope.is_some() {
            return Err(invalid());
        }
        let input: LinksInput =
            serde_json::from_str(attempt.status.payload.input.as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        let attempt_id = attempt.status.attempt.id;
        let read = merge_read(ctx.vault, self.actor)?;
        let proposals = {
            let txn = ctx.vault.store.env.read_txn()?;
            if let Some(completed_units) = landed_units_in_txn(ctx.vault, &txn, attempt_id)? {
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units,
                    step_hashes: Vec::new(),
                });
            }
            let merged = merged_snapshot_in_txn(ctx.vault, &txn, input.merge)?;
            match proposals_in_txn(ctx.vault, &txn, &read, &merged.children)? {
                Some(proposals) => proposals,
                None => {
                    return Ok(DreamerAttemptExecution::Deferred {
                        completed_units: 0,
                        retry_at: (ctx.now_ms / 1_000).saturating_add(merged.retry_secs),
                        step_hashes: Vec::new(),
                    });
                }
            }
        };
        let groups = exposure_groups(&proposals)?;
        let mut charges = StepChargeTally::default();
        let mut links = Vec::new();
        let mut drafts: Vec<Draft> = Vec::new();
        let mut read_back = Vec::new();
        if let Some(Anchored { anchor, partners }) = anchored(&groups, input.anchor)? {
            let step = DurableStepContext {
                vault: ctx.vault,
                attempt_id,
                run_id: attempt.status.attempt.run_id.clone(),
                envelope_actor: self.actor,
                subject: anchor.body.scope_project,
                deadline: Some(ctx.deadline),
                now_ms: ctx.now_ms,
            };
            let mut decided = Vec::with_capacity(partners.len());
            for call in link_calls(anchor, &partners) {
                match self
                    .judge_links(ctx, &step, anchor, &call, &mut charges)
                    .await?
                {
                    ControlFlow::Continue(decisions) => {
                        decided.extend(call.into_iter().zip(decisions));
                    }
                    ControlFlow::Break(stop) => return Ok(stop),
                }
            }
            for (partner, decision) in decided {
                let verdict = NightlyLinkVerdict::of(&decision);
                if verdict == NightlyLinkVerdict::SameAs {
                    drafts.push(same_as_draft(anchor, partner));
                }
                links.push(NightlyLinkProposal {
                    source: anchor.id,
                    target: partner.id,
                    source_children: anchor.children.clone(),
                    target_children: partner.children.clone(),
                    verdict,
                    claim: None,
                    decision,
                });
            }
            // The verdicts read these bodies: each is read again at the commit.
            if !partners.is_empty() {
                read_back.push(anchor);
                read_back.extend(partners);
            }
        }
        let writer = NightlyWrite {
            vault: ctx.vault,
            actor: self.actor,
            attempt: &attempt.status,
            ids: LINK_IDS,
            now: ctx.now_ms / 1_000,
        };
        let commit = ctx.vault.with_write_txn_grouped(|txn| {
            recheck_in_txn(&read, txn, &read_back)?;
            let outputs = writer.claims_in_txn(txn, drafts)?;
            // Each same-as names the proposal claim it wrote, in order.
            let mut written = outputs.iter().copied();
            for link in links
                .iter_mut()
                .filter(|link| link.verdict == NightlyLinkVerdict::SameAs)
            {
                link.claim = written.next();
            }
            writer.result_in_txn(
                txn,
                &MergeResult {
                    outputs,
                    completed_units: charges.units,
                    step_hashes: charges.step_hashes.clone(),
                    chunks: Vec::new(),
                    links,
                },
            )
        });
        match commit {
            Ok(()) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
                step_hashes: charges.step_hashes.clone(),
            }),
            // A proposal that moved before the commit lands again on resume;
            // a gate only an owner act opens keeps the private park.
            Err(error) => Ok(charges.park_on_error(&error)),
        }
    }

    /// One call of `anchor`'s pairs with `partners` through the host's
    /// ladder, the verdict role's generation its first read, under the
    /// group's exposure with each claim's body pinned as it was read. Its
    /// asks name the owners, and its ceiling is the verdict's: no pair goes
    /// up to a role. Each generation that finished joins `charges`.
    /// Continues with each pair's kept decision in order; breaks with what
    /// the attempt does instead.
    async fn judge_links(
        &self,
        ctx: &WakeAttemptContext<'_>,
        step: &DurableStepContext<'_>,
        anchor: &Proposal,
        partners: &[&Proposal],
        charges: &mut StepChargeTally,
    ) -> Result<ControlFlow<DreamerAttemptExecution, Vec<KeptDecision>>> {
        let call = self.role(DREAMER_VERDICT_ROLE);
        // A missing locality waits on no owner act: the continuation resumes
        // after its retry delay (OF-193a).
        let Some(locality) = call.inference.selected_locality() else {
            return Ok(ControlFlow::Break(
                charges.park_for("nightly links need locality", DreamerParkCause::Retry),
            ));
        };
        // The call labels its claims and questions before its state renders
        // (FIX 7506).
        let mut labels = CallLabelMap::default();
        let pack = NightlyLinkQuestion::pack(&self.decisions.nightly_link_wording, partners.len())?;
        self.label_questions(&mut labels, pack.questions());
        let state = pack.state(anchor, partners, &mut labels);
        let mut scope = Scope {
            world: anchor.body.world,
            relationship: anchor.body.rel,
            project: Some(anchor.body.scope_project),
            ..Scope::default()
        };
        let mut versions = Vec::with_capacity(partners.len() + 1);
        let mut evidence = Vec::with_capacity(partners.len() + 1);
        for proposal in std::iter::once(anchor).chain(partners.iter().copied()) {
            let body = &proposal.raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
            scope
                .readable
                .insert(super::resources::document_version(proposal.id, body));
            versions.push(EvidenceVersion {
                id: proposal.id,
                body_hash: super::swarm_evidence_content_hash(body),
            });
            evidence.push(proposal.id);
        }
        let shell = LlmRequest {
            model: call.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope,
                purpose: CallPurpose::Consolidation,
                class: CallClass::Durable {
                    fallback: crate::llm::DeterministicFallback {
                        name: "json_rules_v1".into(),
                        config: None,
                    },
                },
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Consolidation,
                    ModelTierRef("consolidation".into()),
                ),
                response_format: ResponseFormat::Text,
                locality,
            }
            .with_purpose_defaults(),
            messages: Vec::new(),
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        let vault = step.vault;
        let refused = AtomicBool::new(false);
        let seal = |request: LlmRequest| -> Result<LlmRequest> {
            let sealed = vault
                .authorize_model_role(DREAMER_VERDICT_ROLE, request, &call.inference)
                .and_then(|request| {
                    let mut request = request.into_request();
                    super::roles::bind_reasoning(vault, call.backend, &mut request)?;
                    Ok(request)
                });
            if sealed.is_err() {
                refused.store(true, Ordering::Relaxed);
            }
            sealed
        };
        // The continuation's asks name its attempt.
        let correlation = EntityId::from_bytes(*step.attempt_id.as_bytes())?;
        let to = AskTo::owner();
        // The call's input renders from stored rows alone (FIX 11420): the
        // anchor's and each partner's claim body as the merge's snapshot
        // read it, and the subjects their labels name. The wording and the
        // ladder's own questions are the host's text, the choices fixed, and
        // no same-as draft exists before this call.
        let sources: Vec<EntityId> = evidence.iter().copied().chain(labels.rows()).collect();
        let mut spent = Vec::new();
        let decided = self
            .decider()
            .decide_scoped(
                ScopedRead {
                    step,
                    pass: ctx.deadline,
                    call: &call,
                    shell,
                    seal: &seal,
                    versions: &versions,
                    to: &to,
                    correlation,
                    evidence: &evidence,
                    state: &state,
                    ceiling: DecisionRung::Big,
                    sources: Some(sources),
                },
                pack.questions(),
                &labels,
                &mut spent,
            )
            .await;
        // Every generation that finished is spent, whatever the call's
        // outcome.
        for (hash, usage) in &spent {
            charges.record_terminal(vault, step.attempt_id, *hash, usage)?;
        }
        let decisions = match decided {
            Ok(Some(decisions)) => decisions,
            Ok(None) => {
                return Ok(ControlFlow::Break(charges.park_for(
                    "durable step trapped for resume",
                    DreamerParkCause::Signal,
                )));
            }
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(ControlFlow::Break(charges.checkpoint()));
            }
            // A refused reading asks again after its retry delay.
            Err(DurableStepError::SpentSchemaValidation { usage, .. }) => {
                charges.record_usage(&usage);
                return Ok(ControlFlow::Break(
                    charges.park_for(LINKS_REFUSED, DreamerParkCause::Retry),
                ));
            }
            Err(DurableStepError::Engine(error)) if refused.load(Ordering::Relaxed) => {
                return Ok(ControlFlow::Break(charges.park_on_error(&error)));
            }
            Err(error) => {
                return Ok(ControlFlow::Break(
                    charges.park_for(&error.to_string(), DreamerParkCause::of_step(&error)),
                ));
            }
        };
        // A question the decision clock cut keeps its memo: the attempt
        // checkpoints and its resume reads the reply again.
        if ctx.deadline.expired()
            || decisions
                .iter()
                .any(|kept| kept.decision.human_ask == Some(HumanAskReason::Deadline))
        {
            return Ok(ControlFlow::Break(charges.checkpoint()));
        }
        if decisions.len() != partners.len() {
            return Ok(ControlFlow::Break(
                charges.park_for(LINKS_UNREAD, DreamerParkCause::Retry),
            ));
        }
        Ok(ControlFlow::Continue(decisions))
    }
}

/// The proposal claim a same-as verdict writes: the coreference status
/// PROPOSED of a SameAs edge from `anchor` to `partner`, under their group's
/// exposure, its refs the pair. The edge itself is never applied here.
fn same_as_draft(anchor: &Proposal, partner: &Proposal) -> Draft {
    let candidate = ClaimCandidate::new(
        crate::claim::PREDICATE_COREFERENCE_STATUS,
        ClaimSubject::Edge {
            source: anchor.id,
            kind: crate::edge::EdgeKind::SameAs,
            target: partner.id,
        },
        Value::from(crate::claim::COREFERENCE_STATUS_PROPOSED),
        1.0,
    );
    scoped_draft(candidate, &anchor.body, &[anchor, partner])
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid nightly link input".into())
}
