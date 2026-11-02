//! The thing pass (FIX 7508): a thing branch's agent, launched, served and
//! collected inside its parent's wake while the parent's lease holds.
//!
//! Each port call is served here, on the parent's own async path: the same
//! extraction port, guard, durable-step context and charge tally today's
//! per-slice path uses, and the same correction pack. A served extract is
//! that slice's durable step, memoized; a served decide is the branch's
//! pack over the same candidates. So once the agent settles, today's path
//! runs and replays all of it from the memos: the engine assembles,
//! verifies and promotes exactly what it would have, and no question is
//! asked twice.
//!
//! Only the branch's clean slices are lent (FIX 9017): a low-trust slice
//! stays on today's path, which runs it after the agent settles beside the
//! lent slices it replays, and the pack is decided there. A host that
//! cannot lend what the agent needs, a branch with no clean slice, a policy
//! that turns the agent off for a new attempt, or any engine error before a
//! child is queued leaves the branch on today's path, with the typed reason
//! in the attempt's log. A child cut short by its clock, its lease or its
//! spend leaves its slices as continuation debt; a child that settled with
//! slices it never extracted leaves them to today's path.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::input::{self, CORRECTIONS_PACK, ThingPlan};
use super::proposals::{self, DraftFacts, Issued};
use super::{
    THING_CHILD_CHECKPOINT, THING_CHILD_CODE_MODE_OFF, THING_CHILD_HOST_ABSENT,
    THING_CHILD_LAUNCH_FAILED, THING_CHILD_LOAN_REFUSED, THING_CHILD_LOW_TRUST,
    THING_CHILD_PARENT_FAILED, THING_CHILD_REFUSED, THING_CHILD_TRAPPED, THING_CHILD_UNCOVERED,
    THING_DECIDE_PORT, THING_EXTRACT_PORT, THING_PORT_INPUT_UNKNOWN, THING_SLICE_REFUSED,
    ThingChildEvent, ThingChildLaunch, ThingChildSession, ThingChildSettled, ThingChildStart,
    ThingDecideOutput, ThingExtractOutput, ThingPortRequest,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::code_run::{ReaderJobState, SCOPED_CHILD_PARENT_LEASE_LOST, commit_host_inputs};
use crate::dreamer_consolidation::executor::extraction::{self, CitationCheck};
use crate::dreamer_consolidation::executor::{ConsolidationExecutor, PartitionRun};
use crate::dreamer_consolidation::extracted_people::{MintNamespace, bind_people};
use crate::dreamer_consolidation::failure_rules::{self, FailureRules, Stage};
use crate::dreamer_consolidation::resources::{BranchResources, ExtractionSlice};
use crate::dreamer_consolidation::roles::DREAMER_EXTRACTION_ROLE;
use crate::dreamer_consolidation::sieve_ports::{NeighbourhoodExtraction, SliceCall, SliceStep};
use crate::dreamer_consolidation::step_charge::StepChargeTally;
use crate::dreamer_wake::WakeAttemptContext;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::llm::{
    DreamerFailureDecision, DurableStepContext, DurableStepError, DurableStepResult, LlmResponse,
    StepOutcome,
};

/// What a thing branch's pass is handed by its partition attempt: the wake,
/// the branch's resources and every slice (each saying whether it is
/// low-trust), the slices' durable-step context, people namespace, failure
/// rules and citation check, and the attempt.
pub(in crate::dreamer_consolidation) struct ThingPass<'p, 'r> {
    pub(in crate::dreamer_consolidation) ctx: &'p WakeAttemptContext<'p>,
    pub(in crate::dreamer_consolidation) resources: &'p BranchResources<'r>,
    pub(in crate::dreamer_consolidation) slices: &'p [ExtractionSlice],
    pub(in crate::dreamer_consolidation) step: &'p DurableStepContext<'p>,
    pub(in crate::dreamer_consolidation) namespace: MintNamespace,
    pub(in crate::dreamer_consolidation) rules: Option<&'p FailureRules>,
    pub(in crate::dreamer_consolidation) citations: &'p Arc<CitationCheck>,
    pub(in crate::dreamer_consolidation) attempt_id: AttemptId,
}

/// How a thing branch's pass ended.
pub(in crate::dreamer_consolidation) enum ThingPassEnd {
    /// Today's per-slice path runs next: it replays every slice the agent
    /// extracted, and takes any it did not.
    Replay,
    /// The branch ends as this run.
    Run(PartitionRun),
}

/// A queued child and what its parent keeps of it: the branch slice each
/// lent slice is (by its place in the plan), and how many low-trust slices
/// were held back for today's path.
struct LaunchedChild {
    session: Box<dyn ThingChildSession>,
    plan: ThingPlan,
    lent: Vec<usize>,
    held: usize,
    parent_run: EntityId,
    generation: u32,
}

impl LaunchedChild {
    /// The branch slice lent as plan slice `slice`.
    fn slice<'s>(&self, pass: &ThingPass<'s, '_>, slice: usize) -> Option<&'s ExtractionSlice> {
        self.lent.get(slice).and_then(|at| pass.slices.get(*at))
    }
}

/// What the parent served of its child so far: each extracted slice, the
/// first refused reply's reason, whether the pack was decided, and every
/// draft staged.
#[derive(Default)]
struct SliceTable {
    extracted: BTreeMap<usize, ExtractedSlice>,
    refused: Option<String>,
    decided: bool,
    issued: Issued,
}

impl SliceTable {
    /// The input names of every slice extracted, in slice order.
    fn extracted_names(&self, plan: &ThingPlan) -> Vec<String> {
        self.extracted
            .keys()
            .map(|slice| plan.slice_name(*slice).to_owned())
            .collect()
    }
}

/// One slice's finished extraction step, and the answer its extract gave.
struct ExtractedSlice {
    response: LlmResponse,
    failure_policy: Option<DreamerFailureDecision>,
    answer: serde_json::Value,
}

/// What serving one port call came to.
enum PortServed {
    Answer(serde_json::Value),
    Refused(&'static str),
    /// The branch ends as this run; the child is stopped.
    End(PartitionRun),
}

impl ConsolidationExecutor<'_> {
    /// Runs `pass`'s thing branch through its scoped agent, or leaves it on
    /// today's path with the reason logged.
    pub(in crate::dreamer_consolidation) async fn thing_agent_pass(
        &self,
        pass: &ThingPass<'_, '_>,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<ThingPassEnd> {
        if pass.slices.is_empty() {
            return Ok(ThingPassEnd::Replay);
        }
        let mut launched = match self.launch_thing_child(pass) {
            Ok(Ok(launched)) => launched,
            Ok(Err(reason)) => return Ok(per_slice(pass, reason)),
            // An engine error before any child is queued is no refusal of
            // the branch: today's path runs it.
            Err(_) => return Ok(per_slice(pass, THING_CHILD_LAUNCH_FAILED)),
        };
        self.serve_thing_child(pass, &mut launched, charges).await
    }

    /// Frames and commits `pass`'s inputs and asks its host to launch the
    /// agent. The answer's `Err` is why the branch stays on today's path.
    fn launch_thing_child(
        &self,
        pass: &ThingPass<'_, '_>,
    ) -> Result<std::result::Result<LaunchedChild, &'static str>> {
        let ctx = pass.ctx;
        let Some(host) = self.roles.thing_child_host() else {
            return Ok(Err(THING_CHILD_HOST_ABSENT));
        };
        let Some(leased) = AttemptQueue::new(ctx.vault).get(pass.attempt_id)? else {
            return Ok(Err(THING_CHILD_LOAN_REFUSED));
        };
        let generation = leased.attempt_count;
        // The mode is the logical attempt's: one that ran as an agent before
        // keeps running as one, whatever the policy says now.
        let earlier = proposals::earlier_parent(ctx.vault, pass.attempt_id, generation)?;
        let policy = ctx.vault.dreamer_recipe_policy()?;
        if !policy.thing_child_code_mode && earlier.is_none() {
            return Ok(Err(THING_CHILD_CODE_MODE_OFF));
        }
        // Only the clean slices are lent; the loan never carries a tainted
        // one (FIX 9017).
        let lent: Vec<usize> = pass
            .slices
            .iter()
            .enumerate()
            .filter(|(_, slice)| !slice.low_trust)
            .map(|(at, _)| at)
            .collect();
        if lent.is_empty() {
            return Ok(Err(THING_CHILD_LOW_TRUST));
        }
        if let Some(reason) = host.unavailable() {
            return Ok(Err(reason));
        }
        let held = pass.slices.len() - lent.len();
        if held > 0 {
            tracing::info!(
                attempt = %bytes_to_hex_lower(pass.attempt_id.as_bytes()),
                reason = THING_CHILD_LOW_TRUST,
                lent = lent.len(),
                held,
                "a thing branch lends its clean slices; its low-trust ones take the per-slice path"
            );
        }
        let lent_slices: Vec<&ExtractionSlice> =
            lent.iter().filter_map(|at| pass.slices.get(*at)).collect();
        let checkpoint = proposals::newest_checkpoint(ctx.vault, pass.attempt_id, generation)?;
        // The host's real window when it lends one; else the vault's
        // overridable fallback (FIX 9020), never a refusal.
        let window = host
            .window_tokens()
            .unwrap_or(policy.thing_child_fallback_window_tokens);
        let grain = window / u64::from(policy.thing_child_input_window_divisor.max(1));
        let (inputs, plan) = input::frame_inputs(&lent_slices, grain, checkpoint);
        let parent_run = proposals::host_parent_run(pass.attempt_id, generation)?;
        let inputs = commit_host_inputs(ctx.vault, parent_run, self.actor.entity_ref(), inputs)?;
        let bound = pass.resources.request_scope();
        let scope = input::lent_scope(&bound, &lent_slices);
        let launch = ThingChildLaunch {
            ctx,
            leased: &leased,
            guard: self.guard,
            actor: self.actor,
            parent_run,
            inputs,
            bound,
            scope,
            ports: thing_ports(),
            intent_key: format!("thing-child-g{generation}"),
            ask: policy.thing_child_instruction,
        };
        Ok(match host.launch(launch)? {
            ThingChildStart::Launched(session) => Ok(LaunchedChild {
                session,
                plan,
                lent,
                held,
                parent_run,
                generation,
            }),
            ThingChildStart::Unavailable(reason) => Err(reason),
        })
    }

    /// Serves `launched`'s port calls until it settles, its parent's wake
    /// is spent, or a served step ends the branch.
    async fn serve_thing_child(
        &self,
        pass: &ThingPass<'_, '_>,
        launched: &mut LaunchedChild,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<ThingPassEnd> {
        let mut table = SliceTable::default();
        loop {
            if pass.ctx.deadline.expired() {
                return stop_thing_child(pass, launched, &table, PartitionRun::Checkpoint, charges);
            }
            let event = match launched.session.next().await {
                Ok(event) => event,
                Err(error) => {
                    launched.session.stop(THING_CHILD_PARENT_FAILED);
                    charges.record_units(launched.session.close_generation());
                    return Err(error.into());
                }
            };
            let call = match event {
                None => continue,
                Some(ThingChildEvent::Settled(settled)) => {
                    return thing_child_settled(pass, launched, &table, &settled, charges);
                }
                Some(ThingChildEvent::Port(call)) => call,
            };
            let served = match call.request().clone() {
                ThingPortRequest::Extract { input } => {
                    self.serve_extract(pass, launched, &mut table, &input, charges)
                        .await
                }
                ThingPortRequest::Decide { pack } => {
                    self.serve_decide(pass, launched, &mut table, &pack, charges)
                        .await
                }
            };
            match served {
                Ok(PortServed::Answer(value)) => call.answer(Ok(value)),
                Ok(PortServed::Refused(code)) => call.answer(Err(code)),
                Ok(PortServed::End(run)) => {
                    call.answer(Err(stop_code(&run)));
                    return stop_thing_child(pass, launched, &table, run, charges);
                }
                Err(error) => {
                    call.answer(Err(THING_CHILD_PARENT_FAILED));
                    launched.session.stop(THING_CHILD_PARENT_FAILED);
                    charges.record_units(launched.session.close_generation());
                    return Err(error);
                }
            }
        }
    }

    /// One extract: slice `input`'s durable extraction step, the very one
    /// today's path runs, and its draft staged.
    async fn serve_extract(
        &self,
        pass: &ThingPass<'_, '_>,
        launched: &LaunchedChild,
        table: &mut SliceTable,
        input: &str,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<PortServed> {
        let Some(index) = launched.plan.slice_of(input) else {
            return Ok(PortServed::Refused(THING_PORT_INPUT_UNKNOWN));
        };
        if let Some(done) = table.extracted.get(&index) {
            return Ok(PortServed::Answer(done.answer.clone()));
        }
        let Some(slice) = launched.slice(pass, index) else {
            return Ok(PortServed::Refused(THING_PORT_INPUT_UNKNOWN));
        };
        let steps = self
            .roles
            .extraction_ports()
            .neighbourhood_extraction()
            .extract(NeighbourhoodExtraction {
                step: pass.step,
                guard: self.guard,
                call: self.role(DREAMER_EXTRACTION_ROLE),
                slices: vec![SliceCall {
                    transcript: &slice.transcript,
                    labels: &slice.labels,
                    scope: &slice.scope,
                    sources: &slice.sources,
                }],
                namespace: pass.namespace.clone(),
                rules: pass.rules,
                citations: Arc::clone(pass.citations),
                width: 1,
            })
            .await?;
        let Some(SliceStep { step_hash, outcome }) = steps.into_iter().next() else {
            return Err(Error::InvariantViolation(
                "a child extraction port answered another number of slices",
            )
            .into());
        };
        let (response, failure_policy) = match outcome {
            Ok(StepOutcome::Finished {
                response,
                failure_policy,
                ..
            }) => (response, failure_policy),
            Ok(StepOutcome::Trapped { .. }) => return Ok(PortServed::End(PartitionRun::Trapped)),
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(PortServed::End(PartitionRun::Checkpoint));
            }
            Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
                charges.record_usage(&usage);
                table.refused.get_or_insert_with(|| {
                    format!("extraction reply refused: {}", errors.join("; "))
                });
                return Ok(PortServed::Refused(THING_SLICE_REFUSED));
            }
            Err(DurableStepError::FinalizeRefused | DurableStepError::DeadlineHardCut) => {
                return Ok(PortServed::End(PartitionRun::Checkpoint));
            }
            Err(error) => {
                table.refused.get_or_insert_with(|| error.to_string());
                return Ok(PortServed::Refused(THING_SLICE_REFUSED));
            }
        };
        charges.record_terminal(pass.ctx.vault, pass.attempt_id, step_hash, &response.usage)?;
        // Live rules, as today's path reads each reply.
        let rules = failure_rules::load(pass.ctx.vault)?;
        let (candidates, persons) = if accepted(rules.as_ref(), failure_policy, &response) {
            let reply = extraction::extraction_reply(&response)?;
            (reply.candidates.len(), reply.persons.len())
        } else {
            (0, 0)
        };
        let name = launched.plan.slice_name(index);
        let refs = proposals::stage_draft(
            pass.ctx.vault,
            launched.parent_run,
            launched.session.child_run(),
            &DraftFacts {
                slice: index,
                input: name,
                step_hash,
                candidates,
                persons,
                fallback: failure_policy.is_some(),
            },
            &mut table.issued,
        )?;
        let answer = encode(&ThingExtractOutput {
            input: name.to_owned(),
            state: "staged".to_owned(),
            proposals: refs,
            persons: count(persons),
            fallback: failure_policy.is_some(),
        })?;
        table.extracted.insert(
            index,
            ExtractedSlice {
                response,
                failure_policy,
                answer: answer.clone(),
            },
        );
        Ok(PortServed::Answer(answer))
    }

    /// One decide: the branch's correction pack over every slice's
    /// candidates, read as today's path reads them, once every slice is
    /// extracted. Its kept decisions are the durable step's own. While a
    /// low-trust slice is held back, the pack reads candidates the agent
    /// was not lent: it is deferred to today's path, which decides it once
    /// over every slice (FIX 9017).
    async fn serve_decide(
        &self,
        pass: &ThingPass<'_, '_>,
        launched: &LaunchedChild,
        table: &mut SliceTable,
        pack: &str,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<PortServed> {
        if pack != CORRECTIONS_PACK {
            return Ok(PortServed::Refused(THING_PORT_INPUT_UNKNOWN));
        }
        if launched.held > 0 {
            return Ok(PortServed::Answer(encode(&ThingDecideOutput {
                pack: pack.to_owned(),
                state: "deferred".to_owned(),
                questions: 0,
                missing: Vec::new(),
            })?));
        }
        let missing: Vec<String> = (0..launched.plan.slice_count())
            .filter(|slice| !table.extracted.contains_key(slice))
            .map(|slice| launched.plan.slice_name(slice).to_owned())
            .collect();
        if !missing.is_empty() {
            return Ok(PortServed::Answer(encode(&ThingDecideOutput {
                pack: pack.to_owned(),
                state: "pending".to_owned(),
                questions: 0,
                missing,
            })?));
        }
        if table.refused.is_some() {
            return Ok(PortServed::Refused(THING_SLICE_REFUSED));
        }
        let rules = failure_rules::load(pass.ctx.vault)?;
        let mut parsed = Vec::new();
        for index in 0..launched.plan.slice_count() {
            let (Some(slice), Some(done)) =
                (launched.slice(pass, index), table.extracted.get(&index))
            else {
                continue;
            };
            if !accepted(rules.as_ref(), done.failure_policy, &done.response) {
                continue;
            }
            let reply = extraction::extraction_reply(&done.response)?;
            let call = extraction::CallPins {
                labels: &slice.labels,
                pins: pass.resources.pins(),
            };
            let people = bind_people(&reply.persons, &call, &pass.namespace);
            let (taken, _) = Self::parse_candidates(
                &done.response,
                pass.resources,
                &slice.scope,
                extraction::ReplyContext {
                    call,
                    people: &people,
                },
                &slice.sources,
            )?;
            parsed.extend(taken);
        }
        let decided = self
            .decide_corrections(
                pass.step,
                pass.ctx.deadline,
                &parsed,
                pass.resources,
                charges,
            )
            .await;
        Ok(match decided {
            Ok(Some(corrects)) => {
                table.decided = true;
                PortServed::Answer(encode(&ThingDecideOutput {
                    pack: pack.to_owned(),
                    state: "decided".to_owned(),
                    questions: count(corrects.len()),
                    missing: Vec::new(),
                })?)
            }
            Ok(None) => PortServed::End(PartitionRun::Trapped),
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                PortServed::End(PartitionRun::Checkpoint)
            }
            Err(DurableStepError::FinalizeRefused | DurableStepError::DeadlineHardCut) => {
                PortServed::End(PartitionRun::Checkpoint)
            }
            Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
                charges.record_usage(&usage);
                PortServed::End(PartitionRun::Refused {
                    reason: format!("correction read refused: {}", errors.join("; ")),
                })
            }
            Err(error) => PortServed::End(PartitionRun::Refused {
                reason: error.to_string(),
            }),
        })
    }
}

/// Stops `launched` because the branch ends as `run`: its generation's
/// units are charged once and what it extracted is checkpointed for a later
/// wake's transport run.
fn stop_thing_child(
    pass: &ThingPass<'_, '_>,
    launched: &mut LaunchedChild,
    table: &SliceTable,
    run: PartitionRun,
    charges: &mut StepChargeTally,
) -> DurableStepResult<ThingPassEnd> {
    launched.session.stop(stop_code(&run));
    charges.record_units(launched.session.close_generation());
    proposals::stage_checkpoint(
        pass.ctx.vault,
        launched.parent_run,
        launched.generation,
        launched.session.child_run(),
        &table.extracted_names(&launched.plan),
        table.decided,
    )?;
    Ok(ThingPassEnd::Run(run))
}

/// What a settled child leaves: today's path, which replays what it
/// extracted (and takes any slice it left), or continuation debt when its
/// clock, its lease or its spend cut it short.
fn thing_child_settled(
    pass: &ThingPass<'_, '_>,
    launched: &LaunchedChild,
    table: &SliceTable,
    settled: &ThingChildSettled,
    charges: &mut StepChargeTally,
) -> DurableStepResult<ThingPassEnd> {
    charges.record_units(launched.session.close_generation());
    let child_run = launched.session.child_run();
    let (resolved, unresolved) =
        proposals::check_report(settled.report.as_deref(), child_run, &table.issued);
    let slices = launched.plan.slice_count();
    let extracted = table.extracted.len();
    let attempt = bytes_to_hex_lower(pass.attempt_id.as_bytes());
    tracing::info!(
        attempt = %attempt,
        state = settled.state.word(),
        slices,
        extracted,
        resolved,
        unresolved,
        "a thing branch's agent settled"
    );
    if let Some(reason) = &table.refused {
        return Ok(ThingPassEnd::Run(PartitionRun::Refused {
            reason: reason.clone(),
        }));
    }
    if extracted == slices {
        return Ok(ThingPassEnd::Replay);
    }
    if pass.ctx.deadline.expired() || cut_short(&settled.state) {
        proposals::stage_checkpoint(
            pass.ctx.vault,
            launched.parent_run,
            launched.generation,
            child_run,
            &table.extracted_names(&launched.plan),
            table.decided,
        )?;
        return Ok(ThingPassEnd::Run(PartitionRun::Checkpoint));
    }
    tracing::info!(
        attempt = %attempt,
        reason = THING_CHILD_UNCOVERED,
        uncovered = slices.saturating_sub(extracted),
        "a thing branch's agent left slices; the per-slice path takes them"
    );
    Ok(ThingPassEnd::Replay)
}

/// Whether a child's settlement is its clock's, its lease's or its spend's
/// (or its parent's stop), so its slices wait for a later wake; a child
/// still queued or active when its wait came due is too.
fn cut_short(state: &ReaderJobState) -> bool {
    match state {
        ReaderJobState::Queued | ReaderJobState::Active => true,
        ReaderJobState::Done => false,
        ReaderJobState::Partial { reason } | ReaderJobState::Failed { reason } => {
            matches!(
                reason.as_str(),
                "cutoff" | "spend" | SCOPED_CHILD_PARENT_LEASE_LOST
            ) || reason.starts_with("thing_child_")
        }
    }
}

/// The code a child is stopped with when its branch ends as `run`.
const fn stop_code(run: &PartitionRun) -> &'static str {
    match run {
        PartitionRun::Trapped => THING_CHILD_TRAPPED,
        PartitionRun::Checkpoint => THING_CHILD_CHECKPOINT,
        PartitionRun::Refused { .. } => THING_CHILD_REFUSED,
        PartitionRun::Completed { .. } | PartitionRun::Held { .. } => THING_CHILD_PARENT_FAILED,
    }
}

/// Logs why `pass`'s branch runs today's per-slice path.
fn per_slice(pass: &ThingPass<'_, '_>, reason: &'static str) -> ThingPassEnd {
    tracing::info!(
        attempt = %bytes_to_hex_lower(pass.attempt_id.as_bytes()),
        reason,
        "a thing branch runs its slices on the per-slice path"
    );
    ThingPassEnd::Replay
}

/// Whether a finished reply is taken, as today's path takes it: its
/// fallback's policy under the live rules.
fn accepted(
    rules: Option<&FailureRules>,
    policy: Option<DreamerFailureDecision>,
    response: &LlmResponse,
) -> bool {
    policy.is_none_or(|decision| {
        decision
            .consolidation_with_stage(rules.map(|rules| rules.accepts(Stage::Extraction, response)))
    })
}

/// The two ports a thing's agent is lent, which its parent itself calls.
fn thing_ports() -> BTreeSet<String> {
    [THING_EXTRACT_PORT, THING_DECIDE_PORT]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// A port answer's JSON.
fn encode(value: &impl serde::Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|_| Error::InvalidConfig("a thing port answer did not encode".to_owned()))
}

/// A count as a port answer states it.
fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
