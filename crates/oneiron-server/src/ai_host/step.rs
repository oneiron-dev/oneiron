//! One saved-workflow step on a model seat.
//!
//! A step's prompt is data the vault already holds: the agent definition's
//! `instructions` as the system message, then the step's resolved context
//! (briefing, the memory and chat rows its context selected, as text, then
//! each earlier step's output) as user messages. A first step with no
//! briefing and no earlier output is asked its definition's own `desc`. No
//! text is invented here; the output's raw bytes become the step's durable
//! result.
//!
//! A step may hand a masked secret's handle to the use door's table through
//! a `self.use` tool (FIX 2315, `secret_use`); no handle is ever expanded.
//!
//! A step whose task names an objective is also asked for its confession
//! (OF-544, ARCH-0079): after a DONE line, one fenced block naming each
//! objective, whether it was met, and any flaw or doubt. A step that gives
//! none, or one that does not parse, records none.
use std::collections::{BTreeMap, HashMap};

use std::sync::{Arc, Mutex, OnceLock, Weak};

use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{AgentDispatchStatus, AgentDispatcher, agent_dispatch_run_actor};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ReadSetProducer};
use oneiron::compaction::output::restore_output;
use oneiron::context_projection::ResolvedContextProjection;
use oneiron::dreamer_consolidation::confession::{confession_ask, parse_confession};
use oneiron::self_heal::audit::ObjectiveConfession;
use oneiron::skill_optimize::union_source_rows;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, Error,
    LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
    WriteActor,
};

use super::CHAT_ROLE;
use super::live_lease::{self, LiveLease};
use super::payer_funding::{PayerFault, requires_payer, scope_funding};
use crate::models::ModelRuntime;
use crate::server::SyncServer;

mod secret_use;

use secret_use::StepSecretUse;

/// The purpose a workflow step's calls are metered and routed under.
const STEP_PURPOSE: &str = "workflow_step";

/// The step's key in its attempt's read set (FIX 6934, 7073).
const STEP_INPUT: ReadSetProducer = ReadSetProducer::WORKFLOW_STEP_INPUT;

/// The server a step's `self.use` calls the served secret-use door on (FIX
/// 7016): bound once serve has it, held weakly. Unbound, or once the server
/// is gone, a step uses the embedded door.
pub(super) type StepHost = Arc<OnceLock<Weak<SyncServer>>>;

pub(super) struct StepRunner {
    /// Steps run on the generative role, admitted against the vault's live
    /// model policy like chat turns.
    pub(super) models: Arc<ModelRuntime>,
    /// One logical step's budget, shared by all its tries; at least one
    /// call's reservation (config refuses less).
    pub(super) budget_units: u64,
    /// How long a failed step waits before its next try, times the tries.
    pub(super) retry_backoff_secs: u64,
    /// What each step's tries spent in all, by the failed try a retry
    /// follows: the next try replays exactly that. Held only while a retry
    /// may follow, and only in this process.
    pub(super) spent: Mutex<HashMap<AttemptId, u64>>,
    /// The server each step's `self.use` sends through, once bound.
    pub(super) host: StepHost,
    /// The host's wording of the confession ask (FIX 8696), after the
    /// step's objectives.
    pub(super) confession: Arc<str>,
}

/// One model-backed step, with instructions supplied by its stored definition.
pub(super) struct ModelStep<'a> {
    pub(super) definition: &'a AgentDefinition,
    pub(super) attempt: &'a AttemptRecord,
    pub(super) actor: WriteActor,
    pub(super) purpose: &'a str,
    pub(super) messages: Vec<LlmMessage>,
    /// A wave plan's planner, whose craft it is shown beside the step
    /// resident's own (FIX 5777); `None` for every other step.
    pub(super) planner: Option<EntityId>,
    /// The vault rows the caller built the step's prompt from; `None`
    /// when one cannot be named (FIX 11313).
    pub(super) sources: Option<Vec<EntityId>>,
    pub(super) response_format: ResponseFormat,
}

/// A step's raw output and, when it was asked for one and gave one that
/// parses, its confession (OF-544).
pub(super) struct StepOutput {
    pub(super) bytes: Vec<u8>,
    pub(super) confession: Option<Vec<ObjectiveConfession>>,
    /// The objectives it was asked to confess against (FIX 9466).
    pub(super) objectives: Vec<String>,
}

/// What a step's model call returned for its attempt's read set (FIX 6934):
/// its bytes, whether any `self.use` round ran and the planner craft rows it
/// showed, `None` when those are not known complete.
pub(super) struct GeneratedStep {
    pub(super) bytes: Vec<u8>,
    pub(super) tool_rounds: bool,
    pub(super) planner_craft_rows: Option<Vec<EntityId>>,
}

/// The objectives a step is asked to confess against: the caller's, verbatim,
/// when the dispatch carries them; else the one its task names, whitespace
/// folded and whole. The spawn's planned need comes first, then the step's
/// briefing, then the definition's `desc` when that is what the step was
/// asked. An objective is never cut or made up.
fn step_objectives(step: &AgentDispatchStatus, request: Option<&str>) -> Vec<String> {
    if let Some(objectives) = &step.input.objectives {
        return objectives.clone();
    }
    step.input
        .plan
        .as_ref()
        .map(|plan| plan.asked.need.as_str())
        .into_iter()
        .chain(request)
        .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
        .find(|text| !text.is_empty())
        .into_iter()
        .collect()
}

/// Why a step did not produce its output, and whether a later try of the
/// same call may succeed (a model call the provider answered with a
/// retryable error).
pub(super) struct StepFault {
    pub(super) retryable: bool,
    /// The step's meter ran out (`BudgetDenied::Exhausted`) before the call
    /// was answered: its run holds at the cap, paused with its checkpoint,
    /// and is neither failed nor retried (OF-541).
    pub(super) exhausted: bool,
    /// The step's payer waits on the owners' payer-needed ask (FIX 805):
    /// the step parks as it is, neither failed nor retried, until they
    /// answer.
    pub(super) payer: Option<PayerFault>,
    pub(super) error: Error,
}

impl From<Error> for StepFault {
    fn from(error: Error) -> Self {
        Self {
            retryable: false,
            exhausted: false,
            payer: None,
            error,
        }
    }
}

/// Hands a held run's owed notice to its owners, then records it delivered
/// (OF-541). A refusal leaves it owed, and the next pump delivers it: `true`
/// when it is still owed, which keeps the pump's timed recheck (FIX 9467).
pub(super) fn deliver_hold_notice(
    dispatcher: &AgentDispatcher<'_>,
    root: AttemptId,
    now: u64,
) -> bool {
    let delivered = dispatcher
        .deliver_budget_notice(root)
        .and_then(|owed| match owed {
            Some(_) => dispatcher.acknowledge_budget_notice(root, now).map(Some),
            None => Ok(None),
        });
    match delivered {
        Ok(Some(hold)) => {
            let notice = hold.notice.as_ref().map(|notice| notice.text.as_str());
            tracing::info!(?root, notice, "a held run's notice reached its owners");
            false
        }
        Ok(None) => false,
        Err(error) => {
            tracing::error!(kind = ?error.kind(), ?root, "a held run's notice was not delivered");
            true
        }
    }
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

/// Records the rows the step read under its key (FIX 6934, 7073). Capture
/// only (FIX 7021): a storage error recording them never ends the step. The
/// attempt's set goes unknown, as an unsourced inlet's, and later reads of
/// the step record nothing more.
fn record_step_read(
    vault: &Vault,
    attempt: AttemptId,
    rows: Option<Vec<EntityId>>,
    lost: &mut bool,
) {
    if *lost {
        return;
    }
    if let Err(error) = vault.record_attempt_sources(attempt, STEP_INPUT, rows) {
        *lost = true;
        tracing::warn!(
            attempt = ?attempt,
            %error,
            "the workflow step could not record its read set; its pack receipt keeps it unknown"
        );
        let _ = vault.record_attempt_sources(attempt, STEP_INPUT, None);
    }
}

impl StepRunner {
    /// Drops what a failed try spent once no retry follows it.
    pub(super) fn forget(&self, attempt: AttemptId) {
        self.spent
            .lock()
            .expect("step spend mutex poisoned")
            .remove(&attempt);
    }

    /// Runs on the pump thread, which owns `runtime`: blocking on the model
    /// call here never stalls a request worker.
    pub(super) fn run(
        &self,
        runtime: &tokio::runtime::Runtime,
        vault: &Vault,
        step: &AgentDispatchStatus,
        context: ResolvedContextProjection,
    ) -> Result<StepOutput, StepFault> {
        let definition = &step.input.definition;
        // The step and the claim load door that reads its requester craft are
        // the producers its attempt's read set waits on: declared before any
        // of its messages are read, the set reads complete only once both
        // reported, and stays unknown if either never does (FIX 6934, 7073).
        let mut read_set_lost = false;
        if let Err(error) = vault.declare_attempt_read_producers(
            step.attempt.id,
            &[STEP_INPUT, ReadSetProducer::ACTOR_CLAIM],
        ) {
            read_set_lost = true;
            tracing::warn!(
                attempt = ?step.attempt.id,
                %error,
                "the workflow step could not declare its read set; its pack receipt keeps it unknown"
            );
        }
        // FIX 6290: the memory and chat rows the step's context selected, as
        // text read on its run's own lanes. A row that no longer reads is
        // counted left out, never refused.
        let selected =
            AgentDispatcher::new(vault).render_workflow_step_context(&step.attempt, &context);
        let mut messages = Vec::new();
        if let Some(instructions) = definition
            .instructions
            .as_ref()
            .filter(|text| !text.trim().is_empty())
        {
            messages.push(message(LlmMessageRole::System, instructions.clone()));
        }
        // A member's bound run reads its context on their own lane: the
        // step is told how many rows that lane left out (FIX 5416).
        if let Some(notice) = context.narrowed_notice() {
            messages.push(message(LlmMessageRole::System, notice.body));
        }
        // What the selected rows lost here is told by count, beside it.
        if let Some(left_out) = selected.omission_notice() {
            messages.push(message(LlmMessageRole::System, left_out));
        }
        let briefing = context.briefing.filter(|text| !text.trim().is_empty());
        let mut earlier = Vec::with_capacity(context.workflow_output_refs.len());
        for output in &context.workflow_output_refs {
            let bytes = restore_output(vault, output.source)?;
            earlier.push(message(
                LlmMessageRole::User,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
        // The step's request is its briefing; with no briefing and no
        // earlier output, its definition's own `desc`. Its selected rows are
        // context, never a request, so they ask nothing in its place.
        let asked_desc = briefing.is_none() && earlier.is_empty();
        if let Some(briefing) = &briefing {
            messages.push(message(LlmMessageRole::User, briefing.clone()));
        } else if asked_desc {
            messages.push(message(LlmMessageRole::User, definition.desc.clone()));
        }
        if let Some(memory) = selected.memory_text() {
            messages.push(message(LlmMessageRole::User, memory));
        }
        if let Some(chat) = selected.chat_text() {
            messages.push(message(LlmMessageRole::User, chat));
        }
        let has_earlier = !earlier.is_empty();
        messages.extend(earlier);
        let request = briefing
            .as_deref()
            .or(asked_desc.then_some(definition.desc.as_str()));
        let objectives = step_objectives(step, request);
        if !objectives.is_empty() {
            messages.push(message(
                LlmMessageRole::User,
                confession_ask(&objectives, &self.confession),
            ));
        }
        // The step's inputs as the caller's part of one read set (FIX
        // 6934): its definition row and its rendered memory and chat rows,
        // or unknown when it carried earlier outputs, which are hashes, not
        // rows, or when a saved workflow's composition names no definition
        // row. The call carries it as its sources (FIX 11313); the record
        // below reuses it.
        let sources = if has_earlier {
            None
        } else {
            union_source_rows([
                step.input
                    .target
                    .agent_definition_ref()
                    .ok()
                    .map(|id| vec![id]),
                Some(selected.source_rows().to_vec()),
            ])
        };
        // A room-bound step, or a step of a member's bound run, must read
        // its payer (OF-531, FIX 5316).
        let payer_required = requires_payer(vault, step.attempt.id, step.input.room.is_some())?;
        let generated = self.generate_in(
            runtime,
            vault,
            ModelStep {
                definition,
                attempt: &step.attempt,
                actor: agent_dispatch_run_actor(&step.input, step.attempt.id)?,
                purpose: STEP_PURPOSE,
                messages,
                planner: None,
                sources: sources.clone(),
                response_format: ResponseFormat::Text,
            },
            payer_required,
            true,
        )?;
        // The step's inputs as one read set (FIX 6934): the caller's part
        // above with its planner craft, or unknown when it ran tool rounds,
        // which are not rows. A step that ends early before its call records
        // nothing.
        let rows = if generated.tool_rounds {
            None
        } else {
            union_source_rows([sources, generated.planner_craft_rows])
        };
        record_step_read(vault, step.attempt.id, rows, &mut read_set_lost);
        let bytes = generated.bytes;
        let confession = if objectives.is_empty() {
            None
        } else {
            parse_confession(&bytes, &objectives)
        };
        Ok(StepOutput {
            bytes,
            confession,
            objectives,
        })
    }

    pub(super) fn generate(
        &self,
        runtime: &tokio::runtime::Runtime,
        vault: &Vault,
        input: ModelStep<'_>,
    ) -> Result<GeneratedStep, StepFault> {
        self.generate_in(runtime, vault, input, false, false)
    }

    /// [`Self::generate`] for a step that knows whether it must read its
    /// payer (`payer_required`): a room-bound step's root scope must name
    /// its payer (OF-531), and so must a member's bound run's (FIX 5316).
    /// A workflow text step (`offers_use`) may also use a masked secret's
    /// handle through `self.use` (FIX 2315), on a route that takes tools.
    fn generate_in(
        &self,
        runtime: &tokio::runtime::Runtime,
        vault: &Vault,
        input: ModelStep<'_>,
        payer_required: bool,
        offers_use: bool,
    ) -> Result<GeneratedStep, StepFault> {
        let ModelStep {
            definition,
            attempt,
            actor,
            purpose,
            mut messages,
            planner,
            sources,
            response_format,
        } = input;
        // FIX 5777: a wave plan speaks with its planner's instructions for
        // its requester, so it is shown both crafts, each attributed: the
        // planner's first, after the instructions, then the requester's.
        // Each is read here, right before its call is built, so a note
        // erased or no longer supported since the plan was asked for is
        // never shown (FIX 8985). The rows the planner's shows are stamped
        // under the requester's receipt (FIX 5912); a stamp that fails
        // withholds nothing.
        let now = super::unix_now();
        // The planner craft rows the call shows (FIX 6934): kept beside the
        // joined text for the attempt's read set, `None` when not known
        // complete. A planner with no craft shows none.
        let mut planner_craft_rows: Option<Vec<EntityId>> = Some(Vec::new());
        if let Some(planner) = planner
            && let Some(craft) =
                super::resident_craft::planner_craft(vault, &planner, &actor.entity_ref(), now)
        {
            let message = craft.message;
            let entries = craft.entries;
            super::resident_craft::join_craft(&mut messages, message);
            if !entries.is_empty() {
                super::resident_craft::stamp_planner_craft_exposure(
                    vault,
                    attempt,
                    &actor.entity_ref(),
                    &entries,
                );
            }
            planner_craft_rows = entries
                .iter()
                .map(|entry| EntityId::from_hex(&entry.reference))
                .collect::<Result<Vec<_>, _>>()
                .ok();
        }
        // OF-490: the step speaks as its resident, so it is shown that
        // resident's craft after its instructions, each note loaded on its
        // own attempt. A replayed wave plan never calls here.
        // The requester craft rows the call shows (FIX 11313): kept beside
        // the joined text for the run's sources. A step with no craft shows
        // none.
        let mut requester_craft_rows: Option<Vec<EntityId>> = Some(Vec::new());
        if let Some((craft, rows)) =
            super::resident_craft::queue_craft(vault, attempt.id, &actor.entity_ref(), now)
        {
            super::resident_craft::join_craft(&mut messages, craft);
            requester_craft_rows = Some(rows);
        }
        // The requester craft door self-reports each CLAIM it loads (FIX
        // 7017); this empty report makes it report on every path, even when
        // no craft loaded. Reports union, so it never hides those. Capture
        // only: a storage error never ends the step.
        if let Err(error) =
            vault.record_attempt_sources(attempt.id, ReadSetProducer::ACTOR_CLAIM, Some(Vec::new()))
        {
            tracing::warn!(
                attempt = ?attempt.id,
                %error,
                "the workflow step could not record its craft read set; its pack receipt keeps it unknown"
            );
            let _ = vault.record_attempt_sources(attempt.id, ReadSetProducer::ACTOR_CLAIM, None);
        }
        let seat = self
            .models
            .seat(CHAT_ROLE)
            .ok_or_else(|| Error::InvalidConfig("no [models] rung serves workflow steps".into()))?;
        let call_purpose = CallPurpose::Other {
            name: purpose.to_owned(),
        };
        let request = LlmRequest {
            model: seat.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                // No world: the world a step was dispatched in does not vouch
                // for its text (Astra R3). Its definition, its briefing and
                // earlier steps' outputs may come from any world the
                // dispatcher read, so the vault-wide floor holds its fallback
                // on the device while any world stays on it.
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(
                    &call_purpose,
                    definition
                        .model_tier
                        .clone()
                        .unwrap_or_else(|| ModelTierRef(purpose.to_owned())),
                ),
                purpose: call_purpose,
                class: CallClass::BestEffort,
                response_format,
                locality: seat.locality,
                host_keyless: false,
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        // A route the vault narrowed past what this server serves ends the
        // step here, before any call leaves.
        let call = self
            .models
            .admit_role(vault, CHAT_ROLE, request)
            .map_err(|refusal| Error::InvalidConfig(format!("workflow step refused: {refusal}")))?;
        let mut request = call.request;
        // FIX 10592: beside the door-stamped locality, the request carries
        // whether its ladder may only serve free keyless own-server work, so
        // the replay below admits unmetered. Unstamped stays paid.
        request.envelope.host_keyless = call.ladder.all_keyless_own_server();
        let offers_use = offers_use && secret_use::offer(&call.ladder, &mut request);
        // The agent pays: its live budget policy rows, its own meter. Every
        // earlier try of this step failed its model call, and each rung it
        // sent was charged its reservation. Those charges are replayed into
        // this try's meter, so the step's budget and every policy row it
        // matches (the agent's cap, the purpose's) see them: retries share
        // one budget, never renew it. The try this one follows left what the
        // chain spent, or this same try did when it parked on its payer
        // (FIX 805). After a restart nothing is left, and each earlier try
        // is replayed at one reservation per rung of the ladder it has now:
        // an estimate, exact only when every earlier rung went out metered on
        // the same ladder and routes.
        let reserve = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
        let earlier = AttemptQueue::new(vault).retry_chain_depth(attempt.id)?;
        let carried = {
            let mut spent = self.spent.lock().expect("step spend mutex poisoned");
            spent
                .remove(&attempt.id)
                .or_else(|| attempt.retry_of.and_then(|parent| spent.remove(&parent)))
        };
        let run_id = format!(
            "workflow-step:{}",
            oneiron::EntityId::from_bytes(*attempt.id.as_bytes())?.to_hex()
        );
        let charged = match carried {
            Some(units) => units.div_ceil(reserve),
            None => u64::from(earlier).saturating_mul(call.ladder.rungs() as u64),
        };
        // The estimate counts metered reservations only: on a free ladder the
        // earlier tries spent nothing, so no replay is owed. A restart across
        // a paid-to-keyless route move replays 0 for tries that paid, the
        // same estimate class as above.
        let charged = if request.envelope.host_keyless {
            0
        } else {
            charged
        };
        // A step launched under a spend lease (OF-532) is bounded by it too:
        // beside its policy rows, this try may spend no more than the lease
        // has left, read live as each call is admitted (FIX 1819). Replayed
        // charges are already on the lease, so they sit on top of that
        // bound, not inside it.
        let dispatcher = AgentDispatcher::new(vault);
        let lease = dispatcher.spend_scope_for_attempt(attempt.id)?;
        // OF-531: a room-paid step bills its root payer's own account, bound
        // before anything is reserved, never the vault owner's by default;
        // so does a member's bound run's step (FIX 5316). A payer this host
        // cannot bill holds the step on the owners' payer-needed ask: it
        // parks as this try (FIX 805), and once they say yes it bills the
        // vault. Nothing went out, so taken up it replays only what the
        // earlier tries spent.
        let payer = match scope_funding(vault, lease.as_ref(), payer_required) {
            Ok(payer) => payer,
            Err(fault) => {
                let held = matches!(fault, PayerFault::Needed { .. });
                if held {
                    self.spent
                        .lock()
                        .expect("step spend mutex poisoned")
                        .insert(attempt.id, charged.saturating_mul(reserve));
                }
                let error = Error::InvalidConfig(format!("workflow step {fault}"));
                return Err(StepFault {
                    retryable: false,
                    exhausted: false,
                    payer: held.then_some(fault),
                    error,
                });
            }
        };
        let budget_units = match &lease {
            Some(scope) => self.budget_units.min(
                charged
                    .saturating_mul(reserve)
                    .saturating_add(dispatcher.available_units(scope)?),
            ),
            None => self.budget_units,
        };
        let guard = vault.policy_budget_guard(
            run_id.clone(),
            budget_units,
            reserve,
            BudgetExhaustionPolicy::Suspend,
            actor,
        )?;
        let budget = |denied: oneiron::llm::BudgetDenied| StepFault {
            retryable: false,
            exhausted: matches!(denied, oneiron::llm::BudgetDenied::Exhausted),
            payer: None,
            error: Error::InvalidConfig(format!("workflow step budget: {denied:?}")),
        };
        for _ in 0..charged {
            let spent = guard.admit_for_request(&request).map_err(budget)?.lease;
            guard.settle_reserved(&spent).map_err(budget)?;
        }
        let replayed = guard.read().used_units;
        // Each call of this try books its spend on the lease once it
        // settled, and the next is admitted against what the lease has left
        // then, its siblings' spend included (FIX 1819).
        let live = LiveLease::new(vault, lease, guard.clone(), self.budget_units, replayed);
        let uses =
            offers_use.then(|| StepSecretUse::new(vault, attempt, actor, &run_id, &self.host));
        // The step is a run on that meter: each rung its call reaches is
        // admitted on its own permit, sent through the run's gate and
        // settled. An answer pays its tokens, or the reservation when it
        // reports none; a rung that went out and failed pays its reservation.
        // A round `self.use` asks again is the same call on the same run.
        // The run's sources (FIX 11313): the caller's rows with the craft
        // rows this call shows beside them, or unknown when the caller
        // names none, or when the call may answer tools, whose answers are
        // not rows.
        let sources = if offers_use {
            None
        } else {
            union_source_rows([sources, planner_craft_rows.clone(), requester_craft_rows])
        };
        let run = self
            .models
            .funded_run(run_id, guard, payer)
            .sourced(sources.clone());
        // The admitted request is the step's replay capsule (FIX 3028),
        // finalized with the rung that answers it. A capture that fails
        // leaves none and never fails the step.
        oneiron::code_run::capture_workflow_step(
            vault,
            attempt.id,
            attempt.attempt_count,
            actor,
            &request,
            sources,
        );
        let may_send = || {
            live.book_and_revise();
            true
        };
        let generated = match &uses {
            Some(uses) => uses
                .converse(runtime, &call.ladder, &run, &live, request)
                .map(|(response, served, rounds)| ((response, served), rounds)),
            None => runtime
                .block_on(
                    call.ladder
                        .generate_served_while(&run, request, None, &may_send),
                )
                .map(|answered| (answered, false)),
        };
        oneiron::code_run::finalize_step_captures(vault);
        // What this try spent and no call's look booked goes on the lease
        // whatever the call answered; the replayed tries recorded their own.
        live.book_rest()?;
        let (response, tool_rounds) = match generated {
            // The rung that answered, fallback included, is the step's
            // executor: its leaf is attributed to it (OF-540). A refused
            // stamp leaves the leaf unattributed, not failed.
            Ok(((response, served), rounds)) => {
                if let Some(owner) = attempt.lease_owner.as_deref()
                    && let Err(error) = AttemptQueue::new(vault).set_executor_model(
                        attempt.id,
                        owner,
                        attempt.attempt_count,
                        served.as_str(),
                    )
                {
                    tracing::warn!(kind = ?error.kind(), "workflow step executor not stamped");
                }
                (response, rounds)
            }
            Err(oneiron::llm::LlmError::BudgetDenied(denied)) => return Err(budget(denied)),
            Err(error) => {
                let retryable = matches!(error, oneiron::llm::LlmError::Retryable(_));
                if retryable {
                    let chain = run.read().used_units;
                    self.spent
                        .lock()
                        .expect("step spend mutex poisoned")
                        .insert(attempt.id, chain);
                }
                return Err(StepFault {
                    retryable,
                    exhausted: false,
                    payer: None,
                    error: Error::InvalidConfig(format!(
                        "workflow step model call failed: {error}"
                    )),
                });
            }
        };
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        Ok(GeneratedStep {
            bytes: text.into_bytes(),
            tool_rounds,
            planner_craft_rows,
        })
    }
}
