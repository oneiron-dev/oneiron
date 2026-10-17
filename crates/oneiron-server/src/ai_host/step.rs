//! One saved-workflow step on a model seat.
//!
//! A step's prompt is data the vault already holds: the agent definition's
//! `instructions` as the system message, then the step's resolved context
//! (briefing, then each earlier step's output) as user messages. A first step
//! with no context is asked its definition's own `desc`. No text is invented
//! here; the output's raw bytes become the step's durable result.
//!
//! A step whose task fits one objective is also asked for its confession
//! (OF-544, ARCH-0079): after a DONE line, one fenced block naming that
//! objective, whether it was met, and any flaw or doubt. A step that gives
//! none, or one that does not parse, records none.
use std::collections::{BTreeMap, HashMap};

use std::sync::{Arc, Mutex};

use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{AgentDispatchStatus, AgentDispatcher, agent_dispatch_actor};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use oneiron::compaction::output::restore_output;
use oneiron::context_projection::ResolvedContextProjection;
use oneiron::self_heal::audit::ObjectiveConfession;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, Error, LlmMessage,
    LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault, WriteActor,
};

use super::CHAT_ROLE;
use super::payer_funding::{PayerFault, scope_funding};
use crate::models::ModelRuntime;

/// The purpose a workflow step's calls are metered and routed under.
const STEP_PURPOSE: &str = "workflow_step";
/// The longest objective a confession names, in bytes: the seal's bound.
const OBJECTIVE_MAX_BYTES: usize = 256;
/// The fence that opens a step's confession block, after its DONE line.
const CONFESSION_FENCE: &str = "```oneiron-confession";

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
}

/// One model-backed step, with instructions supplied by its stored definition.
pub(super) struct ModelStep<'a> {
    pub(super) definition: &'a AgentDefinition,
    pub(super) attempt: &'a AttemptRecord,
    pub(super) actor: WriteActor,
    pub(super) purpose: &'a str,
    pub(super) messages: Vec<LlmMessage>,
    pub(super) response_format: ResponseFormat,
}

/// A step's raw output and, when it was asked for one and gave one that
/// parses, its confession (OF-544).
pub(super) struct StepOutput {
    pub(super) bytes: Vec<u8>,
    pub(super) confession: Option<Vec<ObjectiveConfession>>,
}

/// The objectives a step is asked to confess against: the one its task names,
/// whitespace folded, when it fits a seal objective. The spawn's planned need
/// comes first, then the step's briefing, then the definition's `desc` when
/// that is what the step was asked. A task too long for one objective asks
/// no confession: an objective is never cut or made up.
fn step_objectives(step: &AgentDispatchStatus, request: Option<&str>) -> Vec<String> {
    step.input
        .plan
        .as_ref()
        .map(|plan| plan.asked.need.as_str())
        .into_iter()
        .chain(request)
        .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
        .find(|text| !text.is_empty())
        .filter(|text| text.len() <= OBJECTIVE_MAX_BYTES)
        .into_iter()
        .collect()
}

/// The ask for a confession against `objectives`, after the step's task.
fn confession_ask(objectives: &[String]) -> String {
    let listed = serde_json::to_string(objectives).unwrap_or_default();
    format!(
        "Objectives assigned to this attempt: {listed}\n\
         When your result is complete, end it with a line that is exactly DONE, then one \
         block fenced ```oneiron-confession holding \
         {{\"objectives\":[{{\"objective\":\"<the assigned objective, copied exactly>\",\
         \"met\":<true or false>,\"flaw\":<null or what is wrong>,\
         \"uncertainty\":<null or what you are unsure of>}}]}} with one row per assigned \
         objective, in order. Say plainly what you did not meet, any flaw and any doubt: a \
         confession never costs the score. Nothing follows the closing fence."
    )
}

/// The confession `output` ends with, when it is a DONE line, then one
/// ```oneiron-confession block whose rows name exactly `objectives`, in
/// order. Anything else is no confession.
fn parse_confession(output: &[u8], objectives: &[String]) -> Option<Vec<ObjectiveConfession>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Block {
        objectives: Vec<ObjectiveConfession>,
    }
    let text = std::str::from_utf8(output).ok()?.trim_end();
    let (head, block) = text.strip_suffix("```")?.rsplit_once(CONFESSION_FENCE)?;
    let head = head.trim_end();
    if head != "DONE" && !head.ends_with("\nDONE") {
        return None;
    }
    let rows = serde_json::from_str::<Block>(block.trim()).ok()?.objectives;
    let named = rows.iter().map(|row| &row.objective);
    (rows.len() == objectives.len() && named.eq(objectives)).then_some(rows)
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
    pub(super) error: Error,
}

impl From<Error> for StepFault {
    fn from(error: Error) -> Self {
        Self {
            retryable: false,
            exhausted: false,
            error,
        }
    }
}

/// Hands a held run's owed notice to its owners, then records it delivered
/// (OF-541). A refusal leaves it owed, and the next pump delivers it.
pub(super) fn deliver_hold_notice(dispatcher: &AgentDispatcher<'_>, root: AttemptId, now: u64) {
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
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(kind = ?error.kind(), ?root, "a held run's notice was not delivered");
        }
    }
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
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
        let mut messages = Vec::new();
        if let Some(instructions) = definition
            .instructions
            .as_ref()
            .filter(|text| !text.trim().is_empty())
        {
            messages.push(message(LlmMessageRole::System, instructions.clone()));
        }
        let briefing = context.briefing.filter(|text| !text.trim().is_empty());
        if let Some(briefing) = &briefing {
            messages.push(message(LlmMessageRole::User, briefing.clone()));
        }
        for earlier in &context.workflow_output_refs {
            let bytes = restore_output(vault, earlier.source)?;
            messages.push(message(
                LlmMessageRole::User,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
        let asked_desc = !messages.iter().any(|m| m.role == LlmMessageRole::User);
        if asked_desc {
            messages.push(message(LlmMessageRole::User, definition.desc.clone()));
        }
        let request = briefing
            .as_deref()
            .or(asked_desc.then_some(definition.desc.as_str()));
        let objectives = step_objectives(step, request);
        if !objectives.is_empty() {
            messages.push(message(LlmMessageRole::User, confession_ask(&objectives)));
        }
        let bytes = self.generate_in(
            runtime,
            vault,
            ModelStep {
                definition,
                attempt: &step.attempt,
                actor: agent_dispatch_actor(&step.input)?,
                purpose: STEP_PURPOSE,
                messages,
                response_format: ResponseFormat::Text,
            },
            step.input.room.is_some(),
        )?;
        let confession = if objectives.is_empty() {
            None
        } else {
            parse_confession(&bytes, &objectives)
        };
        Ok(StepOutput { bytes, confession })
    }

    pub(super) fn generate(
        &self,
        runtime: &tokio::runtime::Runtime,
        vault: &Vault,
        input: ModelStep<'_>,
    ) -> Result<Vec<u8>, StepFault> {
        self.generate_in(runtime, vault, input, false)
    }

    /// [`Self::generate`] for a step that knows whether it works in a room
    /// (`room`): a room-bound step's root scope must name its payer (OF-531).
    fn generate_in(
        &self,
        runtime: &tokio::runtime::Runtime,
        vault: &Vault,
        input: ModelStep<'_>,
        room: bool,
    ) -> Result<Vec<u8>, StepFault> {
        let ModelStep {
            definition,
            attempt,
            actor,
            purpose,
            messages,
            response_format,
        } = input;
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
            },
            messages,
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        // A route the vault narrowed past what this server serves ends the
        // step here, before any call leaves.
        let call = self
            .models
            .admit_role(vault, CHAT_ROLE, request)
            .map_err(|refusal| Error::InvalidConfig(format!("workflow step refused: {refusal}")))?;
        let request = call.request;
        // The agent pays: its live budget policy rows, its own meter. Every
        // earlier try of this step failed its model call, and each rung it
        // sent was charged its reservation. Those charges are replayed into
        // this try's meter, so the step's budget and every policy row it
        // matches (the agent's cap, the purpose's) see them: retries share
        // one budget, never renew it. The try this one follows left what the
        // chain spent. After a restart nothing is left, and each earlier try
        // is replayed at one reservation per rung of the ladder it has now:
        // an estimate, exact only when every earlier rung went out metered on
        // the same ladder and routes.
        let reserve = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
        let earlier = AttemptQueue::new(vault).retry_chain_depth(attempt.id)?;
        let carried = attempt.retry_of.and_then(|parent| {
            self.spent
                .lock()
                .expect("step spend mutex poisoned")
                .remove(&parent)
        });
        let run_id = format!(
            "workflow-step:{}",
            oneiron::EntityId::from_bytes(*attempt.id.as_bytes())?.to_hex()
        );
        let charged = match carried {
            Some(units) => units.div_ceil(reserve),
            None => u64::from(earlier).saturating_mul(call.ladder.rungs() as u64),
        };
        // A step launched under a spend lease (OF-532) is bounded by it too:
        // beside its policy rows, this try may spend no more than the lease
        // has left. Replayed charges are already on the lease, so they sit
        // on top of that bound, not inside it.
        let dispatcher = AgentDispatcher::new(vault);
        let lease = dispatcher.spend_scope_for_attempt(attempt.id)?;
        // OF-531: a room-paid step bills its root payer's own account, bound
        // before anything is reserved, never the vault owner's by default.
        // A payer this host cannot bill holds the step on the owners'
        // payer-needed ask: it is retried, and a try after their yes bills
        // the vault. Nothing went out, so the retry replays only what the
        // earlier tries spent.
        let payer = match scope_funding(vault, lease.as_ref(), room) {
            Ok(payer) => payer,
            Err(fault) => {
                let retryable = matches!(fault, PayerFault::Needed { .. });
                if retryable {
                    self.spent
                        .lock()
                        .expect("step spend mutex poisoned")
                        .insert(attempt.id, charged.saturating_mul(reserve));
                }
                return Err(StepFault {
                    retryable,
                    exhausted: false,
                    error: Error::InvalidConfig(format!("workflow step {fault}")),
                });
            }
        };
        let budget_units = match &lease {
            Some(scope) => self.budget_units.min(
                charged
                    .saturating_mul(reserve)
                    .saturating_add(dispatcher.guard_for_scope(scope)?.read().remaining_units),
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
            error: Error::InvalidConfig(format!("workflow step budget: {denied:?}")),
        };
        for _ in 0..charged {
            let spent = guard.admit_for_request(&request).map_err(budget)?.lease;
            guard.settle_reserved(&spent).map_err(budget)?;
        }
        let replayed = guard.read().used_units;
        // The step is a run on that meter: each rung its call reaches is
        // admitted on its own permit, sent through the run's gate and
        // settled. An answer pays its tokens, or the reservation when it
        // reports none; a rung that went out and failed pays its reservation.
        let run = self.models.funded_run(run_id, guard, payer);
        let generated = runtime.block_on(call.ladder.generate_served(&run, request, None));
        // What this try spent goes on the lease whatever the call answered;
        // the replayed tries recorded their own.
        if let Some(scope) = &lease {
            dispatcher.record_guard_spend(scope, run.read().used_units.saturating_sub(replayed))?;
        }
        let response = match generated {
            // The rung that answered, fallback included, is the step's
            // executor: its leaf is attributed to it (OF-540). A refused
            // stamp leaves the leaf unattributed, not failed.
            Ok((response, served)) => {
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
                response
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
        Ok(text.into_bytes())
    }
}
