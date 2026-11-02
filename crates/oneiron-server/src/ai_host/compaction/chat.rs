//! A self agent's chat compaction (FIX 4465 D, Engine D4): the conversation
//! constructor of the shared writer factory, beside code mode's run seats.
//! It uses the same self registry, gate policy and home logic: one writer,
//! bound to the answering agent, wearing its home at the place its caller
//! sits, on the house compaction route. A live flight forks the answer's own
//! admitted call, captured at the answer's breakpoint through a per-answer
//! admission that hands back exactly that call; it is never admitted again
//! over a rendered transcript. Under a row on `auto` (FIX 6029, the
//! default) a breakpoint whose prefix is cold leaves the flight to the
//! cheap writer as the agent, over the retained ledger. The flight spends on
//! its own guard on the chat actor's budget line and bills the payer the
//! turn resolved: each call takes its own permit and settles once, and
//! filing settles nothing. It runs off the answer's path, queued with every
//! other pass.

use std::sync::Arc;

use oneiron::agent_def::AgentDefinition;
use oneiron::claim::CallerLocality;
use oneiron::code_run::bind_compaction_caller;
use oneiron::compaction::{
    ChatLog, CompactionDriver, CompactionOff, ConversationCompactionUnavailable,
    ConversationFlightOutcome, capture_conversation_fork, seal_conversation_flight,
};
use oneiron::engine_executor::CompactionSpawn;
use oneiron::llm::run_admission::PayerPerson;
use oneiron::llm::{SelfCompactionDefault, SelfCompactionSource};
use oneiron::{
    BudgetExhaustionPolicy, CompactionOwnership, EdgeActorClass, EntityId, LlmRequest,
    MemoryProfile, Vault, WriteActor,
};

use super::{CodeModeCompaction, CompactionMeter, LiveAdmission, ThreadSpawn};
use crate::ai_host::AiHandle;
use crate::models::{OfferLadder, RoleCall, RoleRefusal};

/// `chat_compaction_entry`: a chat answer compacts as its agent only for an
/// agent whose engine-owned profile names `self`, under a row that reads
/// the live context: one that selects the live fork, or `auto` (FIX 6029),
/// which forks the warm prefix or writes on the cheap writer. A row on the
/// retained turns and every other agent keep the chat path as it was.
fn chat_compaction_entry(profile: &MemoryProfile, row: &SelfCompactionDefault) -> bool {
    profile.compaction == CompactionOwnership::Engine
        && profile.writes_as_self()
        && matches!(
            row.source,
            SelfCompactionSource::Auto | SelfCompactionSource::LiveFork
        )
}

/// A self agent that compacts its chat as itself.
pub(crate) struct ChatSelfMode {
    agent: EntityId,
    definition: AgentDefinition,
    profile: MemoryProfile,
    hot_turns: u64,
}

impl ChatSelfMode {
    /// The answering agent.
    pub(crate) const fn agent(&self) -> EntityId {
        self.agent
    }

    /// How many recent turns stay raw: the agent's own hot window, else
    /// the host's.
    pub(crate) const fn hot_turns(&self) -> u64 {
        self.hot_turns
    }

    /// The instructions its definition gives the model, when it gives any.
    pub(crate) fn instructions(&self) -> Option<&str> {
        self.definition
            .instructions
            .as_deref()
            .filter(|text| !text.trim().is_empty())
    }
}

/// What an answer brings to its breakpoint.
pub(crate) struct ChatBreakpointCall {
    pub(crate) vault: Arc<Vault>,
    pub(crate) mode: ChatSelfMode,
    /// The log the answer's request was assembled from.
    pub(crate) log: ChatLog,
    /// Where the turn's caller sits: the home read's ceiling, never an
    /// eligibility test.
    pub(crate) locality: CallerLocality,
    /// The actor whose budget line the turn runs on.
    pub(crate) payer: WriteActor,
    /// Who the turn bills when a room pays for it.
    pub(crate) funding: Option<PayerPerson>,
    pub(crate) budget_units: u64,
    /// The reply's MESSAGE: the flight's paid calls' job.
    pub(crate) message: EntityId,
}

/// One answer's own admitted call, as its breakpoint captures it: a clone
/// of that call, handed back only for that call's own request.
struct AnswerAdmission {
    request: LlmRequest,
    ladder: Arc<OfferLadder>,
}

impl LiveAdmission for AnswerAdmission {
    fn admit_live(&self, request: LlmRequest) -> Result<RoleCall, RoleRefusal> {
        if request != self.request {
            return Err(RoleRefusal::Refused(Box::new(
                oneiron::Error::InvariantViolation("a breakpoint captures only its own answer"),
            )));
        }
        Ok(RoleCall {
            request: self.request.clone(),
            ladder: Arc::clone(&self.ladder),
        })
    }
}

impl AiHandle {
    /// The self mode `agent` answers chat in (FIX 4465 D), when its
    /// definition's profile names `self` and the vault's row reads the live
    /// context, on `live_fork` or `auto` (FIX 6029). `None` keeps the chat
    /// path as it was. A host whose writer
    /// factory is off still reads the agent's log this way; its breakpoint
    /// names why no flight runs.
    pub(crate) fn chat_self_mode(&self, vault: &Vault, agent: EntityId) -> Option<ChatSelfMode> {
        let definition = vault.get_agent_definition(&agent).ok().flatten()?;
        let profile = definition.memory_profile.clone()?;
        let row = vault
            .purpose_default_table()
            .ok()?
            .self_compaction()
            .clone();
        if !chat_compaction_entry(&profile, &row) {
            return None;
        }
        let house = match self.writer_compaction.get() {
            Some(CodeModeCompaction::Live(live)) => live.hot_steps,
            _ => 0,
        };
        Some(ChatSelfMode {
            agent,
            hot_turns: profile.hot_steps.unwrap_or(house),
            definition,
            profile,
        })
    }

    /// Enters an answer's breakpoint: past its profile's threshold, the
    /// answer's own `admitted` call is captured now, before it is sent (none
    /// under `auto` when its prefix is cold, FIX 6029), and its flight is
    /// queued to run off the answer's path. Says why no flight is queued
    /// when none is; the log then stays raw.
    pub(crate) fn enter_chat_breakpoint(
        &self,
        call: ChatBreakpointCall,
        admitted: &RoleCall,
    ) -> Result<(), ConversationCompactionUnavailable> {
        use ConversationCompactionUnavailable as Why;
        let live = match self.writer_compaction.get() {
            Some(CodeModeCompaction::Live(live)) => Arc::clone(live),
            Some(CodeModeCompaction::Off(why)) => return Err(Why::Off(*why)),
            None => return Err(Why::Off(CompactionOff::NoModels)),
        };
        let byline = WriteActor::new(call.mode.agent, EdgeActorClass::Agent);
        let host = bind_compaction_caller(byline, call.locality, None);
        let guard = call
            .vault
            .policy_budget_guard(
                format!("chat-compaction:{}", call.message.to_hex()),
                call.budget_units,
                oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(call.budget_units),
                BudgetExhaustionPolicy::Suspend,
                call.payer,
            )
            .map_err(|_| Why::Unmetered)?;
        let admission: Arc<dyn LiveAdmission> = Arc::new(AnswerAdmission {
            request: admitted.request.clone(),
            ladder: Arc::clone(&admitted.ladder),
        });
        let meter = CompactionMeter::Chat {
            guard,
            payer: call.funding.clone(),
        };
        let registry = live
            .self_registry(
                &call.mode.profile,
                call.mode.definition.clone(),
                host,
                Some(meter),
                &admission,
            )
            .map_err(|_| Why::Off(CompactionOff::BackendFailed))?;
        let driver = match CompactionDriver::for_profile(&call.mode.profile, &registry) {
            Ok(Some(driver)) => driver,
            Ok(None) => return Err(Why::Off(CompactionOff::HarnessCompacts)),
            Err(_) => return Err(Why::Off(CompactionOff::BackendFailed)),
        };
        if call.log.uncompacted_tokens < driver.compact_at() {
            return Err(Why::Quiet);
        }
        let captured = capture_conversation_fork(&driver, &admitted.request);
        let spawn = ThreadSpawn {
            passes: Arc::clone(&live.passes),
            credential: call.payer.entity_ref().to_hex(),
            runtime: live.runtime.clone(),
        };
        let policy = live.policy;
        let mut driver = driver;
        spawn.spawn(Box::new(move || {
            let ChatBreakpointCall {
                vault,
                log,
                message,
                ..
            } = call;
            let flight = match seal_conversation_flight(
                &vault,
                &mut driver,
                policy,
                byline,
                captured.clone(),
                &log,
                message,
            ) {
                Ok(flight) => flight,
                Err(Why::Pending(stop)) => {
                    tracing::info!(
                        %stop,
                        "a chat compaction hook left Pending; settled asks drain before its retry"
                    );
                    if let Err(error) = vault.drain_verb_asks() {
                        tracing::warn!(%error, "a chat compaction's Pending could not drain");
                        return;
                    }
                    match seal_conversation_flight(
                        &vault,
                        &mut driver,
                        policy,
                        byline,
                        captured,
                        &log,
                        message,
                    ) {
                        Ok(flight) => flight,
                        Err(why) => {
                            tracing::info!(
                                reason = why.as_str(),
                                "a chat turn's own compaction did not fly; its log stays raw"
                            );
                            return;
                        }
                    }
                }
                Err(why) => {
                    tracing::info!(
                        reason = why.as_str(),
                        "a chat turn's own compaction did not fly; its log stays raw"
                    );
                    return;
                }
            };
            match flight.fly(&vault) {
                ConversationFlightOutcome::Landed(summary) => tracing::debug!(
                    summary = %summary.to_hex(),
                    "a chat turn's own compaction landed"
                ),
                ConversationFlightOutcome::Rejected(check) => tracing::info!(
                    check = check.as_str(),
                    "a chat turn's own compaction was refused by its gate; its log stays raw"
                ),
                ConversationFlightOutcome::Refused(reason) => tracing::info!(
                    %reason,
                    "a chat turn's own compaction was refused; its log stays raw"
                ),
            }
        }));
        Ok(())
    }
}
