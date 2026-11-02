//! A conversation's self-written compaction (FIX 4465 D): a self agent's
//! chat turn compacts as the agent. The agent's log is read from the
//! retained ledger as its reader reads it ([`read_chat_log`]): landed
//! summaries stand in for the turns they cover, and each turn the log holds
//! is pinned by its projection's fingerprint. At the answer's breakpoint
//! its host captures the answer's own admitted request as the fork's
//! prefix ([`capture_conversation_fork`]), or, under a row on `auto` whose
//! live prefix is cold, leaves the flight to the cheap writer as the agent
//! (FIX 6029). Past the profile's threshold the oldest turns outside the hot
//! tail seal one window in one SESSION, sized on the writer the flight was
//! prepared on; the flight runs off the answer's path, its paid tries filed
//! in the model-step family, its summary minted as the session's next epoch
//! with a durable receipt keyed by the SUMMARY and the Dreamer's check
//! declared in the same write. A flight that cannot run keeps the raw log
//! and names why; it is never handed to the Dreamer or the plain house
//! writer.

use serde::{Deserialize, Serialize};

use super::driver::WindowLog;
use super::{
    CompactHooks, CompactionBackend, CompactionCheck, CompactionDirective, CompactionDriver,
    CompactionEvidence, CompactionExecution, CompactionGateFailure, CompactionGatePolicy,
    CompactionOff, CompactionRefusal, CompactionRequest, CompactionSuppression, GatedCompaction,
    SelfCompactionUnavailable, compact_invocation, compaction_input_tokens, gate_compaction,
};
use crate::code_run::{ExecutorStorage, LiveCompactionFork};
use crate::edge::EdgeActorClass;
use crate::runtime_hooks::VerbHookStop;
use crate::{EntityId, LlmRequest, Vault, WriteActor};

mod log;
mod storage;

use log::ChatLogWindow;
pub use log::{ChatLog, ChatLogLine, read_chat_log};
pub(crate) use storage::{conversation_receipt_in, put_conversation_receipt_in_txn};

/// The run a conversation's paid compaction calls are filed under: the
/// chat's own source, never a code run's.
const CHAT_COMPACTION_RUN_REF: &str = "chat-compaction";

/// Why a pass's calls were not filed: its route refused the write. The
/// receipt keeps their usage either way.
const STEP_FILING_REFUSED: &str = "step_filing_refused";

/// One retained turn of a conversation's window, by revision: the turn, who
/// it speaks for, the MESSAGEs its reader read in order, and the hex of its
/// projection's fingerprint, which pins its words, rows and authors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationTurnSpan {
    pub turn: EntityId,
    /// `user` or `companion`.
    pub role: String,
    pub messages: Vec<EntityId>,
    pub fingerprint: String,
}

/// The retained evidence a conversation's self-written summary was cut
/// from: the SESSION its turns were witnessed into, the conversation and the
/// branch it read (a DAG conversation's HEAD), and the window's turns in
/// order. The chat generation that sealed it is the paid calls' job, never
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationEvidence {
    pub session: EntityId,
    pub conversation: EntityId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<EntityId>,
    pub turns: Vec<ConversationTurnSpan>,
}

/// Why a conversation's self-written compaction did not fly at a
/// breakpoint. The log stays raw for the turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationCompactionUnavailable {
    /// No compaction writer serves this host.
    Off(CompactionOff),
    /// The agent cannot write this flight as itself.
    Writer(SelfCompactionUnavailable),
    /// The log is under its profile's threshold.
    Quiet,
    /// Past the threshold, no turn outside the hot tail can be compacted
    /// now: the next one is open, incomplete, outside a recorded SESSION,
    /// not read exactly, or already covered.
    NoWindow,
    /// The window did not seal: its SESSION's lineage does not continue at
    /// it.
    WindowNotSealed,
    /// The log could not be read.
    LogUnreadable,
    /// The chat actor's budget line could not be read for the flight's own
    /// guard.
    Unmetered,
    /// A blocking host.compact hook saved an ask/Pending stop (FIX 10085).
    Pending(VerbHookStop),
}

impl ConversationCompactionUnavailable {
    /// The stable name a log line carries.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off(why) => why.as_str(),
            Self::Writer(why) => why.as_str(),
            Self::Quiet => "quiet",
            Self::NoWindow => "no_window",
            Self::WindowNotSealed => "window_not_sealed",
            Self::LogUnreadable => "log_unreadable",
            Self::Unmetered => "unmetered",
            Self::Pending(_) => "pending",
        }
    }
}

/// `capture_conversation_fork`: the answer's own `live` request, as its
/// rung sends it, captured at its breakpoint for its flight, on its
/// driver's backend. `None` for a flight the cheap writer writes as the
/// agent: a row on the retained turns, or a row on `auto` whose live prefix
/// is cold here (FIX 6029). Why none can be bound, for a row that selects
/// the live fork. Called before the answer is sent, so the rung is the one
/// its walk takes now.
pub fn capture_conversation_fork(
    driver: &CompactionDriver,
    live: &LlmRequest,
) -> Option<Result<LiveCompactionFork, SelfCompactionUnavailable>> {
    driver
        .backend()
        .capture_live_fork(live, driver.summary_token_budget())
}

/// One sealed conversation flight: the driver that sealed it, its window's
/// request, the fork its backend froze, and the evidence its receipt names.
pub struct ConversationFlight<'a> {
    driver: &'a mut CompactionDriver,
    request: CompactionRequest,
    policy: CompactionGatePolicy,
    byline: WriteActor,
    evidence: ConversationEvidence,
    /// The chat generation whose breakpoint sealed it: its paid calls' job.
    job: EntityId,
    hooks: CompactHooks,
}

/// Seals `log`'s window for one flight past its driver's threshold, on the
/// `captured` fork its backend sends (FIX 4465 D), or on the cheap writer as
/// the agent when the breakpoint captured none (FIX 6029). The flight is
/// prepared first, so its window is sized on the writer it runs on: the
/// longest run of whole turns that writer takes, and its evidence names
/// exactly those turns. `byline` is the answering agent, `job` the reply's
/// MESSAGE. Off the answer's path.
///
/// # Errors
///
/// Why no flight runs; the driver is let go with the error.
pub fn seal_conversation_flight<'a>(
    vault: &'a Vault,
    driver: &'a mut CompactionDriver,
    policy: CompactionGatePolicy,
    byline: WriteActor,
    captured: Option<Result<LiveCompactionFork, SelfCompactionUnavailable>>,
    log: &'a ChatLog,
    job: EntityId,
) -> Result<ConversationFlight<'a>, ConversationCompactionUnavailable> {
    use ConversationCompactionUnavailable as Why;
    match driver.observe_from_context_build(vault, log.uncompacted_tokens) {
        Ok(CompactionDirective::Begin { .. }) => {}
        Ok(CompactionDirective::Quiet) => return Err(Why::Quiet),
        Err(_) => return Err(Why::LogUnreadable),
    }
    let Some(whole) = log.window.as_ref() else {
        driver.abandon();
        return Err(Why::NoWindow);
    };
    let prepared = match captured {
        None => driver.backend().prepare_flight(false),
        Some(captured) => driver
            .admit_self_live_binding(byline, captured)
            .and_then(|fork| driver.backend().prepare_live_flight(false, fork)),
    };
    if let Err(why) = prepared {
        driver.abandon();
        return Err(Why::Writer(why));
    }
    let budget = driver.summary_token_budget();
    let room = driver.backend().input_token_limit(budget);
    let Some(window) = window_within(whole, budget, room) else {
        driver.backend().end_flight();
        driver.abandon();
        return Err(Why::NoWindow);
    };
    let turn_start = window.messages.first().map_or(0, |message| message.turn);
    let fits = |pins: &[String]| {
        crate::tokenizer::count_context_pack_tokens(&pins.join("\n")) as u64 <= budget
            && room.is_none_or(|room| {
                compaction_input_tokens(turn_start, &window.messages, pins, None, budget) <= room
            })
    };
    // The agent's own pins the window holds word for word, while they fit,
    // then the lines a `host.compact` hook pins.
    let mut pins: Vec<String> = Vec::new();
    for pin in &driver.memory_profile().verbatim_pins {
        let held = !pin.trim().is_empty()
            && window
                .messages
                .iter()
                .any(|message| message.content.contains(pin.as_str()));
        if held && !pins.contains(pin) {
            pins.push(pin.clone());
            if !fits(&pins) {
                pins.pop();
            }
        }
    }
    let last = window.messages.last().map_or(0, |message| message.turn);
    let hooks = vault.pre_compact_hooks(
        compact_invocation(log.conversation.as_bytes(), last),
        byline.entity_ref(),
        &window.messages,
        &mut pins,
        budget,
        &fits,
    );
    if let Some(stop) = hooks.pending() {
        driver.backend().end_flight();
        driver.abandon();
        return Err(Why::Pending(stop.clone()));
    }
    let Ok(request) = driver.seal_request(
        vault,
        &window.session,
        window.messages,
        pins,
        window.sources,
        true,
        WindowLog::Conversation,
    ) else {
        driver.backend().end_flight();
        driver.abandon();
        return Err(Why::WindowNotSealed);
    };
    let evidence = ConversationEvidence {
        session: window.session,
        conversation: log.conversation,
        branch: log.branch,
        turns: window.spans,
    };
    Ok(ConversationFlight {
        driver,
        request,
        policy,
        byline,
        evidence,
        job,
        hooks,
    })
}

/// The longest run of `window`'s first turns whose rendered input fits
/// `room` beside a reply of `budget`, with those turns' own sources and
/// spans: all of it when it fits whole or nothing bounds it. `None` when not
/// even its first turn fits. The rest waits for a later flight.
fn window_within(window: &ChatLogWindow, budget: u64, room: Option<u64>) -> Option<ChatLogWindow> {
    let turn_start = window.messages.first()?.turn;
    let fits = |turns: usize| {
        room.is_none_or(|room| {
            compaction_input_tokens(turn_start, &window.messages[..turns], &[], None, budget)
                <= room
        })
    };
    if fits(window.messages.len()) {
        return Some(window.clone());
    }
    // Whole turns only: the largest count that fits, by halves.
    let (mut held, mut over) = (0, window.messages.len());
    while over - held > 1 {
        let mid = held + (over - held) / 2;
        if fits(mid) {
            held = mid;
        } else {
            over = mid;
        }
    }
    if held == 0 {
        return None;
    }
    let spans = window.spans[..held].to_vec();
    let sources = spans
        .iter()
        .flat_map(|span| std::iter::once(span.turn).chain(span.messages.iter().copied()))
        .collect();
    Some(ChatLogWindow {
        session: window.session,
        messages: window.messages[..held].to_vec(),
        sources,
        spans,
    })
}

/// How a conversation flight ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationFlightOutcome {
    /// Its summary landed as this SUMMARY.
    Landed(EntityId),
    /// The gate refused every try; the last failed this check.
    Rejected(CompactionCheck),
    /// A call or the landing was refused, with why.
    Refused(String),
}

impl ConversationFlight<'_> {
    /// Runs the flight's passes on its frozen fork, files every paid try,
    /// and lands an accepted summary with its receipt and its check.
    #[must_use]
    pub fn fly(self, vault: &Vault) -> ConversationFlightOutcome {
        let backend = std::sync::Arc::clone(self.driver.backend());
        let (pass, mut execution) = run_pass(backend.as_ref(), &self.request, &self.policy);
        if let Some(execution) = execution.as_mut() {
            file_pass(vault, self.job, execution);
        }
        let outcome = match (pass, execution) {
            (Pass::Accepted(gated), Some(mut execution)) => {
                execution.evidence = Some(CompactionEvidence::Conversation(self.evidence.clone()));
                let (first, last) = (
                    self.request.turn_start,
                    self.request
                        .window
                        .last()
                        .map_or(self.request.turn_start, |message| message.turn),
                );
                match self
                    .driver
                    .integrate_conversation(vault, self.byline, *gated, execution)
                {
                    Ok(plan) => {
                        let summary = plan.summary_id;
                        vault.post_compact_hooks(self.hooks, &plan, first, last);
                        ConversationFlightOutcome::Landed(summary)
                    }
                    Err(error) => {
                        self.driver.abandon();
                        ConversationFlightOutcome::Refused(format!(
                            "landing_refused:{:?}",
                            error.kind()
                        ))
                    }
                }
            }
            (Pass::Accepted(_), None) => {
                self.driver.abandon();
                ConversationFlightOutcome::Refused("no_writer_receipt".to_owned())
            }
            (Pass::Rejected(failure), _) => {
                self.driver.abandon();
                ConversationFlightOutcome::Rejected(failure.check)
            }
            (Pass::Refused(refusal), _) => {
                self.driver.abandon();
                ConversationFlightOutcome::Refused(refusal.detail)
            }
        };
        backend.end_flight();
        outcome
    }
}

/// How one pass's tries ended.
enum Pass {
    Accepted(Box<GatedCompaction>),
    Rejected(CompactionGateFailure),
    Refused(CompactionRefusal),
}

/// Up to `policy.tries` tries, each retry naming the check the last one
/// failed, as an executor flight's pass runs them: the answering try's
/// record comes back stamped with the accepted summary's snapshot, each try
/// refused before it keeps its own usage line, and the record holds every
/// paid call of the pass, the refused ones first, for its host to file.
fn run_pass(
    backend: &dyn CompactionBackend,
    request: &CompactionRequest,
    policy: &CompactionGatePolicy,
) -> (Pass, Option<CompactionExecution>) {
    let mut retry: Option<CompactionCheck> = None;
    let mut last = None;
    let mut spent: Option<CompactionExecution> = None;
    let mut rejected = Vec::new();
    let mut calls = Vec::new();
    for _ in 0..policy.tries.max(1) {
        let (product, mut execution) = match backend.compact_as_writer(request, retry) {
            Ok(answer) => answer,
            Err(refusal) => {
                let spent = spent.map(|spent| spent.with_rejected(rejected).with_calls(calls));
                return (Pass::Refused(refusal), spent);
            }
        };
        if let Some(execution) = execution.as_mut() {
            calls.append(&mut execution.calls);
        }
        match gate_compaction(request, &product, policy) {
            Ok(gated) => {
                if let Some(prior) = spent.take() {
                    rejected.push(prior.usage);
                }
                let execution = execution.map(|execution| {
                    execution
                        .accepted(gated.summary_text(), rejected)
                        .with_calls(calls)
                });
                return (Pass::Accepted(Box::new(gated)), execution);
            }
            Err(failure) => {
                if let Some(execution) = execution
                    && let Some(prior) = spent.replace(execution)
                {
                    rejected.push(prior.usage);
                }
                retry = Some(failure.check);
                last = Some(failure);
            }
        }
    }
    let spent = spent.map(|spent| spent.with_rejected(rejected).with_calls(calls));
    match last {
        Some(failure) => (Pass::Rejected(failure), spent),
        None => (
            Pass::Refused(CompactionRefusal {
                suppression: CompactionSuppression::TurnScoped { check: None },
                detail: "the compaction pass made no try".to_owned(),
            }),
            spent,
        ),
    }
}

/// Files the pass's paid calls as `job`'s steps on base, where chat's rows
/// land, and pins the receipt to them. Filing settles nothing again: the
/// flight's meter settled each call once when it ran.
fn file_pass(vault: &Vault, job: EntityId, execution: &mut CompactionExecution) {
    let calls = std::mem::take(&mut execution.calls);
    let writer = WriteActor::new(execution.writer, EdgeActorClass::Agent);
    match ExecutorStorage::Canonical(vault).file_compaction_steps(
        CHAT_COMPACTION_RUN_REF,
        job,
        writer,
        &calls,
        now_ms(),
    ) {
        Ok(mut steps) => {
            if execution.snapshot().is_some() {
                execution.step = steps.pop();
            }
            execution.rejected_steps = steps;
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a conversation's self-written compaction calls were not filed"
            );
            execution.step_unfiled = Some(STEP_FILING_REFUSED.to_owned());
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
