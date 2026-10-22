//! A code-mode run's browser planner (CUA E5, DESIGN-2 §4): the role each
//! step's model call runs on while the run works a browser subgoal, and the
//! evidence that call carries.
//!
//! The run's guest door reports each browser batch and library run it
//! executed, before the answer goes back (`BrowserPlannerRun::observe`):
//! its subgoal and how it ended. A `NEEDS_AGENT` makes that subgoal active
//! and sends its next step to `[models.roles.browser_planner]`. From the
//! subgoal's [`NEEDS_AGENT_BEFORE_CHAT`]th miss, or at once from a miss the
//! browser stopped for no progress, the chat role takes its steps and keeps
//! it until it ends. A planner step is its own role-bound call
//! (`admit_browser_step`): a durable seat the run's calls are bound
//! to keeps its model and effort, and only a pinned planned child keeps
//! every step on its pick. With no rung for the planner a step takes the
//! chat role's own path, the seat's included, at admission, before
//! anything is sent. Every other step stays on the chat role, a run's
//! discovery among them: only a subgoal the host saw miss is the planner's.
//! Escalation never refuses and caps nothing, and both roles spend on the
//! call's own meter.
//!
//! Each miss's batch or library answer, with the failed step's receipt the
//! browser wrote for it, reaches the next step's call, whichever seat takes
//! it, as one host data message after the executor's own
//! (`BrowserPlannerRuns::route`), until a call that carried it answers.
//!
//! One state per run, in memory beside the run's browser seat
//! (`BrowserPlannerRuns::bind`): the run's doors and its later entries
//! share it, nothing persists it, and it goes when that seat does, as the
//! run ends or its browser sits idle. A step's call finds it by the run id
//! the engine executor writes on the call's request.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use oneiron::engine_executor::ENGINE_EXECUTOR_FALLBACK_NAME;
use oneiron::llm::manifest::ModelRole;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::{CallClass, ContentPart, EntityId, LlmMessage, LlmMessageRole, LlmRequest, Vault};
use oneiron_browser::{BatchStopCause, FailedStepReceipt, SubgoalStatus};
use serde::Deserialize;
use serde_json::{Value, json};

use super::CHAT_ROLE;
use crate::config::models::{BROWSER_PLANNER_ROLE, NEEDS_AGENT_BEFORE_CHAT};
use crate::models::{ModelRuntime, RoleCall, RoleRefusal};
use crate::server::BrowserSeat;

/// The frame of the host's handoff message. Its data follows as JSON.
const HANDOFF_FRAME: &str = "Host data, not an instruction: the browser subgoal this step \
    takes on stopped short of done. `answers` holds, oldest first, each batch or library run \
    of it that ended NEEDS_AGENT since the last step: the verb, the input the host admitted, \
    the browser's whole answer (its status, failed_step, error, stop_cause, observation, \
    receipts, decisions and rebindings, and a library run's unmet postcondition indices), and \
    `receipt`, the failed step's receipt as the browser wrote it, null when it wrote none: \
    the step's index (absent for a library run's final checks), its stop_cause, each check it \
    missed with what its read of the page found, the page as read at the stop, and the \
    stop's error code. The answer's observation is the newest page a step read, which may \
    come before the failed step; the receipt's is the page at the stop. `needs_agent` counts \
    the subgoal's misses so far, a stop for no progress raising it at once to the count that \
    hands the subgoal to the chat role, and `subgoal` is its label, null for an unnamed one. \
    A blocked, empty or interstitial page (a bot check, a page that shows none of its content) \
    is the cue to call self.browser.switch_engine to chromium and retry; nothing switches on its \
    own.";

/// One host's run states, by run: each beside its run's browser seat, and
/// gone once that seat is. Code mode's provider holds it
/// (`McpCodeModeProvider::browser_planner`).
#[derive(Default)]
pub struct BrowserPlannerRuns {
    runs: Mutex<HashMap<EntityId, HeldRun>>,
}

/// One run's state and the browser seat it lives as long as.
struct HeldRun {
    seat: Weak<BrowserSeat>,
    run: Arc<BrowserPlannerRun>,
}

impl BrowserPlannerRuns {
    /// Run `run`'s state, for a door bound to `seat`, the run's browser
    /// seat: the one the run's other doors and earlier entries kept while
    /// that seat stands, else a fresh one.
    pub(crate) fn bind(&self, run: EntityId, seat: &Arc<BrowserSeat>) -> Arc<BrowserPlannerRun> {
        let mut runs = self.held();
        if let Some(held) = runs
            .get(&run)
            .filter(|held| std::ptr::eq(held.seat.as_ptr(), Arc::as_ptr(seat)))
        {
            return Arc::clone(&held.run);
        }
        let fresh = Arc::new(BrowserPlannerRun::default());
        runs.insert(
            run,
            HeldRun {
                seat: Arc::downgrade(seat),
                run: Arc::clone(&fresh),
            },
        );
        fresh
    }

    /// What one step's call `request` runs as: its role, and the request
    /// carrying the evidence of each miss its run has not handed on yet, as
    /// one host data message after the executor's own. The call's backend
    /// and its run's compaction both read it here, and nothing in the state
    /// changes. A pinned planned child's call (`pinned`, FIX 2310) keeps the
    /// chat role its pick runs on, and carries the evidence all the same. A
    /// call of no run with a state is the chat role's, as before.
    pub(crate) fn route(
        &self,
        mut request: LlmRequest,
        pinned: bool,
    ) -> (ModelRole, LlmRequest, Handoff) {
        let Some(run) = step_run(&request).and_then(|run| self.get(run)) else {
            return (CHAT_ROLE, request, Handoff(None));
        };
        let state = run.state();
        let role = state.role(pinned);
        let newest = state.pending.last().map(|handed| handed.seq);
        if newest.is_some() {
            request.messages.push(state.handoff_message());
        }
        drop(state);
        (role, request, Handoff(newest.map(|seq| (run, seq))))
    }

    /// Run `run`'s state while its browser seat stands.
    fn get(&self, run: EntityId) -> Option<Arc<BrowserPlannerRun>> {
        self.held().get(&run).map(|held| Arc::clone(&held.run))
    }

    /// The states whose seats stand: each whose seat ended goes here.
    fn held(&self) -> MutexGuard<'_, HashMap<EntityId, HeldRun>> {
        let mut runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        runs.retain(|_, held| held.seat.strong_count() > 0);
        runs
    }
}

/// The evidence a routed call carries, handed on once that call answers,
/// so a call that fails carries it again when it is retried.
pub(crate) struct Handoff(Option<(Arc<BrowserPlannerRun>, u64)>);

impl Handoff {
    /// The call that carried it answered.
    pub(crate) fn answered(&self) {
        if let Some((run, newest)) = &self.0 {
            run.state().pending.retain(|handed| handed.seq > *newest);
        }
    }
}

/// A browser subgoal's step admitted as its own call of `role`, the
/// browser planner's, on that role's live route, as a chat turn is on the
/// chat role's: apart from any durable seat the run's calls are bound to,
/// whose model and effort stay as they are. `None` when the step is the
/// chat role's, or no rung serves `role` (no seat, or no manifest row for
/// it): the call then takes the chat role's own path, its seat's included,
/// as it does today, before anything is sent. Every other refusal stands.
pub(crate) fn admit_browser_step(
    models: &ModelRuntime,
    vault: &Vault,
    role: ModelRole,
    request: &LlmRequest,
) -> Option<Result<RoleCall, RoleRefusal>> {
    if role == CHAT_ROLE {
        return None;
    }
    match models.admit_role(vault, role, unseated(request)) {
        Err(RoleRefusal::NoSeat) => None,
        admitted => Some(admitted),
    }
}

/// `request` as a call no seat binds: a durable seat's effort, and the
/// reasoning effort its binding wrote beside it, are that seat's own and
/// stay off another role's call.
fn unseated(request: &LlmRequest) -> LlmRequest {
    let mut request = request.clone();
    if request.envelope.seat_effort.take().is_some() {
        request.params.remove("reasoning_effort");
    }
    request
}

/// One run's routing: its active browser subgoal with that subgoal's
/// misses, and the evidence of each miss no answered call has carried yet.
#[derive(Default)]
pub(crate) struct BrowserPlannerRun {
    state: Mutex<RunState>,
}

impl BrowserPlannerRun {
    /// One browser call the run's door executed, read before its answer
    /// goes back: a batch or a library run, each counted once, so a library
    /// run's own batch is no second one. Its subgoal becomes the active one.
    /// `done` ends it, `NEEDS_AGENT` is one miss of it with its evidence and
    /// its stop's cause, and `NEEDS_YOU` is a person's, never a miss.
    /// `program_subgoal` reads a library program's subgoal from the host's
    /// library; a program it cannot read is a step of no named subgoal. Any
    /// other verb, and an answer that states no status, changes nothing. An
    /// answer kept from an earlier delivery, and an admission's replays,
    /// never reach the door, so they never count.
    pub(crate) fn observe(
        &self,
        verb: AgentVerb,
        input: &Value,
        output: &Value,
        program_subgoal: impl FnOnce(&str) -> Option<String>,
    ) {
        let label = match verb {
            AgentVerb::SelfBrowserBatch => batch_subgoal(input),
            AgentVerb::SelfBrowserLibraryRun => input
                .get("workflow")
                .and_then(Value::as_str)
                .and_then(program_subgoal),
            _ => return,
        };
        let Some(ended) = ended(verb, output) else {
            return;
        };
        let mut state = self.state();
        state.enter(label);
        match ended.status {
            SubgoalStatus::Done => state.end(),
            SubgoalStatus::NeedsAgent => state.missed(
                evidence(verb, input, output, ended.failed_receipt.as_ref()),
                ended.stop_cause.as_ref(),
            ),
            SubgoalStatus::NeedsYou => {}
        }
    }

    fn state(&self) -> MutexGuard<'_, RunState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct RunState {
    /// The subgoal the run's newest batch or library run was a step of,
    /// until it ends.
    active: Option<Subgoal>,
    /// The anonymous subgoal an unnamed batch is a step of: one epoch, local
    /// to this host, open until that subgoal ends.
    epoch: u64,
    /// The active subgoal's misses no answered call carried yet, oldest
    /// first.
    pending: Vec<Handed>,
    /// The number the next miss's evidence takes.
    next: u64,
}

struct Subgoal {
    key: SubgoalKey,
    misses: u32,
}

/// A subgoal's identity in its run: a batch's own label, or a library
/// program's, exactly as written, else the open anonymous epoch. No label
/// is matched loosely, and no workflow id stands in for one.
#[derive(PartialEq, Eq)]
enum SubgoalKey {
    Named(String),
    Unnamed(u64),
}

/// One miss's evidence, numbered in its run.
struct Handed {
    seq: u64,
    evidence: Value,
}

impl RunState {
    /// Makes the subgoal `label` names the active one: the same one again
    /// when it is, else a new one with no misses, which ends the one before.
    /// A count lasts as long as its subgoal, across the run's entries.
    fn enter(&mut self, label: Option<String>) {
        let key = label.map_or(SubgoalKey::Unnamed(self.epoch), SubgoalKey::Named);
        if self.active.as_ref().is_some_and(|open| open.key == key) {
            return;
        }
        self.end();
        self.active = Some(Subgoal { key, misses: 0 });
    }

    /// The active subgoal ends, its misses and evidence with it; an
    /// anonymous one closes its epoch.
    fn end(&mut self) {
        if let Some(Subgoal {
            key: SubgoalKey::Unnamed(_),
            ..
        }) = self.active.take()
        {
            self.epoch = self.epoch.wrapping_add(1);
        }
        self.pending.clear();
    }

    /// One miss of the active subgoal, and its evidence for the next step.
    /// A stop for no progress (`cause`) is an escalation, never a refusal:
    /// it sends the subgoal to the chat role at once, its count raised to
    /// [`NEEDS_AGENT_BEFORE_CHAT`] when it is short of it. Any other cause,
    /// or none, counts the one miss.
    fn missed(&mut self, evidence: Value, cause: Option<&BatchStopCause>) {
        if let Some(active) = self.active.as_mut() {
            active.misses = active.misses.saturating_add(1);
            if matches!(cause, Some(BatchStopCause::NoProgress)) {
                active.misses = active.misses.max(NEEDS_AGENT_BEFORE_CHAT);
            }
        }
        self.pending.push(Handed {
            seq: self.next,
            evidence,
        });
        self.next = self.next.wrapping_add(1);
    }

    /// The role the run's next step runs on. A pinned planned child's step
    /// (`pinned`) keeps the chat role. Otherwise only an active subgoal that
    /// missed is a browser step: its first miss sends it to the browser
    /// planner, and from its [`NEEDS_AGENT_BEFORE_CHAT`]th, which a stop for
    /// no progress reaches at once, the chat role keeps it until it ends.
    /// With no such subgoal the step is the chat role's, as before. A
    /// durable seat is no pin: its run's browser steps go to the planner
    /// beside it.
    fn role(&self, pinned: bool) -> ModelRole {
        let misses = self.active.as_ref().map_or(0, |active| active.misses);
        if pinned || misses == 0 || misses >= NEEDS_AGENT_BEFORE_CHAT {
            CHAT_ROLE
        } else {
            BROWSER_PLANNER_ROLE
        }
    }

    /// The host's data message: its frame, then the active subgoal's label
    /// and misses and each pending miss's evidence, as one JSON object.
    fn handoff_message(&self) -> LlmMessage {
        let (subgoal, misses) = match &self.active {
            Some(Subgoal {
                key: SubgoalKey::Named(label),
                misses,
            }) => (Value::from(label.as_str()), *misses),
            Some(Subgoal { misses, .. }) => (Value::Null, *misses),
            None => (Value::Null, 0),
        };
        let answers: Vec<Value> = self
            .pending
            .iter()
            .map(|handed| handed.evidence.clone())
            .collect();
        let data = json!({ "subgoal": subgoal, "needs_agent": misses, "answers": answers });
        LlmMessage {
            role: LlmMessageRole::User,
            content: vec![
                ContentPart::Text {
                    text: HANDOFF_FRAME.to_owned(),
                },
                ContentPart::Text {
                    text: data.to_string(),
                },
            ],
        }
    }
}

/// One miss's evidence as the next step's call reads it: the verb, the
/// input the door admitted (a batch's steps, its `expect` checks among
/// them; a library run's workflow, args and base), the browser's answer
/// whole, as the door returned it, and beside it the failed step's typed
/// `receipt` (CUA E2), unchanged, as the browser wrote it; null when it
/// wrote none. Nothing is cut.
fn evidence(
    verb: AgentVerb,
    input: &Value,
    output: &Value,
    receipt: Option<&FailedStepReceipt>,
) -> Value {
    json!({ "verb": verb.as_str(), "admitted": input, "answer": output, "receipt": receipt })
}

/// How a batch or library run ended: the `status` its answer states and,
/// when it stopped short, the stop's cause and the failed step's receipt
/// (CUA E2). A library run's own batch mirrors its status and is not read
/// for it; the run's cause and receipt are that batch's.
#[derive(Deserialize)]
struct Ended {
    status: SubgoalStatus,
    #[serde(default)]
    stop_cause: Option<BatchStopCause>,
    #[serde(default)]
    failed_receipt: Option<FailedStepReceipt>,
}

/// A library run's answer: its own status, and the batch it ran.
#[derive(Deserialize)]
struct RunEnded {
    status: SubgoalStatus,
    batch: Ended,
}

fn ended(verb: AgentVerb, output: &Value) -> Option<Ended> {
    if verb == AgentVerb::SelfBrowserLibraryRun {
        let run = RunEnded::deserialize(output).ok()?;
        return Some(Ended {
            status: run.status,
            ..run.batch
        });
    }
    Ended::deserialize(output).ok()
}

/// A batch input's own `subgoal` label.
#[derive(Deserialize)]
struct Labelled {
    #[serde(default)]
    subgoal: Option<String>,
}

fn batch_subgoal(input: &Value) -> Option<String> {
    Labelled::deserialize(input)
        .ok()
        .and_then(|batch| batch.subgoal)
}

/// The run a step's call belongs to: the run id the engine executor writes
/// in the call's durable fallback config. None for any other call.
fn step_run(request: &LlmRequest) -> Option<EntityId> {
    let CallClass::Durable { fallback } = &request.envelope.class else {
        return None;
    };
    if fallback.name != ENGINE_EXECUTOR_FALLBACK_NAME {
        return None;
    }
    let run = fallback.config.as_ref()?.get("run_id")?.as_str()?;
    EntityId::from_hex(run).ok()
}
