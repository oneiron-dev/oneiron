//! The seam between the runner and the hook sandbox (ARCH-0080 §6). The
//! sandbox runs one body; the runner owns everything around it.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{EdgeActorClass, EntityId, Result};

/// Answers one `ai.verdict` call of a body; the refusal text otherwise.
pub type HookVerdictCall<'a> = &'a mut dyn FnMut(&str) -> std::result::Result<String, String>;

/// Runs one hook body in a bounded sandbox.
pub trait HookBodyRuntime: Send + Sync {
    /// Runs one body; `read` answers `oneiron.read`. Returns the emitted outcome JSON.
    /// `context` is the run's clock: the runtime measures each read and
    /// verdict callback through it, and never stops a body for its budget.
    fn run_hook(
        &self,
        body: &str,
        input_json: &str,
        context: &mut HookRunContext,
        read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> Result<HookBodyRun>;

    /// [`Self::run_hook`] for a fact hook: `verdict` answers `ai.verdict`.
    /// A runtime without the import answers no verdict.
    fn run_fact_hook(
        &self,
        body: &str,
        input_json: &str,
        context: &mut HookRunContext,
        read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
        verdict: HookVerdictCall<'_>,
    ) -> Result<HookBodyRun> {
        let _ = verdict;
        self.run_hook(body, input_json, context, read)
    }
}

/// What one body run gave back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookBodyRun {
    /// The one outcome the body emitted, as JSON.
    pub outcome_json: String,
    pub fuel_used: u64,
    /// Reads, verdicts and the emit.
    pub host_calls: u32,
}

/// One hook run's clock (FIX 8842). Its caller makes it once, before the
/// body runs, and reads its overrun once the run has ended. Its deadline,
/// `budget_ms` after its start, is an accounting deadline, never a stop: an
/// admitted read or verdict runs to its end and its answer is delivered
/// even when late, the body runs to its own end, and a run past it keeps
/// its outcome with the overrun beside it.
#[derive(Debug)]
pub struct HookRunContext {
    started: Instant,
    budget_ms: u32,
    deadline: Instant,
    /// Time spent in read and verdict callbacks so far.
    callbacks: Duration,
    read_overruns: u32,
    verdict_overruns: u32,
}

impl HookRunContext {
    /// A run's clock, started now, for a body whose budget is `budget_ms`.
    #[must_use]
    pub fn new(budget_ms: u32) -> Self {
        let started = Instant::now();
        Self {
            started,
            budget_ms,
            deadline: started + Duration::from_millis(u64::from(budget_ms)),
            callbacks: Duration::ZERO,
            read_overruns: 0,
            verdict_overruns: 0,
        }
    }

    #[must_use]
    pub const fn budget_ms(&self) -> u32 {
        self.budget_ms
    }

    /// The run's accounting deadline: advisory context for a callback (a
    /// verdict host may read it), never a stop.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Runs one admitted read callback to its end and measures it; its
    /// answer comes back as it is, late or not.
    pub fn read<T>(&mut self, answer: impl FnOnce() -> T) -> T {
        let (answer, late) = self.measure(answer);
        self.read_overruns = self.read_overruns.saturating_add(u32::from(late));
        answer
    }

    /// [`Self::read`] for one `ai.verdict` callback.
    pub fn verdict<T>(&mut self, answer: impl FnOnce() -> T) -> T {
        let (answer, late) = self.measure(answer);
        self.verdict_overruns = self.verdict_overruns.saturating_add(u32::from(late));
        answer
    }

    /// `answer`, beside whether it ended past the deadline; its time counts
    /// toward the run's callback time.
    fn measure<T>(&mut self, answer: impl FnOnce() -> T) -> (T, bool) {
        let began = Instant::now();
        let answer = answer();
        let ended = Instant::now();
        self.callbacks = self
            .callbacks
            .saturating_add(ended.saturating_duration_since(began));
        (answer, ended > self.deadline)
    }

    /// The run's overrun, read once its body has ended (its worker joined,
    /// a failed run's too): `None` for a run that ended by its deadline.
    #[must_use]
    pub fn finish(&self) -> Option<HookBudgetOverrun> {
        let now = Instant::now();
        if now <= self.deadline {
            return None;
        }
        Some(HookBudgetOverrun {
            budget_ms: self.budget_ms,
            elapsed_ms: millis(now.saturating_duration_since(self.started)),
            overrun_ms: millis(now.saturating_duration_since(self.deadline)),
            callback_ms: millis(self.callbacks),
            read_overruns: self.read_overruns,
            verdict_overruns: self.verdict_overruns,
        })
    }
}

/// A hook run that ended past its `budget_ms` (FIX 8842): a measured fact
/// beside its outcome, never a failure. Its run's state, outcome and pins
/// are what they would be within the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookBudgetOverrun {
    pub budget_ms: u32,
    /// From the run's start to its end.
    pub elapsed_ms: u64,
    /// How far past its deadline the run ended.
    pub overrun_ms: u64,
    /// Time its read and verdict callbacks took, all of them.
    pub callback_ms: u64,
    /// Reads whose callback ended past the deadline.
    pub read_overruns: u32,
    /// Verdicts whose callback ended past the deadline.
    pub verdict_overruns: u32,
}

impl HookBudgetOverrun {
    /// The overrun as a Hook receipt's named fields.
    pub(super) fn receipt_fields(&self) -> [(&'static str, String); 6] {
        [
            ("budget_ms", self.budget_ms.to_string()),
            ("elapsed_ms", self.elapsed_ms.to_string()),
            ("overrun_ms", self.overrun_ms.to_string()),
            ("callback_ms", self.callback_ms.to_string()),
            ("read_overruns", self.read_overruns.to_string()),
            ("verdict_overruns", self.verdict_overruns.to_string()),
        ]
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// `ai.verdict` for a fact hook that declares the generative class (ARCH-0080
/// §4 Its shape). The server supplies it: a verdict climbs its decision
/// ladder, under run admission, and a verb hook never reaches it.
pub trait HookVerdict: Send + Sync {
    /// Asks `request_json`, an `ai.verdict` input, for `reader`, the reader
    /// the hook's grant names. `deadline` is the hook run's accounting
    /// deadline, advisory context only: it never clamps or refuses the ask
    /// (FIX 8842). The verdict as JSON, or the refusal's text, beside the
    /// rows the same ask resolved its evidence to: `Some([])` for one read
    /// from none, `None` when they are not known. Blocks: the runner calls it
    /// off the runtime.
    fn verdict(
        &self,
        reader: EntityId,
        class: EdgeActorClass,
        request_json: &str,
        deadline: Instant,
    ) -> (std::result::Result<String, String>, Option<Vec<EntityId>>);
}
