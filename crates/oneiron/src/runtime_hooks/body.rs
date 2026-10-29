//! The seam between the runner and the hook sandbox (ARCH-0080 §6). The
//! sandbox runs one body; the runner owns everything around it.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{EdgeActorClass, EntityId, Result};

use super::filter;
use super::grant::HookGrant;

/// Answers one `ai.verdict` call of a body; the refusal text otherwise.
pub type HookVerdictCall<'a> = &'a mut dyn FnMut(&str) -> std::result::Result<String, String>;

/// Runs one hook body in a bounded sandbox.
pub trait HookBodyRuntime: Send + Sync {
    /// Runs one body; `read` answers `oneiron.read`. Returns the emitted outcome JSON.
    /// `context` is the run's clock: the runtime measures each read and
    /// verdict callback through it, and never stops a body for its budget.
    /// It reports what the body used there too, a failed body's included
    /// ([`HookRunContext::report_usage`], FIX 9332); a runtime that reports
    /// nothing leaves a failed run's usage unavailable, never zero.
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

/// What one hook body used (FIX 9332): its fuel and its host calls (reads,
/// verdicts and the emit), each as its runtime measured it. A count no one
/// measured is `None`, never a zero standing in for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookBodyUsage {
    pub fuel_used: Option<u64>,
    pub host_calls: Option<u32>,
}

impl HookBodyUsage {
    /// A run that invoked no runtime: it used nothing, known.
    pub const NOT_RUN: Self = Self {
        fuel_used: Some(0),
        host_calls: Some(0),
    };
    /// A runtime ran the body and reported nothing of what it used.
    pub const UNAVAILABLE: Self = Self {
        fuel_used: None,
        host_calls: None,
    };

    /// The usage as a Hook receipt's named fields: a measured count as its
    /// number, one not measured as `unavailable`, never `0`.
    pub(super) fn receipt_fields(&self) -> [(&'static str, String); 2] {
        let spelled = |count: Option<u64>| {
            count.map_or_else(
                || HOOK_USAGE_UNAVAILABLE.to_owned(),
                |measured| measured.to_string(),
            )
        };
        [
            ("fuel_used", spelled(self.fuel_used)),
            ("host_calls", spelled(self.host_calls.map(u64::from))),
        ]
    }
}

/// A CALLS choice (FIX 9332): how a Hook receipt spells a count its run's
/// runtime did not measure.
const HOOK_USAGE_UNAVAILABLE: &str = "unavailable";

/// One hook run's clock (FIX 8842). Its caller makes it once, before the
/// body runs, and reads its overrun once the run has ended. Its deadline,
/// `budget_ms` after its start, is an accounting deadline, never a stop: an
/// admitted read or verdict runs to its end and its answer is delivered
/// even when late, the body runs to its own end, and a run past it keeps
/// its outcome with the overrun beside it. It also holds what the body used
/// (FIX 9332), for a run that failed: nothing, until its caller invokes a
/// runtime ([`Self::body_starts`]), then unavailable until the runtime
/// reports it.
#[derive(Debug)]
pub struct HookRunContext {
    started: Instant,
    budget_ms: u32,
    deadline: Instant,
    /// Time spent in read and verdict callbacks so far.
    callbacks: Duration,
    read_overruns: u32,
    verdict_overruns: u32,
    usage: HookBodyUsage,
    /// How the runtime prepared the body it ran (FIX 9208): `None` until a
    /// runtime that prepares reports it.
    preparation: Option<HookPreparation>,
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
            usage: HookBodyUsage::NOT_RUN,
            preparation: None,
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

    /// Its caller is about to invoke a runtime on the body: what the body
    /// uses is unavailable until the runtime reports it (FIX 9332).
    pub fn body_starts(&mut self) {
        self.usage = HookBodyUsage::UNAVAILABLE;
    }

    /// What the body used, as its runtime measured it, on its success and
    /// its failure alike.
    pub fn report_usage(&mut self, usage: HookBodyUsage) {
        self.usage = usage;
    }

    /// What the body used, as it stands: [`HookBodyUsage::NOT_RUN`] while no
    /// runtime was invoked.
    #[must_use]
    pub const fn usage(&self) -> HookBodyUsage {
        self.usage
    }

    /// How the runtime prepared the body before it ran it (FIX 9208), on
    /// its success and its failure alike.
    pub fn report_preparation(&mut self, preparation: HookPreparation) {
        self.preparation = Some(preparation);
    }

    /// The body's preparation, once a runtime reported one.
    #[must_use]
    pub const fn preparation(&self) -> Option<&HookPreparation> {
        self.preparation.as_ref()
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

/// How a runtime prepared a hook body before it ran it (FIX 9208): the body
/// stays as authored (its `body_hash` names it); a TypeScript body runs as
/// the JavaScript its preparation printed, named here by that
/// preparation's identity. JavaScript runs byte for byte as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookPreparation {
    /// `javascript` or `typescript`: the language the body ran as.
    pub language: String,
    /// Why a body that is not JavaScript ran as written: the preparation's
    /// typed note code, never a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// A TypeScript body's preparation identity (the Oxc pin, its options,
    /// the executed JavaScript and its position map), lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// The trusted context of one `ai.verdict` a fact hook asks (FIX 10068,
/// 10075): the runner builds it from the binding and the run, never from the
/// request. Its grant is the authority the verdict's evidence is read under;
/// its pack and author name the line the verdict's model calls are charged
/// to, once, by the rungs that make them.
#[derive(Debug, Clone)]
pub struct HookVerdictContext {
    /// The grant the hook reads under, as it stands for this run: its
    /// reader reads the evidence, and its predicates and worlds bound which
    /// evidence reaches the ladder.
    pub grant: HookGrant,
    pub binding: EntityId,
    /// The exact pack source the body came from.
    pub source: EntityId,
    pub pack: String,
    pub hook: String,
    /// The actor whose pack it is: the line its verdicts spend on is theirs.
    pub author: EntityId,
    pub author_class: HookActorClass,
    /// The run that asks, by its key as lowercase hex.
    pub run: String,
    /// Which of the run's verdicts this is, from 0.
    pub ordinal: u32,
    /// The hook run's accounting deadline: advisory context only, never a
    /// clamp or a refusal (FIX 8842).
    pub deadline: Instant,
}

impl HookVerdictContext {
    /// The class the grant's reader reads as.
    #[must_use]
    pub const fn reader_class(&self) -> EdgeActorClass {
        filter::edge_class(self.grant.reader_class)
    }
}

/// One model call a hook's verdict made, as its run settled it (FIX 10075):
/// the run instance and the lease. A hook record names it; nothing settles
/// it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSettledCallRef {
    #[serde(with = "crate::serialize::entity_ref")]
    pub instance: EntityId,
    pub lease: String,
}

/// What one `ai.verdict` came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookVerdictReply {
    /// The verdict as JSON, or the refusal's text.
    pub reply: std::result::Result<String, String>,
    /// The rows the ask resolved its evidence to: `Some([])` for one read
    /// from none, `None` when they are not known.
    pub evidence: Option<Vec<EntityId>>,
    /// Each model call the ask settled, in the order they settled, a
    /// refused ask's included.
    pub calls: Vec<HookSettledCallRef>,
}

impl HookVerdictReply {
    /// A verdict refused before it read or asked anything.
    #[must_use]
    pub fn refused(reason: impl Into<String>) -> Self {
        Self {
            reply: Err(reason.into()),
            evidence: Some(Vec::new()),
            calls: Vec::new(),
        }
    }
}

/// `ai.verdict` for a fact hook that declares the generative class (ARCH-0080
/// §4 Its shape). The server supplies it: a verdict climbs its decision
/// ladder, under run admission, and a verb hook never reaches it.
pub trait HookVerdict: Send + Sync {
    /// Asks `request_json`, an `ai.verdict` input, in `context`: its
    /// evidence read by the grant's reader and shown only as the grant shows
    /// it (FIX 10068), its model calls charged once to the hook's pack line
    /// by the rungs that make them (FIX 10075). The context's deadline is
    /// advisory only: it never clamps or refuses the ask (FIX 8842). Blocks:
    /// the runner calls it off the runtime.
    fn verdict(&self, context: &HookVerdictContext, request_json: &str) -> HookVerdictReply;
}
