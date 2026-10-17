//! The seam between the runner and the hook sandbox (ARCH-0080 §6). The
//! sandbox runs one body; the runner owns everything around it.

use std::time::Instant;

use crate::{EdgeActorClass, EntityId, Result};

/// Answers one `ai.verdict` call of a body; the refusal text otherwise.
pub type HookVerdictCall<'a> =
    &'a mut dyn FnMut(&str) -> std::result::Result<String, String>;

/// Runs one hook body in a bounded sandbox.
pub trait HookBodyRuntime: Send + Sync {
    /// Runs one body; `read` answers `oneiron.read`. Returns the emitted outcome JSON.
    fn run_hook(
        &self,
        body: &str,
        input_json: &str,
        budget_ms: u32,
        read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> Result<HookBodyRun>;

    /// [`Self::run_hook`] for a fact hook: `verdict` answers `ai.verdict`.
    /// A runtime without the import answers no verdict.
    fn run_fact_hook(
        &self,
        body: &str,
        input_json: &str,
        budget_ms: u32,
        read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
        verdict: HookVerdictCall<'_>,
    ) -> Result<HookBodyRun> {
        let _ = verdict;
        self.run_hook(body, input_json, budget_ms, read)
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

/// `ai.verdict` for a fact hook that declares the generative class (ARCH-0080
/// §4 Its shape). The server supplies it: a verdict climbs its decision
/// ladder, under run admission, and a verb hook never reaches it.
pub trait HookVerdict: Send + Sync {
    /// Asks `request_json`, an `ai.verdict` input, for `reader`, the reader
    /// the hook's grant names, answering by `deadline`. The verdict as JSON,
    /// or the refusal's text. Blocks: the runner calls it off the runtime.
    fn verdict(
        &self,
        reader: EntityId,
        class: EdgeActorClass,
        request_json: &str,
        deadline: Instant,
    ) -> std::result::Result<String, String>;
}
