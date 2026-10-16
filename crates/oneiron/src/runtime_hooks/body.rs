//! The seam between the runner and the hook sandbox (ARCH-0080 §6). The
//! sandbox runs one body; the runner owns everything around it.

use crate::Result;

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
}

/// What one body run gave back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookBodyRun {
    /// The one outcome the body emitted, as JSON.
    pub outcome_json: String,
    pub fuel_used: u64,
    /// Reads plus the emit.
    pub host_calls: u32,
}
