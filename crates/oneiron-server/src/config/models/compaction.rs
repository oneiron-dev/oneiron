//! `[models.code_mode.compaction]`: each code-mode run's window compacts by
//! itself (agent-runtime-v1 §d7). On by default wherever code mode is served.
use oneiron::llm::manifest::ModelRole;
use serde::Deserialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompactionFile {
    enabled: Option<bool>,
    role: Option<ModelRole>,
    window_tokens: Option<u64>,
    hot_steps: Option<u64>,
    tries: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactionSettings {
    pub enabled: bool,
    /// The seat passes run on. Unset: `checker` when its rungs take a whole
    /// window, else the seat code mode itself runs on.
    pub role: Option<ModelRole>,
    /// The window budget a run parks at. Unset: the smallest context the
    /// code-mode seat's rungs leave for input.
    pub window_tokens: Option<u64>,
    /// The newest steps that never compact.
    pub hot_steps: u64,
    /// Tries one pass makes before the run keeps its raw window.
    pub tries: u32,
}

const DEFAULT_HOT_STEPS: u64 = 2;
const DEFAULT_TRIES: u32 = 3;

impl CompactionFile {
    pub(super) fn resolve(self) -> anyhow::Result<CompactionSettings> {
        let settings = CompactionSettings {
            enabled: self.enabled.unwrap_or(true),
            role: self.role,
            window_tokens: self.window_tokens,
            hot_steps: self.hot_steps.unwrap_or(DEFAULT_HOT_STEPS),
            tries: self.tries.unwrap_or(DEFAULT_TRIES),
        };
        if settings.window_tokens == Some(0) || settings.tries == 0 {
            anyhow::bail!(
                "models.code_mode.compaction: window_tokens and tries must be greater than zero"
            );
        }
        Ok(settings)
    }
}
