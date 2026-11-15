//! Moved from `crates/oneiron/src/code_run/shadow_runner/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::dreamer_runner::shadow_values::ArtifactDigest;
pub use crate::dreamer_runner::shadow_values::ArtifactDigestAlgorithm;
pub use crate::dreamer_runner::shadow_values::EngineArtifactPin;
pub use crate::dreamer_runner::shadow_values::ShadowBridgeWindow;
pub use crate::dreamer_runner::shadow_values::ShadowIsolation;
pub use crate::dreamer_runner::shadow_values::ShadowIsolationRequired;
pub use crate::dreamer_runner::shadow_values::ShadowMeterContext;
pub use crate::dreamer_runner::shadow_values::ShadowModelPin;
pub use crate::dreamer_runner::shadow_values::ShadowSandboxBinding;
pub use crate::dreamer_runner::shadow_values::ShadowScope;
pub use crate::dreamer_runner::shadow_values::ShadowTarget;
pub use crate::dreamer_runner::shadow_values::ShadowTraceEntry;
pub use crate::dreamer_runner::shadow_values::ShadowTraceKind;
pub use crate::dreamer_runner::shadow_values::ShadowUnavailable;
pub use crate::dreamer_runner::shadow_values::ShadowUnavailableReason;
pub use crate::dreamer_runner::shadow_values::ShadowUsage;
use serde::Deserialize;
use serde::Serialize;

/// Why an arm's window was full, as a frame carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum ShadowWindowFullReason {
    InFlight,
    Suppressed { cause: String },
    NothingToCompact,
}
