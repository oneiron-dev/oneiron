//! Moved from `crates/oneiron/src/failure_signals.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::failure_signals::code_fix::CandidateFixResult;
pub use crate::failure_signals::code_fix::CodeFixExport;
pub use crate::failure_signals::code_fix::CodeFixSource;
pub use crate::failure_signals::code_fix::CodeFixVerdict;
pub use crate::failure_signals::code_fix::CodeFixWithheld;
pub use crate::failure_signals::code_fix::FixOutcome;
pub use crate::failure_signals::code_fix::InventedFailureExample;
pub use crate::failure_signals::code_fix::InventedMessage;
pub use crate::failure_signals::code_fix::InventedRole;
pub use crate::failure_signals::code_fix::exact::ReplayFidelity;
pub use crate::failure_signals::delivery::FAILURE_SIGNAL_BATCH_VERSION;
pub use crate::failure_signals::status::FailureSignalBatchReceipt;
pub use crate::failure_signals::status::FailureSignalDeliveryStatus;
pub use crate::failure_signals::status::FailureSignalWaiting;
pub use oneiron_verb_wire::failure_signals::held::read::HeldFailureSignalBatchView;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

/// Graduating `Other` requires a new taxonomy variant and version; never
/// reinterpret a previously exported class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "taxonomy_version", content = "failure_class")]
pub enum FailureTaxonomy {
    #[serde(rename = "v1")]
    V1(FailureClassV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClassV1 {
    RefusalOverreach,
    TaskFailure,
    UserFrustration,
    MemoryMiss,
    MemoryIntrusion,
    PersonaBreak,
    LatencyAbandon,
    SilentDegradation,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    System,
    Custom,
    /// The observation names no affected agent (a detector's diagnostic).
    /// Exported in clear as `unattributed`; it never carries an agent ref.
    Unattributed,
}

/// The closed, content-free surface vocabulary. A new surface needs a reviewed
/// enum addition, not a caller-supplied name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSurface {
    Chat,
    Voice,
    Code,
    Task,
    Background,
    Other,
}
pub mod code_fix;
pub mod count_delivery;
pub mod delivery;
pub mod held;
pub mod status;
