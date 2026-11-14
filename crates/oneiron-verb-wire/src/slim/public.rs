//! Moved from `crates/oneiron/src/slim/public.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::slim::ShedBlocker;
use crate::slim::ShedCause;
use oneiron_store::heap_drop::HeapDropReport;
use serde::Deserialize;
use serde::Serialize;

/// The serving host's declared policy; it is not a provider-call timeout.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlimIdlePolicy {
    pub long_outbound_wait_secs: u64,
    pub exits_on_idle: bool,
    pub lazy_rebuild: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlimDropRequest {
    pub cause: ShedCause,
    pub waited_secs: std::num::NonZeroU64,
}

/// Identities only. Payloads, credentials and provider responses never leave here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SlimResumeStep {
    OutboundIntent {
        intent_id: String,
        attempt_id: String,
        call_seq: u64,
        updated_ms: u64,
    },
    Model {
        attempt_id: String,
        step_hash: String,
        updated_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlimResidueView {
    pub step: SlimResumeStep,
    pub entered_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "residency", rename_all = "snake_case")]
pub enum SlimStateView {
    Full,
    Slim { residue: SlimResidueView },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlimStateSnapshot {
    pub process_id: u32,
    pub state: SlimStateView,
}

/// Returned only after the engine's fixed-order shed transaction finishes,
/// or once the owner's request finds it owed nothing (`nothing_pending`).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlimDropReceipt {
    pub process_id: u32,
    pub outcome: SlimDropOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SlimDropOutcome {
    Entered {
        residue: SlimResidueView,
        dropped: HeapDropReport,
    },
    AlreadySlim {
        residue: SlimResidueView,
        dropped: HeapDropReport,
    },
    Refused {
        blocker: ShedBlocker,
    },
    /// The owner's request waited while more than one outbound step was
    /// pending, then found none pending on a FULL vault: no shed was owed,
    /// so none ran (FIX 10157). It says nothing of how any send ended.
    NothingPending,
}

/// Logical FULL only: this neither rebuilds indexes nor reissues the saved step.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlimResumeReceipt {
    pub process_id: u32,
    pub outcome: SlimResumeOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SlimResumeOutcome {
    AlreadyFull,
    Resumed { residue: SlimResidueView },
}

/// A retained pointer can be inspected again after FULL or a process restart.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SlimResumeStepRequest {
    Model {
        attempt_id: String,
        step_hash: String,
    },
    OutboundIntent {
        intent_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SavedResumeStep {
    Model {
        attempt_id: String,
        step_hash: String,
        checkpoint: oneiron_store::model_step_record::ModelStepCheckpoint,
    },
    OutboundIntent {
        step: SlimResumeStep,
        state: SavedIntentState,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SavedIntentState {
    Pending,
    Done,
    Abandoned,
    /// The provider accepted the send as a remote task (FIX 7960).
    Deferred,
}
