//! Moved from `crates/oneiron/src/retrieval_depth/controls.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::embedding_vocabulary::InputKind;
pub use oneiron_store::retrieval_deadline::RetrievalDeadline;
#[cfg(any(test, feature = "test-hooks"))]
pub use oneiron_store::retrieval_deadline::SlowRetrievalStage;
#[cfg(any(test, feature = "test-hooks"))]
pub use oneiron_store::retrieval_deadline::still_deadline_clock_for_test;
use oneiron_store::retrieval_telemetry::state::RetrievalTurn;
use serde::Deserialize;
use serde::Serialize;

/// Opt-in stage capture and the actual host turn whose retrieval is being observed.
/// The vault's capture setting remains authoritative; this cannot turn it on.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecallTelemetry {
    #[serde(default)]
    pub capture_trace: bool,
    #[serde(default)]
    pub turn: Option<RetrievalTurn>,
}
