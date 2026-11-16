//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/targeted.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// What one `coach.agent_health` job reviews. A Nil input is the nightly
/// review, as every job queued before this input existed is.
#[derive(Debug, Serialize, Deserialize)]
pub enum HealthReviewInput {
    /// The scoped background review, each scope over its own window.
    Nightly,
    /// One agent attempt at its terminal receipt.
    Terminal {
        attempt: AttemptId,
        /// The lease generation it settled under.
        generation: u32,
        /// The settle's pack receipt, when it minted one. It is evidence of
        /// the settle, never the agent's identity: its actor is whoever
        /// settled the row.
        receipt: Option<String>,
    },
    /// One live agent attempt at a Dreamer wake.
    Live {
        attempt: AttemptId,
        /// The recipe-wake receipt whose wake queued it.
        wake: AttemptId,
        /// The lease generation it held when that wake queued it.
        generation: u32,
    },
}
