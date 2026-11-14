//! Moved from `crates/oneiron/src/merge_queue/check_store.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::merge_queue::check_inputs::QueueCheckHold;
use crate::merge_queue::check_inputs::QueueCheckNeed;
use crate::merge_queue::types::CheckPhase;
use oneiron_base::error::Result;
use oneiron_store::contract_oracle::invalid;
use serde::Deserialize;
use serde::Serialize;

/// Where a checked initialization stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckInitStage {
    /// Approved and frozen; the baseline checks have not passed.
    Requested,
    /// Both baseline phases passed and the contract baseline is recorded;
    /// the queue is not initialized yet. A retry only attaches.
    Checked { baseline_id: String },
    /// The queue was initialized at the baseline.
    Initialized { baseline_id: String },
}

/// What a work row asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckRequest {
    Initialize {
        baseline_commit: String,
        contract_baseline_ref: Option<String>,
    },
    Check {
        batch: String,
        mask: u64,
        phase: CheckPhase,
        force_refresh: bool,
    },
    Diagnose {
        batch: String,
    },
}

impl QueueCheckRequest {
    /// The request's identity: the same init, check or diagnosis maps to
    /// the same work row. A refresh is the same request asked again.
    pub fn digest(&self) -> Result<String> {
        let identity = match self {
            Self::Initialize {
                baseline_commit,
                contract_baseline_ref,
            } => (
                "init",
                baseline_commit.as_str(),
                0,
                None,
                contract_baseline_ref.as_deref(),
            ),
            Self::Check {
                batch, mask, phase, ..
            } => ("check", batch.as_str(), *mask, Some(*phase), None),
            Self::Diagnose { batch } => ("diagnose", batch.as_str(), 0, None, None),
        };
        let bytes = rmp_serde::to_vec_named(&("oneiron:queue-check-request:v1", identity))
            .map_err(|_| invalid("queue check request encoding failed"))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    fn force_refresh(&self) -> bool {
        matches!(
            self,
            Self::Check {
                force_refresh: true,
                ..
            }
        )
    }
}

/// Where a work row stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckStatus {
    Queued,
    Running,
    /// The work is kept; nothing went green.
    NeedsConfiguration(QueueCheckNeed),
    /// No verdict; the work and its exhaust are kept.
    Held(QueueCheckHold),
    /// The work ran to a verdict, or for an init to its pointers.
    Completed {
        passed: bool,
    },
    /// The path this check fills already held a verdict when it ran.
    Settled {
        verdict_ref: String,
    },
}

/// The attempt lease one running generation holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckLease {
    pub owner: String,
    /// The attempt's own lease generation fence.
    pub attempt_count: u32,
}
