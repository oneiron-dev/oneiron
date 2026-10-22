//! Typed lifecycle observations and completion receipts over the SLIM controller.
use serde::{Deserialize, Serialize};

use super::{
    HeapDropReport, InboundResumeOutcome, JournaledResumeStep, ShedBlocker, ShedCause, ShedOutcome,
    SlimResidue, SlimState,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::{MemoryError, MemoryResult};
use crate::outbound_intent_ledger::{IntentState, intent_ledger_records};

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

impl From<JournaledResumeStep> for SlimResumeStep {
    fn from(step: JournaledResumeStep) -> Self {
        match step {
            JournaledResumeStep::OutboundIntent {
                intent_id,
                attempt_id,
                call_seq,
                updated_ms,
            } => Self::OutboundIntent {
                intent_id: bytes_to_hex_lower(&intent_id),
                attempt_id: bytes_to_hex_lower(attempt_id.as_bytes()),
                call_seq,
                updated_ms,
            },
            JournaledResumeStep::Model {
                attempt_id,
                step_hash,
                updated_ms,
            } => Self::Model {
                attempt_id: bytes_to_hex_lower(attempt_id.as_bytes()),
                step_hash: bytes_to_hex_lower(&step_hash),
                updated_ms,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlimResidueView {
    pub step: SlimResumeStep,
    pub entered_at_ms: u64,
}

impl From<SlimResidue> for SlimResidueView {
    fn from(residue: SlimResidue) -> Self {
        Self {
            step: residue.step.into(),
            entered_at_ms: residue.entered_at_ms,
        }
    }
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

impl Vault {
    /// One atomic observation, with no resume, journal write or heap rebuild.
    #[must_use]
    pub fn slim_state_snapshot(&self) -> SlimStateSnapshot {
        let state = match &*self.slim.lock_state() {
            SlimState::Full => SlimStateView::Full,
            SlimState::Slim(residue) => SlimStateView::Slim {
                residue: residue.clone().into(),
            },
        };
        SlimStateSnapshot {
            process_id: std::process::id(),
            state,
        }
    }
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

impl From<ShedOutcome> for SlimDropReceipt {
    fn from(outcome: ShedOutcome) -> Self {
        let outcome = match outcome {
            ShedOutcome::Entered { residue, dropped } => SlimDropOutcome::Entered {
                residue: residue.into(),
                dropped,
            },
            ShedOutcome::AlreadySlim { residue, dropped } => SlimDropOutcome::AlreadySlim {
                residue: residue.into(),
                dropped,
            },
            ShedOutcome::Refused(blocker) => SlimDropOutcome::Refused { blocker },
        };
        Self {
            process_id: std::process::id(),
            outcome,
        }
    }
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

impl From<InboundResumeOutcome> for SlimResumeReceipt {
    fn from(outcome: InboundResumeOutcome) -> Self {
        let outcome = match outcome {
            InboundResumeOutcome::AlreadyFull => SlimResumeOutcome::AlreadyFull,
            InboundResumeOutcome::Resumed { residue } => SlimResumeOutcome::Resumed {
                residue: residue.into(),
            },
        };
        Self {
            process_id: std::process::id(),
            outcome,
        }
    }
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
        checkpoint: crate::llm::model_step::ModelStepCheckpoint,
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
}

/// Reads the existing journals only. No provider call, recovery pass or new ledger.
pub fn saved_resume_step_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SlimResumeStepRequest,
) -> MemoryResult<SavedResumeStep> {
    owner.revalidate(vault)?;
    match input {
        SlimResumeStepRequest::Model {
            attempt_id,
            step_hash,
        } => {
            let reference = EntityId::from_hex(&attempt_id)
                .map_err(|_| MemoryError::bad_request("invalid attempt_id"))?;
            let id = AttemptId::from_bytes(reference.as_bytes())?;
            let hash = blake3::Hash::from_hex(&step_hash)
                .map_err(|_| MemoryError::bad_request("invalid step_hash"))?;
            let checkpoint = crate::llm::model_step::resume_checkpoint(vault, id, hash.as_bytes())?
                .ok_or(crate::Error::EntityNotFound)?;
            Ok(SavedResumeStep::Model {
                attempt_id: bytes_to_hex_lower(id.as_bytes()),
                step_hash: bytes_to_hex_lower(hash.as_bytes()),
                checkpoint,
            })
        }
        SlimResumeStepRequest::OutboundIntent { intent_id } => {
            let id = blake3::Hash::from_hex(&intent_id)
                .map_err(|_| MemoryError::bad_request("invalid intent_id"))?;
            let listing = intent_ledger_records(vault).map_err(super::map_intent_ledger_error)?;
            if let Some(corrupt) = listing.corrupt.into_iter().next() {
                return Err(super::map_intent_ledger_error(corrupt.error).into());
            }
            let record = listing
                .records
                .into_iter()
                .find(|row| &row.id == id.as_bytes())
                .ok_or(crate::Error::EntityNotFound)?;
            let state = match record.state {
                IntentState::Pending => SavedIntentState::Pending,
                IntentState::Done => SavedIntentState::Done,
                IntentState::Abandoned => SavedIntentState::Abandoned,
            };
            let step = JournaledResumeStep::OutboundIntent {
                intent_id: record.id,
                attempt_id: record.attempt_id,
                call_seq: record.call_seq,
                updated_ms: record.updated_ms,
            }
            .into();
            Ok(SavedResumeStep::OutboundIntent { step, state })
        }
    }
}
