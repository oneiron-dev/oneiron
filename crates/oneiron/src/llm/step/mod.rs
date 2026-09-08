//! LLM-5 durable-step layer: `call_as_step` BLAKE3 memoization plus the
//! unified Budget/Consent trap record (ONE-1343).
//!
//! Step identity is the request content hash ([`LlmRequest::canonical_hash`])
//! — never a call-site ordinal. Memo scope is `(job_id, step_hash)` and is
//! per-device: live progression and the memo index live in private
//! `vault_meta` rows that never sync, while ONE terminal `dreamer.step`
//! vault claim per finished step is the durable, auditable record
//! (checkpoint-in-append). Control flow re-runs on resume; side effects are
//! memoized — never bit-replayed.

mod codec;
mod execute;
mod peer_wait;
mod step_claim;
mod step_state;
mod trap;
mod trap_binding;
mod types;

// The moved bodies still spell these parent (`llm`) names as `super::X`;
// one level deeper `super` is this module, so it re-exports them unchanged.
use super::{BudgetLease, BudgetSettlement, LlmUsage};

pub use self::execute::call_as_step;
pub use self::peer_wait::{
    PeerResultWaitBinding, reconcile_peer_result_signals, register_peer_result_wait,
    send_peer_result_signal,
};
pub use self::trap::{
    consume_trap_signal, open_trap, register_wait, send_trap_signal, trap_for_durable_wait,
    trap_park_owner,
};
pub use self::types::{
    DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES, DREAMER_STEP_PREDICATE, DREAMER_STEP_RETRY_BACKOFF_MS,
    DREAMER_STEP_VALUE_KEYS, DREAMER_STEP_VALUE_SCHEMA_VERSION, DREAMER_TRAP_PREDICATE,
    DREAMER_TRAP_VALUE_KEYS, DREAMER_TRAP_VALUE_SCHEMA_VERSION, DreamerTrapKind, DreamerTrapState,
    DurableStepContext, DurableStepError, DurableStepResult, StepOutcome, StepProgression, TrapRef,
};

pub(crate) use self::step_claim::{deindex_dreamer_step_claim, index_dreamer_step_claim_for_put};

#[cfg(test)]
mod tests;

// The flat step.rs module used to provide these names to the sibling test
// module through `use super::*`: every step-internal item the tests name
// bare. After the directory split the seam re-imports them so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use self::{peer_wait::*, step_claim::*, step_state::*, trap::*, types::*};
#[cfg(test)]
use crate::ClaimCandidate;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::AttemptId;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::entity_id::{EntityId, bytes_to_hex_lower};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::llm::{
    BudgetGuard, CallClass, CallPurpose, LlmBackend, LlmError, LlmRequest, LlmResponse,
    PinnedConfigViolation, PinnedModelConfig, canonical_json_bytes,
};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
#[cfg(test)]
use rmpv::Value;
