//! Shared durable-step type layer: schema consts, error, progression/trap enums, step context, and outcome.

use crate::attempt_queue::AttemptId;
use crate::side_table::{FixedSideKey, SideKey};

/// `AttemptId` is a foreign (same-crate) type; every step-family side table keys on it, so the
/// `SideKey` binding lives once here rather than once per table module.
impl SideKey for AttemptId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes).ok()
    }
}

impl FixedSideKey for AttemptId {
    const WIDTH: usize = 16;
}

pub(super) const DREAMER_STEP_STATE_SCHEMA_VERSION: u64 = 1;

pub(super) const DREAMER_STEP_STATE_KEYS: [&str; 9] = [
    "schema_version",
    "progression",
    "started_at",
    "updated_at",
    "response",
    "actor",
    "subject",
    "claim",
    "erased",
];

pub(super) const DREAMER_TRAP_BINDING_SCHEMA_VERSION: u64 = 1;

pub(super) const DREAMER_TRAP_BINDING_KEYS: [&str; 4] =
    ["schema_version", "job_id", "step_hash", "park_owner"];

pub(super) const DREAMER_PEER_WAIT_SCHEMA_VERSION: u64 = 1;

pub(super) const DREAMER_PEER_WAIT_KEYS: [&str; 4] =
    ["schema_version", "trap_claim_id", "step_hash", "at"];

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

pub(super) const KEY_ATTEMPT_ID: &str = "job_id";

pub(super) const KEY_STEP_HASH: &str = "step_hash";

pub(super) const KEY_PROGRESSION: &str = "progression";

pub(super) const KEY_MODEL_ID: &str = "model_id";

pub(super) const KEY_PURPOSE: &str = "purpose";

pub(super) const KEY_PARAMS_HASH: &str = "params_hash";

pub(super) const KEY_USAGE_IN: &str = "usage_in";

pub(super) const KEY_USAGE_OUT: &str = "usage_out";

pub(super) use crate::store::model_step_response_carriage::KEY_RESPONSE;

pub(super) const KEY_RESPONSE_REF: &str = "response_ref";

pub(super) const KEY_RESPONSE_VERSION: &str = "response_version";

pub(super) const KEY_RESPONSE_HASH: &str = "response_hash";

pub(super) const KEY_AT: &str = "at";

pub(super) const KEY_TRAP_KIND: &str = "trap_kind";

pub(super) const KEY_STATE: &str = "state";

pub(super) const KEY_NOTE: &str = "note";

pub(super) const KEY_PARK_OWNER: &str = "park_owner";

pub(super) const KEY_TRAP_CLAIM_ID: &str = "trap_claim_id";

pub(super) const KEY_STARTED_AT: &str = "started_at";

pub(super) const KEY_UPDATED_AT: &str = "updated_at";

/// A step-state row's write-time owners (KS-2B1): its actor, its subject and
/// the terminal claim that logged it.
pub(super) const KEY_STATE_ACTOR: &str = "actor";

pub(super) const KEY_STATE_SUBJECT: &str = "subject";

pub(super) const KEY_STATE_CLAIM: &str = "claim";

/// A step-state row whose response its owner's erase took (KS-2B1).
pub(super) const KEY_STATE_ERASED: &str = "erased";

// Runtime write-envelope provenance keys stamped by `dreamer_runtime_envelope`
// onto every step/trap record. The memo-index admission gate (ONE-1344) reads
// them back off the stored claim, so writer and reader share these constants.
pub(super) const ENVELOPE_PROVENANCE_SURFACE_KEY: &str = "surface";

pub(super) const ENVELOPE_PROVENANCE_RUN_KEY: &str = "run";

pub(super) const ENVELOPE_PROVENANCE_ATTEMPT_KEY: &str = "job_id";

/// A `params_hash` / `step_hash` is a BLAKE3 digest rendered as lowercase hex.
pub(super) const STEP_HEX_DIGEST_LEN: usize = 64;

pub(super) const TRAP_CHAIN_WALK_CAP: usize = 64;

pub use crate::model_step_error::{DurableStepError, DurableStepResult, ReplyCheck};

pub use crate::model_step_record::{
    DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES, DREAMER_STEP_PREDICATE, DREAMER_STEP_RETRY_BACKOFF_MS,
    DREAMER_STEP_VALUE_KEYS, DREAMER_STEP_VALUE_SCHEMA_VERSION, DREAMER_TRAP_PREDICATE,
    DREAMER_TRAP_VALUE_KEYS, DREAMER_TRAP_VALUE_SCHEMA_VERSION, DreamerTrapKind, DreamerTrapState,
    StepProgression, TrapRef,
};

pub(crate) use crate::model_step_effect::StepEffectBinding;

pub use crate::model_step_context::{DurableStepContext, StepOutcome};
