//! The code run model-heal count request and view records.
//! `CodeRunModelHealCountRequest` is the first of its records.
//! These are local definitions; `memory::code_run_doors` re-exports them.

use serde::{Deserialize, Serialize};

/// Names the one model whose healed-turn tally the owner reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunModelHealCountRequest {
    /// The full `provider/name@revision` id the executor seat was configured
    /// with. No revision is filled in and no provider wire label resolves.
    pub model_id: String,
}

/// How many durable executor turns of this vault the model needed wire
/// healing for: a routing signal, not a correction receipt. It names no run,
/// turn, repair or retry outcome, because the tally stores none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRunModelHealCountView {
    /// The model id as the request named it.
    pub model_id: String,
    /// Zero when this vault holds no tally for the model, which says nothing
    /// of whether the model exists or serves.
    pub healed_turns: u64,
}
