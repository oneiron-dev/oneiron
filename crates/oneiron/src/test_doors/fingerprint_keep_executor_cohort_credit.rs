//! Door for `tests/fingerprint_keep_executor_cohort_credit.rs` (PLAN-UC-04 3.4b): the two
//! executor digests and the late-credit receipt key, which the engine computes in private
//! code, with the replay encoding and the bridge call rows the step hash reads.

use rmpv::Value;

use crate::Result;
use crate::code_run::{CodeRunBridgeCall, SelfEffect};
use crate::engine_executor::{EngineExecutorConfig, EngineExecutorResult};
use crate::session_overlay::RouteTarget;

/// Every input of a REPL step's checkpoint hash, by `prepared_step_state_hash`'s names.
#[derive(Clone, Debug)]
pub struct StepState {
    pub previous: [u8; 32],
    pub seq: u64,
    pub request_hash: [u8; 32],
    pub script: String,
    pub prepared: Option<[u8; 32]>,
    pub observation: [u8; 32],
    pub done: bool,
    pub outputs: Vec<(String, [u8; 32])>,
    pub bindings: Vec<(String, String)>,
    pub implicit_speak: Option<String>,
    pub bridge_calls: Vec<CodeRunBridgeCall>,
    pub bridge_end: u64,
    pub context: [u8; 32],
}

/// A run's replay identity under a storage binding: the session ref of an off-record
/// session (`None` for canonical storage) and the session's route target.
#[must_use]
pub fn executor_config_hash(
    session_ref: Option<&str>,
    route_target: Option<RouteTarget>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> [u8; 32] {
    crate::engine_executor::executor_config_hash_for_test(
        session_ref,
        route_target,
        config,
        continuation,
    )
}

/// A REPL step's checkpoint hash.
///
/// # Errors
/// A bridge call value that does not encode.
pub fn step_state_hash(step: &StepState) -> EngineExecutorResult<[u8; 32]> {
    crate::engine_executor::step_state_hash_for_test(step)
}

/// A bridge call value's replay encoding, which the step hash writes.
///
/// # Errors
/// A value that does not encode.
pub fn encode_code_run_replay_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    crate::code_run::encode_code_run_replay_value(value, context)
}

/// A bridge call row with the fields the step hash reads; every other field is empty.
#[must_use]
pub fn bridge_call(
    seq: u64,
    effect: SelfEffect,
    request: Value,
    outcome: Value,
    rewritten_request: Option<Value>,
) -> CodeRunBridgeCall {
    CodeRunBridgeCall {
        seq,
        effect,
        request,
        outcome,
        started_at_ms: 0,
        finished_at_ms: 0,
        action_digest: None,
        spawn_targets: Default::default(),
        hook_view_served: false,
        rewritten_request,
    }
}

/// A late-credit receipt's key.
#[must_use]
pub fn late_credit_receipt_id(attempt: &str, outcome: &str, axis: &str) -> String {
    crate::skill_attribution::receipt_id_for_test(attempt, outcome, axis)
}
