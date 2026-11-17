//! Door for `tests/fingerprint_keep_oneiron_json_digests.rs` (PLAN-UC-04 stage 6.4d): the
//! sorted-JSON digests of a durable model step's params, a public model step's submit and a
//! model trial's measurements, which the engine computes in private code.

use crate::LlmRequest;
use crate::llm::model_step::ModelStepSubmit;
use crate::llm::model_trials::{FrozenTrialCase, TrialMeasurement, TrialSetPin};

/// A durable model step's params identity of `request`, or `None` when its params do not
/// encode.
#[must_use]
pub fn request_params_hash(request: &LlmRequest) -> Option<String> {
    crate::llm::request_params_hash_for_test(request)
}

/// The call hash a public model step's invocation claim holds for `input`, or `None` when
/// it does not encode.
#[must_use]
pub fn submit_call_hash(input: &ModelStepSubmit) -> Option<[u8; 32]> {
    crate::llm::model_step::submit_call_hash_for_test(input)
}

/// The measurements hash of a trial with the set pin `set`, its frozen `cases` and
/// `measurements`, or `None` when they do not encode.
#[must_use]
pub fn trial_measurements_hash(
    set: &TrialSetPin,
    cases: &[FrozenTrialCase],
    measurements: &[TrialMeasurement],
) -> Option<[u8; 32]> {
    crate::llm::model_trials::trial_measurements_hash_for_test(set, cases, measurements)
}
