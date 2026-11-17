//! Door for `tests/fingerprint_keep_imap_plan_encoder_digests.rs` (PLAN-UC-04 stage
//! 6.3e): an IMAP folder's digest, a live goal-axis plan's digest and an encoder input's
//! hash. The first two are private to their modules.

use crate::memory::extraction::EncoderInput;
use crate::skill_optimize::GoalAxisPlan;

/// The digest of an IMAP folder labelled `label`: 16 lowercase hex digits.
#[must_use]
pub fn imap_folder_digest(label: &str) -> String {
    crate::mail_pack::imap_folder_digest_for_test(label)
}

/// The digest of `plan`, as a live goal-axis row stores it.
#[must_use]
pub fn live_axis_plan_digest(plan: &GoalAxisPlan) -> String {
    crate::skill_optimize::live_axis_plan_digest_for_test(plan)
}

/// The hash of `input`, as a shadow trace stamps it.
#[must_use]
pub fn encoder_input_hash(input: &EncoderInput) -> String {
    crate::memory::extraction::hash_input(input)
}
