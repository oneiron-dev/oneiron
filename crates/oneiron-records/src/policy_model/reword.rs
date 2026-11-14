//! Moved from `crates/oneiron/src/policy_model/reword.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::binding::PolicyContentBinding;
use serde::Deserialize;
use serde::Serialize;

/// The owner-authored constraint disclosed to the author and the reader. The
/// author generates a new candidate in their own voice and submits it through
/// the same classify/enforce door. No retry bypasses the current policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRewordRequest {
    pub row_ref: String,
    pub constraint: String,
    pub why: Option<String>,
    pub rejected_binding: PolicyContentBinding,
}
