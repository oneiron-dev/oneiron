//! The saved-query plan digest, for the K-proof of PLAN-UC-04 stage 1.1
//! (`tests/fingerprint_keep_saved_query.rs`).

use crate::error::Result;
use crate::saved_query::{EVIDENCE_HASH_LEN, MembershipWritePlan};

/// The digest the membership watermark keeps for `plan`.
///
/// # Errors
///
/// The plan's encoders'.
pub fn plan_content_digest(plan: &MembershipWritePlan) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    crate::saved_query::plan_content_digest(plan)
}
