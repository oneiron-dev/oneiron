//! Pure runtime admission invariant over one stored skill record.

use super::{SkillLifecycle, SkillRecord};
use oneiron_contracts::claim::ClaimApprovalStatus;

/// The one runtime admission invariant used by the load door and hub installs.
#[must_use]
pub fn skill_loadable(record: &SkillRecord) -> bool {
    record.lifecycle_status == SkillLifecycle::Active
        && matches!(
            record.approval_status,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
}
