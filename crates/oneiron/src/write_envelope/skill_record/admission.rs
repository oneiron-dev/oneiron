//! Pure runtime admission invariant over one stored skill record.

use oneiron_contracts::claim::ClaimApprovalStatus;
use super::{SkillLifecycle, SkillRecord};

/// The one runtime admission invariant used by the load door and hub installs.
#[must_use]
pub(crate) fn skill_loadable(record: &SkillRecord) -> bool {
    record.lifecycle_status == SkillLifecycle::Active
        && matches!(
            record.approval_status,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
}
