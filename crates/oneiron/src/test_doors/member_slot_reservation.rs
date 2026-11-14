//! An onboarding stopped right after it reserved its member's slot, before
//! its workspace is established, for `tests/companion_split.rs` (review
//! round 1 of #7656).
use crate::{MemberOnboardingIntent, MemberOnboardingStep, Result, Vault, WriteActor};

/// Runs `intent`'s onboarding through its Started step only: the member's
/// slot is reserved, and no workspace preset is published. A later
/// [`Vault::onboard_workspace_member`] with the same intent resumes it.
///
/// # Errors
///
/// The onboarding's own refusals at its Started step.
pub fn reserve_member_slot(
    vault: &Vault,
    intent: MemberOnboardingIntent,
    writer: &WriteActor,
) -> Result<()> {
    vault
        .onboard_workspace_member_halting_after(intent, writer, None, MemberOnboardingStep::Started)
        .map(|_| ())
}
