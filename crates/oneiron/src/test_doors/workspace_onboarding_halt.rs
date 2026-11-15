//! A workspace onboarding stopped after a named step, for the test that
//! resumes it once the one-vault setting has turned unreadable (L7-05).
use crate::consent::AuthenticatedOwner;
use crate::workspace_roster::{
    MemberOnboardingIntent, MemberOnboardingOutcome, MemberOnboardingStep,
};
use crate::{Result, Vault, WriteActor};

/// [`Vault::onboard_workspace_member`], stopping after `halt_after`. `None`
/// leaves a journal that the next call with the same intent resumes from.
///
/// # Errors
///
/// The onboarding's.
pub fn onboard_workspace_member_halting_after(
    vault: &Vault,
    intent: MemberOnboardingIntent,
    authenticated_writer: &WriteActor,
    mailbox_owner: Option<&AuthenticatedOwner>,
    halt_after: MemberOnboardingStep,
) -> Result<Option<MemberOnboardingOutcome>> {
    vault.onboard_workspace_member_halting_after(
        intent,
        authenticated_writer,
        mailbox_owner,
        halt_after,
    )
}
