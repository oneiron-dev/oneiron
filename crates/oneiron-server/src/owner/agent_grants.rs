//! The serve start's backfill of default agent Grants (FIX
//! AGENT-GRANTLESS-VISIBLE; Engine RULING GRANTLESS-SHAPE Q6 = A, 12 Nov
//! 03:02). Once the server is built (this install's profile enrolled, no
//! listener or worker started), the host of a self-hosted vault acts as its
//! owner ([`super::host_owner`]) and mints each agent paired before Grants
//! its default read Grant, once per vault
//! ([`oneiron::Vault::backfill_default_agent_grants`]). Any other posture is
//! skipped and writes nothing. A refusal is logged, and the start goes on.

use oneiron::Vault;
use oneiron::federation::DefaultAgentGrantBackfill;

/// Runs the backfill at a plain serve start (module docs).
pub(crate) fn backfill_default_grants_at_start(vault: &Vault) {
    if vault.privacy_posture() != oneiron::HostingPrivacyPosture::SelfHostLocal {
        return;
    }
    match backfill(vault) {
        Ok(DefaultAgentGrantBackfill::Completed { grants }) => tracing::info!(
            minted = grants.len(),
            "the agents paired before Grants hold their default read Grants"
        ),
        Ok(
            DefaultAgentGrantBackfill::AlreadyComplete | DefaultAgentGrantBackfill::NotSelfHosted,
        ) => {}
        Err(error) => tracing::warn!(
            %error,
            "the default agent Grants were not minted at this start; the next start tries again"
        ),
    }
}

fn backfill(vault: &Vault) -> anyhow::Result<DefaultAgentGrantBackfill> {
    let owner = super::host_owner(vault)?;
    Ok(vault.backfill_default_agent_grants(&owner)?)
}
