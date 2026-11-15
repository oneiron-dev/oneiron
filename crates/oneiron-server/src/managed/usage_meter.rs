//! The usage meter a managed start binds to its hosted vault before any
//! worker starts (census L8-12; oneiron/runtime.md #provider-health: "the
//! trusted host binds before work starts"). Self-hosted serve binds its
//! vault's embedded owner (`commands::serve`); a hosted vault's meter names
//! the payer of the tenancy the supervisor started it under.

use oneiron_vault_contract::tenancy::VaultTenancy;

use crate::server::SyncServer;

/// The id a hosted vault's usage meter names: its tenancy's payer (RULING
/// HOSTED-BILLING-OWNER = A, 14 Nov; ARCH-0043 :108, RD-28: "The org account
/// pays"). An account vault's owner pays for it, and the organization pays
/// for its shared vault and for each member vault it started.
///
/// The argv carries no separate "included" mark, so a member vault started
/// under an organization is one that organization included. The control
/// plane must therefore start a personal vault the organization did not
/// include as `Account { owner }`, never as `OrganizationMember`: such a
/// vault "is not on the org invoice" (RD-28). FIX-LIST
/// [HOSTED-METER-UNINCLUDED-MEMBER-VAULT] pins that in oneiron-cloud's
/// provisioning.
pub(crate) fn billing_owner(tenancy: VaultTenancy) -> [u8; 32] {
    match tenancy {
        VaultTenancy::Account { owner } => owner,
        VaultTenancy::OrganizationShared { organization }
        | VaultTenancy::OrganizationMember { organization, .. } => organization,
    }
}

/// Binds `server`'s usage meter to `tenancy`'s payer ([`billing_owner`]),
/// as the 32-byte id in lowercase hex. Call it on the built server before
/// any worker starts, so every admitted call is attributed. A failed bind (a
/// vault whose authority log has no genesis yet) leaves this start
/// unmetered, as self-hosted serve's does; the next start binds it again.
pub(crate) fn bind_tenancy_usage_metering(server: &SyncServer, tenancy: VaultTenancy) {
    let owner = oneiron_contracts::entity_id::bytes_to_hex_lower(&billing_owner(tenancy));
    if let Err(error) = server.bind_usage_metering(owner) {
        tracing::warn!(
            %error,
            "usage is not metered on this managed start; the next start binds it again"
        );
    }
}
