//! Typed named Admin policy/powers and the one-hop scoped Delegate mint.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use oneiron::task_verb::sdk::{
    self, FederationDelegateRequest, FederationMemberGrant, OrgAdminConfigureRequest,
    OrgAdminConfigured, OrgAdminPowers, OrgAdminPowersRequest,
};

use super::host_doors::support::{Listed, MaybeListed, credential_listing, refused};
use super::legal_hold_doors::as_owner_naming;
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

pub(crate) async fn vault_org_admin_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OrgAdminConfigureRequest,
) -> Listed<OrgAdminConfigured> {
    as_owner_naming(
        server,
        auth,
        "vault.org_admin.configure",
        move |server, owner| sdk::configure_org_admin_as_owner(server.vault(), owner, input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_org_admin_powers(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OrgAdminPowersRequest,
) -> Listed<OrgAdminPowers> {
    const VERB: &str = "vault.org_admin.powers";
    if !auth.is_owner_grade() && auth.org_ref() != Some(input.org_ref.to_hex().as_str()) {
        return refused(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "organization administration power denied",
            &["Use a credential bound to this organization."],
        ));
    }
    if let Err(refusal) = super::owner_binding::host_preflight(server, auth) {
        return refused(refusal);
    }
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "organization powers require the credential's registered principal",
                &["Present your own registered credential."],
            ));
        }
    };
    credential_listing(server, auth, caller, VERB, move |_, auth, memory| {
        let mut powers = sdk::read_org_admin_powers(&memory, input)?;
        powers
            .powers
            .retain(|power| auth.has_scope(CoreScope::OrgAdmin(*power)));
        Ok(powers)
    })
    .await
}

pub(crate) async fn vault_members_delegate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FederationDelegateRequest,
) -> MaybeListed<FederationMemberGrant> {
    const VERB: &str = "vault.members.delegate";
    let parent = input.parent_grant;
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::create_federation_delegate_as(server.vault(), &holder, input),
        move |grant| Some(vec![parent, grant.grant_ref]),
    )
    .await
}
