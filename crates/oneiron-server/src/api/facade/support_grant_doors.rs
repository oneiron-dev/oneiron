//! The host doors of the owner's support grant rows (OF-606):
//! `vault.support_grants.mint`, `.list` and `.revoke`. `host_doors`
//! re-exports them, so the generated HTTP facade handler and the MCP
//! dispatcher call them by the name every host door has, and a tool call, a
//! code-mode call and an SDK call meet one admission: the vault owner's
//! proof, as `/v1/owner/support-grants/*` takes it (`owner_routes::owner`),
//! a managed customer's included and never a hosted operator's root. A
//! support credential is never the owner's, so it never passes, its own
//! grant included. The engine rechecks the proof in its own transaction;
//! mint and revoke sign with the host's slip issuer, the one
//! `api/pairing.rs` builds for its own slip doors, after that recheck.
//!
//! Each lists its rows (`host_door_lists`): the support PERSON each grant it
//! answers names. The grant itself is the authority log's signed slip,
//! which holds no row.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    self, SupportGrantList, SupportGrantListRequest, SupportGrantMintAnswer,
    SupportGrantMintRequest, SupportGrantRevokeAnswer, SupportGrantRevokeRequest,
};

use super::host_doors::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.support_grants.mint`: the owner mints our support person or agent
/// a time-limited, revocable grant, bound to that party's own key.
pub(crate) async fn vault_support_grants_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SupportGrantMintRequest,
) -> Listed<SupportGrantMintAnswer> {
    const VERB: &str = "vault.support_grants.mint";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || -> MemoryResult<SupportGrantMintAnswer> {
        crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(sdk::mint_support_grant_as(
                server.vault(),
                &owner,
                issuer,
                input,
            ))
        })
        .map_err(|_| internal(VERB))?
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let rows = answer
        .as_ref()
        .map_or_else(|_| Vec::new(), |minted| vec![minted.grant.holder]);
    (answer, rows)
}

/// `vault.support_grants.list`: the vault's support grants, newest first.
pub(crate) async fn vault_support_grants_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SupportGrantListRequest,
) -> Listed<SupportGrantList> {
    const VERB: &str = "vault.support_grants.list";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || {
        sdk::list_support_grants_as(server.vault(), &owner, input)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let rows: Vec<EntityId> = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |list| list.grants.iter().map(|grant| grant.holder).collect(),
    );
    (answer, rows)
}

/// `vault.support_grants.revoke`: the owner revokes one support grant; what
/// support already read is not recalled.
pub(crate) async fn vault_support_grants_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SupportGrantRevokeRequest,
) -> Listed<SupportGrantRevokeAnswer> {
    const VERB: &str = "vault.support_grants.revoke";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || -> MemoryResult<SupportGrantRevokeAnswer> {
        crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(sdk::revoke_support_grant_as(
                server.vault(),
                &owner,
                issuer,
                input,
            ))
        })
        .map_err(|_| internal(VERB))?
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let rows = answer
        .as_ref()
        .map_or_else(|_| Vec::new(), |revoked| vec![revoked.holder]);
    (answer, rows)
}
