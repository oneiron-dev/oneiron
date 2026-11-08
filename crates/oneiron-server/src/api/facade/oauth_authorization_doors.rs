//! The host door of the owner's answer to an outside app's OAuth sign-in request (FIX 4902):
//! `vault.oauth.authorization.answer`, the one-tap actions of the inbox ask `/oauth/authorize`
//! sent him. `host_doors` re-exports it, so the generated HTTP facade handler and the MCP
//! dispatcher call it by the name every host door has, and a tool call, a code-mode call and an
//! SDK call meet one admission: the vault owner's proof, as `/v1/owner` takes it, never a
//! person's or an agent's. The engine door rechecks that proof in each writer and records his
//! acts with `surface`, where his say-so reached this install (`host_door_surface`). An allow
//! lists the agent grant it minted (`host_door_lists`).
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::task_verb::sdk::{self, OAuthAuthorizationAnswer, OAuthAuthorizationAnswered};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.oauth.authorization.answer`: the owner allows or denies one pending sign-in request,
/// listing the agent grant an allow minted.
pub(crate) async fn vault_oauth_authorization_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: OAuthAuthorizationAnswer,
) -> Listed<OAuthAuthorizationAnswered> {
    as_owner_naming(
        server,
        auth,
        "vault.oauth.authorization.answer",
        move |server, owner| {
            sdk::answer_oauth_authorization_as(server.vault(), owner, surface, input)
        },
        |answered| answered.grant_ref.into_iter().collect(),
    )
    .await
}
