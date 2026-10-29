//! The host doors of the owner's custody rows (WILL L04 row 04, FIX 4993):
//! `vault.secrets.register`, `vault.secrets.rotate`, `vault.secrets.rewrap`,
//! `vault.secrets.revoke`, `vault.secrets.custody.get` and
//! `vault.secrets.custody.submit`.
//! `host_doors` re-exports them, so the generated HTTP facade handler and
//! the MCP dispatcher call them by the name every host door has. Each takes
//! the vault owner's proof as `/v1/owner` takes it (`owner_routes::owner`),
//! as `door_admits` already did before any hook ran, and the engine door
//! checks the owner again in its own transaction. Each runs the engine door
//! its `/v1/owner/secrets/*` route runs. Custody lives in side tables and
//! the authority log, which hold no row, so each door lists none.

use std::sync::Arc;

use oneiron::Vault;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    SecretCustodyGetRequest, SecretCustodyReply, SecretCustodySubmitRequest,
    SecretCustodyViewReply, SecretRegisterReply, SecretRegisterRequest, SecretRevokeReply,
    SecretRevokeRequest, SecretRewrapRequest, SecretRotateReply, SecretRotateRequest,
    register_secret_as, revoke_secret_as, rewrap_secret_as, rotate_secret_as,
    secret_custody_get_as, submit_sealed_custody_as,
};

use super::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Runs `act` off the runtime as the vault owner `auth` proves for `verb`.
async fn as_custody_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Vault, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || act(server.vault(), &owner))
        .await
        .unwrap_or_else(|_| Err(internal(verb)));
    (answer, Vec::new())
}

/// `vault.secrets.register`: the value is the owner's explicit plaintext
/// choice; the row keeps no call receipt of it.
pub(crate) async fn vault_secrets_register(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: SecretRegisterRequest,
) -> Listed<SecretRegisterReply> {
    // A wiped HTTP body's value, put back after the redacted args decoded
    // (FIX 11442). Any other transport's input already carries its own.
    let mut input = input;
    if let Some(secret) = super::secret_body::current_secret() {
        input.value_base64 = (*secret).clone();
    }
    as_custody_owner(
        server,
        auth,
        "vault.secrets.register",
        move |vault, owner| register_secret_as(vault, owner, surface, input),
    )
    .await
}

/// `vault.secrets.rotate`: as register, for the new value.
pub(crate) async fn vault_secrets_rotate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: SecretRotateRequest,
) -> Listed<SecretRotateReply> {
    // A wiped HTTP body's value, put back after the redacted args decoded
    // (FIX 11442). Any other transport's input already carries its own.
    let mut input = input;
    if let Some(secret) = super::secret_body::current_secret() {
        input.value_base64 = (*secret).clone();
    }
    as_custody_owner(server, auth, "vault.secrets.rotate", move |vault, owner| {
        rotate_secret_as(vault, owner, surface, input)
    })
    .await
}

/// `vault.secrets.rewrap`: no value travels.
pub(crate) async fn vault_secrets_rewrap(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: SecretRewrapRequest,
) -> Listed<SecretCustodyReply> {
    as_custody_owner(server, auth, "vault.secrets.rewrap", move |vault, owner| {
        rewrap_secret_as(vault, owner, surface, input)
    })
    .await
}

/// `vault.secrets.revoke`: the record goes terminal; no value travels.
pub(crate) async fn vault_secrets_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: SecretRevokeRequest,
) -> Listed<SecretRevokeReply> {
    as_custody_owner(server, auth, "vault.secrets.revoke", move |vault, owner| {
        revoke_secret_as(vault, owner, surface, input)
    })
    .await
}

/// `vault.secrets.custody.get`: the value-free view a surface seals under.
pub(crate) async fn vault_secrets_custody_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SecretCustodyGetRequest,
) -> Listed<SecretCustodyViewReply> {
    as_custody_owner(
        server,
        auth,
        "vault.secrets.custody.get",
        move |vault, owner| secret_custody_get_as(vault, owner, input),
    )
    .await
}

/// `vault.secrets.custody.submit`: this install sees only the ciphertext;
/// the row keeps no call receipt of it.
pub(crate) async fn vault_secrets_custody_submit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: SecretCustodySubmitRequest,
) -> Listed<SecretCustodyReply> {
    // A wiped HTTP body's sealed input, put back after the redacted args
    // decoded (FIX 11668). Any other transport's input already carries its own.
    let mut input = input;
    if let Some(secret) = super::secret_body::current_secret() {
        input.input_base64 = (*secret).clone();
    }
    as_custody_owner(
        server,
        auth,
        "vault.secrets.custody.submit",
        move |vault, owner| submit_sealed_custody_as(vault, owner, surface, input),
    )
    .await
}
