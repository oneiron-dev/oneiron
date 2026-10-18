//! Legacy owner-auth gate and scoped-read constructors for both auth flavors.

use crate::auth::CoreAuth;
use crate::auth::require_owner_auth;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::http::HeaderMap;
use oneiron::claim::CallerLocality;
use oneiron::runtime_hooks::verb::{VerbAskCredentialSource, VerbAskInstrument};

/// Gates the legacy `/api/*` routes on an owner-grade bearer.
///
/// These routes read the whole vault under one actor ref, so they stay a
/// trust-root surface: scoped `/v1` delegation tokens do not reach them.
pub(super) fn check_api_auth(
    headers: &HeaderMap,
    server: &SyncServer,
) -> Result<CoreAuth, ApiError> {
    if server.managed_issuer.is_some() {
        return CoreAuth::for_server(headers, server);
    }
    require_owner_auth(headers, &server.config, server.vault().as_ref())
}

/// [`check_api_auth`] for an OWNER ACT door (FIX 2222): the grade it
/// authenticates, then the owner-act admission
/// ([`super::host_action::require_host_owner_act`]) before the door reads,
/// writes or answers anything. On a self-hosted vault the host root and the
/// dev mode act as the owner; a hosted operator's root gets the typed 403
/// (`required_scope: support_grant`). A ROOT ADMIN door keeps
/// [`check_api_auth`] alone.
pub(super) fn check_api_owner_act(
    headers: &HeaderMap,
    server: &SyncServer,
) -> Result<CoreAuth, ApiError> {
    let auth = check_api_auth(headers, server)?;
    super::host_action::require_host_owner_act(server, &auth)?;
    Ok(auth)
}

/// `/api/search_text`'s gate (FIX 3604): whatever [`check_api_auth`] admits,
/// and also a verified slip that holds core read. Such a slip reads its local
/// page under its own key ([`scoped_read_for_legacy_api`]) and asks the home
/// with its forwarded proof. A scoped credential that verifies no slip stays
/// out, because the legacy read lane reads it as the host root. A search is
/// an owner act: a hosted operator's root is refused (FIX 2222), and a
/// scoped slip keeps its own key.
pub(super) fn check_search_text_auth(
    headers: &HeaderMap,
    server: &SyncServer,
) -> Result<CoreAuth, ApiError> {
    let refused = match check_api_owner_act(headers, server) {
        Ok(auth) => return Ok(auth),
        Err(refused) => refused,
    };
    let auth = CoreAuth::for_server(headers, server)?;
    if auth.verified_slip().is_none() {
        return Err(refused);
    }
    auth.require(crate::auth::CoreScope::Read)?;
    super::host_action::require_host_owner_act(server, &auth)?;
    Ok(auth)
}

/// The read key a verified credential reads under on every `/v1` door. It is
/// the engine's one builder, the one the facade's read lane uses: the owner's
/// live full credential reads as the owner, and any other holder needs a live
/// grant for relationship data. A credential that grants no read is refused.
pub(crate) fn credential_read_key(
    vault: &oneiron::Vault,
    proof: &oneiron::authority::VerifiedSlip,
) -> Result<oneiron::claim::ScopedReadActorKey, ApiError> {
    vault
        .credential_read_key(proof)
        .map_err(|error| super::core_engine_error("credential read key failed", error))?
        .ok_or_else(ApiError::unauthorized)
}

/// A facade handle that reads as `auth`'s credential does: a verified slip
/// binds the handle's reads to the same credential key, so a narrower
/// credential stays bounded by it. A caller with no slip keeps the handle's
/// own lane.
/// Every handle here is a transport caller's, slip or none, and carries the
/// slip the request was admitted on into the work it queues, and that
/// slip's exact instrument, which a door that can run the call again names
/// in a verb hook's ask (ARCH-0080 §3 Ask).
/// It acts inside the off-record session the request names, bound to the
/// principal its credential names (OF-063, FIX 1668): host doors, the
/// context board and every other door that builds its handle here. A
/// credential that names no principal binds no session (FIX 2271).
/// A self-hosted root, or the explicit local dev mode, on the owner's own
/// handle reads under the host action the one resolver names (FIX 2222):
/// the owner's guarded key, proved again in each read's snapshot, never the
/// root's proof on a person's handle. A hosted operator's root resolves no
/// action, so its proof binds the handle and reads nothing.
pub(crate) fn credential_memory<'a>(
    vault: &'a oneiron::Vault,
    auth: Option<&CoreAuth>,
    actor: oneiron::EntityId,
    class: oneiron::EdgeActorClass,
) -> oneiron::memory::Memory<'a> {
    let memory = transport_memory(vault, auth, actor, class);
    let action = auth
        .and_then(|auth| super::host_action::host_action_of(vault, auth))
        .and_then(Result::ok);
    let memory = match action {
        Some(action) => match memory.with_host_action_authority(&action) {
            Ok(memory) => return memory,
            // Another actor's handle (a hook's host actor): the credential's
            // own proof binds it, as for any other caller.
            Err(_) => transport_memory(vault, auth, actor, class),
        },
        None => memory,
    };
    match auth.and_then(CoreAuth::verified_slip) {
        Some(proof) => memory.with_read_proof(proof),
        None => memory,
    }
}

/// [`credential_memory`]'s handle before its read binding: the transport
/// invocation, the request's slip and instrument, and its off-record session.
fn transport_memory<'a>(
    vault: &'a oneiron::Vault,
    auth: Option<&CoreAuth>,
    actor: oneiron::EntityId,
    class: oneiron::EdgeActorClass,
) -> oneiron::memory::Memory<'a> {
    let mut memory = vault.memory(actor, class).with_transport_invocation();
    if let Some(binding) = auth.and_then(CoreAuth::invocation_slip) {
        memory = memory.with_invocation_slip(binding);
    }
    if let Some(instrument) = auth.and_then(verb_ask_instrument) {
        memory = memory.with_credential_instrument(instrument);
    }
    if auth.is_some() {
        // Only this host verifies the credential again, so a verb hook's
        // settlement never runs this caller's call without it.
        memory = memory.for_credential();
    }
    if let Some(auth) = auth
        && let Some(session) = auth.off_record_session()
        && super::call_receipt::request_principal(auth).is_some()
    {
        memory = memory.in_off_record_session(session);
    }
    memory
}

/// An MCP caller's handle: [`credential_memory`]'s, inside the off-record
/// session its request names whenever its call binds that session for a
/// principal (`call_receipt::mcp_session_principal`, OF-063, FIX 2271): the
/// one its credential names, or, for the configured root, the host-registered
/// actor it acts through. A verified slip that names no principal binds
/// none. Its call receipt reads the same principal, so a reference refusal
/// or an unlinked prose link its rows make inside an anonymous session it
/// entered keeps no receipt, as the call keeps none. HTTP callers keep
/// [`credential_memory`]'s own rule.
pub(crate) fn mcp_credential_memory<'a>(
    vault: &'a oneiron::Vault,
    auth: Option<&CoreAuth>,
    actor: oneiron::EntityId,
    class: oneiron::EdgeActorClass,
) -> oneiron::memory::Memory<'a> {
    let memory = credential_memory(vault, auth, actor, class);
    match auth.and_then(CoreAuth::off_record_session) {
        Some(session) if super::call_receipt::mcp_session_principal(auth, actor).is_some() => {
            memory.in_off_record_session(session)
        }
        _ => memory,
    }
}

/// The exact instrument a verified slip's request was admitted on, as a
/// verb hook's ask names it: only a slip whose request kept its instrument
/// for queued work has one, so the host can verify it again.
fn verb_ask_instrument(auth: &CoreAuth) -> Option<VerbAskInstrument> {
    auth.invocation_slip()?;
    let claims = auth.verified_slip()?.claims();
    Some(VerbAskInstrument {
        source: VerbAskCredentialSource::Slip,
        vault: claims.vault_id,
        slip: claims.slip_id,
        fingerprint: auth.instrument()?,
        ceiling: auth.authority_ceiling(),
    })
}

/// The read `auth` makes, where its connection sits: a caller off this
/// device reads no device-local world (DEC-0005). A self-hosted root, or the
/// explicit local dev mode, reads with the owner's guarded key the one
/// resolver names; a hosted operator's root is refused (FIX 2222).
pub(crate) fn scoped_read_for_core_auth<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let Some(action) = super::host_action::host_action_of(vault, auth) {
        let action = action.map_err(super::host_action::host_action_refusal)?;
        return Ok(vault.scoped_read(action.read_key().at(auth.locality())));
    }
    if let Some(proof) = auth.verified_slip() {
        return Ok(vault.scoped_read(credential_read_key(vault, proof)?.at(auth.locality())));
    }
    let actor_ref = auth.principal_ref().unwrap_or(auth.principal());
    let mut key = oneiron::claim::ScopedReadActorKey::new(actor_ref)
        .ok_or_else(|| ApiError::internal_server_error("scoped read actor key is empty"))?;
    if !auth.is_owner_grade() {
        key = key.require_access_grants(
            auth.principal_ref()
                .and_then(|id| oneiron::EntityId::from_hex(id).ok()),
        );
    }
    Ok(vault.scoped_read(key.at(auth.locality())))
}

/// The legacy read lane for the credential [`check_api_auth`] admitted, where
/// its connection sits. A verified slip reads under its own key, through the
/// one builder, so an agent's full-scope slip reads a relationship's rows here
/// only on a grant, as on `/v1`, and every read checks that slip's liveness.
/// The host root's slip reads as the owner on a self-hosted vault and is
/// refused on a hosted one (FIX 2222). A credential that verifies no slip
/// reads only as the explicit local dev mode, with the owner's key; no other
/// slip-less caller is taken for the host root.
pub(super) fn scoped_read_for_legacy_api<'a>(
    server: &'a SyncServer,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let Some(proof) = auth.verified_slip() {
        let vault = server.vault().as_ref();
        return Ok(vault.scoped_read(credential_read_key(vault, proof)?.at(auth.locality())));
    }
    if !auth.is_local_dev_hatch() {
        return Err(ApiError::forbidden_scope("owner"));
    }
    scoped_read_for_host_root(server, auth.locality())
}

/// The host root's read, for a caller whose connection sits at `locality`:
/// the owner's guarded key on a self-hosted vault, the typed refusal on a
/// hosted one (FIX 2222).
pub(super) fn scoped_read_for_host_root(
    server: &SyncServer,
    locality: CallerLocality,
) -> Result<oneiron::claim::ScopedRead<'_>, ApiError> {
    let vault = server.vault().as_ref();
    if let Some(issuer) = server.managed_issuer.as_ref() {
        let proof = vault
            .verified_host_root_slip(issuer)
            .map_err(|_| ApiError::unauthorized())?;
        return Ok(vault.scoped_read(credential_read_key(vault, &proof)?.at(locality)));
    }
    if let Some(secret) = server.config.auth_secret.as_deref() {
        let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())
            .map_err(|_| ApiError::unauthorized())?;
        let proof = vault
            .verified_host_root_slip(&issuer)
            .map_err(|_| ApiError::unauthorized())?;
        return Ok(vault.scoped_read(credential_read_key(vault, &proof)?.at(locality)));
    }
    // Explicit dev mode is not a production root-slip factory: it reads as
    // the owner its host action names, with that owner's guarded key, never
    // as a string actor (FIX 2222).
    let action = vault
        .dev_action_authority()
        .map_err(super::host_action::host_action_refusal)?;
    Ok(vault.scoped_read(action.read_key().at(locality)))
}
