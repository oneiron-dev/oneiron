//! Legacy owner-auth gate and scoped-read constructors for both auth flavors.

use crate::auth::CoreAuth;
use crate::auth::require_owner_auth;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::http::{HeaderMap, request::Parts};
use oneiron::claim::CallerLocality;
use oneiron::runtime_hooks::verb::{VerbAskCredentialSource, VerbAskInstrument};

/// Gates the legacy `/api/*` routes on an owner-grade bearer, from the
/// request's headers alone.
///
/// These routes read the whole vault under one actor ref, so they stay a
/// trust-root surface: scoped `/v1` delegation tokens do not reach them.
/// On a managed vault a request with no slip is anonymous and refused, and
/// a caller's own forwarded slip keeps its own grade: a narrower one is
/// refused, named, never served as the host (WILL-PLAN L14 row 01). A slip
/// the host holds never passes there: a managed vault's host acts as nobody
/// (FIX 2222), and operator help on it goes through the owner's support
/// grants (FIX 4408). It never names a managed vault's attested owner: a
/// door that may take him asks [`check_request_auth`].
pub(super) fn check_api_auth(
    headers: &HeaderMap,
    server: &SyncServer,
) -> Result<CoreAuth, ApiError> {
    if server.managed_issuer.is_some() {
        let auth = CoreAuth::for_server(headers, server)?;
        if auth.is_host_holder() {
            return Err(super::host_action::host_action_refusal(
                oneiron::Error::HostActionRequiresSupportGrant,
            ));
        }
        if !auth.is_owner_grade() {
            return Err(crate::auth::caller_slip_too_narrow("this legacy door"));
        }
        return Ok(auth);
    }
    require_owner_auth(headers, &server.config, server.vault().as_ref())
}

/// [`check_api_auth`] for a door a managed vault's supervisor may attest the
/// owner on (WILL-PLAN L14 row 01): on a managed vault the caller is the
/// request's one caller ([`CoreAuth::for_managed_request`]), its own slip,
/// else the attested owner while the vault records him as its live owner,
/// at owner grade; a request with neither is anonymous and refused, never
/// the host's root (FIX 2222). Elsewhere it is the owner-grade credential
/// the headers carry.
pub(super) fn check_request_auth(parts: &Parts, server: &SyncServer) -> Result<CoreAuth, ApiError> {
    let Some(auth) = managed_request_caller(parts, server) else {
        return require_owner_auth(&parts.headers, &server.config, server.vault().as_ref());
    };
    let auth = auth?;
    if !auth.is_owner_grade() {
        return Err(crate::auth::caller_slip_too_narrow("this legacy door"));
    }
    require_live_managed_owner(server, &auth)?;
    Ok(auth)
}

/// [`CoreAuth::for_managed_request`] for the request `parts` name.
fn managed_request_caller(
    parts: &Parts,
    server: &SyncServer,
) -> Option<Result<CoreAuth, ApiError>> {
    CoreAuth::for_managed_request(
        &parts.headers,
        &parts.extensions,
        crate::auth::request_path(parts),
        server,
    )
}

/// A managed vault's attested owner stands only while the vault records the
/// holder as its live owner (`owner_routes::managed_owner_proof`); every
/// other caller passes. Refused as the owner door refuses, told to sign in
/// again (FIX 5327).
pub(crate) fn require_live_managed_owner(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<(), ApiError> {
    let Some(holder) = auth.managed_owner() else {
        return Ok(());
    };
    super::owner_routes::managed_owner_proof(server, holder)?
        .map(drop)
        .ok_or_else(ApiError::managed_owner_not_live)
}

/// [`check_request_auth`] for an OWNER ACT door (FIX 2222): the grade it
/// authenticates, then the owner-act admission
/// ([`super::host_action::require_host_owner_act`]) before the door reads,
/// writes or answers anything. On a self-hosted vault the host root and the
/// dev mode act as the owner; a hosted operator's root gets the typed 403
/// (`required_scope: support_grant`). A ROOT ADMIN door keeps
/// [`check_request_auth`] alone.
pub(super) fn check_request_owner_act(
    parts: &Parts,
    server: &SyncServer,
) -> Result<CoreAuth, ApiError> {
    let auth = check_request_auth(parts, server)?;
    super::host_action::require_host_owner_act(server, &auth)?;
    Ok(auth)
}

/// `/api/search_text`'s gate (FIX 3604): whatever [`check_request_owner_act`]
/// admits, and also a verified slip that holds core read. Such a slip reads
/// its local page under its own key ([`scoped_read_for_legacy_api`]) and asks
/// the home with its forwarded proof. A scoped credential that verifies no
/// slip stays out, because the legacy read lane reads it as the host root. A
/// search is an owner act: a hosted operator's root is refused (FIX 2222), and
/// a scoped slip keeps its own key.
pub(super) fn check_search_text_auth(
    parts: &Parts,
    server: &SyncServer,
) -> Result<CoreAuth, ApiError> {
    let refused = match check_request_owner_act(parts, server) {
        Ok(auth) => return Ok(auth),
        Err(refused) => refused,
    };
    // The same one caller: an attested owner the gate refused is never read
    // again as the host's root.
    let auth = match managed_request_caller(parts, server) {
        Some(auth) => auth?,
        None => CoreAuth::for_server(&parts.headers, server)?,
    };
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
    if let Some(auth) = auth {
        // Only this host verifies the credential again, so a verb hook's
        // settlement never runs this caller's call without it.
        memory = memory.for_credential();
        // The machine the request's connection proved rides beside the
        // locality a door reads at, so an off-device read is judged for that
        // machine, not an unknown one (mesh PR2b). It names nothing on this
        // device, and nothing when no proof stood.
        let proved = oneiron::settings::ReadDestination::proved(auth.peer());
        memory = memory.for_destination(&proved);
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
/// resolver names; a hosted operator's root is refused (FIX 2222). A managed
/// vault's attested owner reads with his own key, held to this request's
/// owner proof ([`managed_owner_read_key`]).
pub(crate) fn scoped_read_for_core_auth<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let Some(action) = super::host_action::host_action_of(vault, auth) {
        let action = action.map_err(super::host_action::host_action_refusal)?;
        return Ok(vault.scoped_read(action.read_key().for_destination(&auth.destination())));
    }
    if let Some(key) = managed_owner_read_key(vault, auth) {
        return Ok(vault.scoped_read(key?));
    }
    if let Some(proof) = auth.verified_slip() {
        let key = credential_read_key(vault, proof)?;
        return Ok(vault.scoped_read(key.for_destination(&auth.destination())));
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
    Ok(vault.scoped_read(key.for_destination(&auth.destination())))
}

/// The legacy read lane for the credential [`check_api_auth`] admitted, where
/// its connection sits. A verified slip reads under its own key, through the
/// one builder, so an agent's full-scope slip reads a relationship's rows here
/// only on a grant, as on `/v1`, and every read checks that slip's liveness.
/// The host root's slip reads as the owner on a self-hosted vault and is
/// refused on a hosted one (FIX 2222). A managed vault's attested owner reads
/// with his own guarded key ([`managed_owner_read_key`]). Any other credential
/// that verifies no slip reads only as the explicit local dev mode, with the
/// owner's key, which a managed vault never has
/// ([`scoped_read_for_host_root`]); no other slip-less caller is taken for the
/// host root.
pub(super) fn scoped_read_for_legacy_api<'a>(
    server: &'a SyncServer,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    if let Some(proof) = auth.verified_slip() {
        let vault = server.vault().as_ref();
        let key = credential_read_key(vault, proof)?;
        return Ok(vault.scoped_read(key.for_destination(&auth.destination())));
    }
    if let Some(key) = managed_owner_read_key(server.vault(), auth) {
        return Ok(server.vault().scoped_read(key?));
    }
    if !auth.is_local_dev_hatch() {
        return Err(ApiError::forbidden_scope("owner"));
    }
    scoped_read_for_host_root(server, auth.locality())
}

/// The read key of a managed vault's attested owner (`ManagedOwnerAction`),
/// as the facade's owner binding builds it: the recorded owner the holder
/// names, while that owner is live, reads with his own key held to this
/// request's owner proof, at the caller's locality, so every read proves the
/// owner again in its own snapshot. `None` for any other caller. An attested
/// holder the vault does not record as its live owner is refused, never read
/// as a plain person or as the host's root.
fn managed_owner_read_key(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
) -> Option<Result<oneiron::claim::ScopedReadActorKey, ApiError>> {
    let holder = auth.managed_owner()?;
    Some(live_owner_read_key(vault, holder).map(|key| key.for_destination(&auth.destination())))
}

/// [`managed_owner_read_key`]'s key for `holder`, before its locality.
fn live_owner_read_key(
    vault: &oneiron::Vault,
    holder: oneiron::EntityId,
) -> Result<oneiron::claim::ScopedReadActorKey, ApiError> {
    let refused = || ApiError::forbidden_scope("owner");
    let owner = vault
        .authenticate_recorded_owner(
            holder,
            &holder.to_hex(),
            oneiron::store::GateDecisionId::now(),
        )
        .map_err(|_| refused())?
        .ok_or_else(refused)?;
    if !vault.is_live_vault_owner(&owner).map_err(|_| refused())?
        || owner.actor_for_read(vault).map_err(|_| refused())? != holder
    {
        return Err(refused());
    }
    vault.owner_proof_read_key(&owner).map_err(|_| refused())
}

/// The host root's read, for a caller whose connection sits at `locality`:
/// the owner's guarded key on a self-hosted vault, the typed refusal on a
/// hosted one (FIX 2222). A managed vault has none: its request is its own
/// slip's or its attested owner's, else anonymous, and reads nothing as the
/// host or as the dev mode.
pub(super) fn scoped_read_for_host_root(
    server: &SyncServer,
    locality: CallerLocality,
) -> Result<oneiron::claim::ScopedRead<'_>, ApiError> {
    if server.managed_issuer.is_some() {
        return Err(ApiError::forbidden_scope("owner"));
    }
    let vault = server.vault().as_ref();
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
