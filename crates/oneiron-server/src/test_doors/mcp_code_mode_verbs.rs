//! Door for `tests/code_mode_host_verb_refusals.rs`: the code-mode host-verb
//! path as a run's guest calls it, without a QuickJS host, a model, or a
//! guest. `call_verb` drives the composed production path
//! (`McpCodeModeVerbs`, which runs the binding admission, the credential gate
//! and the run-guest admission in that order); the gate-level fns stay only
//! where they add what the composed answer drops (the two gateway messages)
//! or stop where the composed call must not go (the control, past whose
//! admission a real guest would start).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap, HeaderName, HeaderValue};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, holder_proof};
use oneiron::code_run::{AgentVerbDoor, SelfAgentVerbCall};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::InvocationId;
use oneiron::test_doors::host_write_origin::host_write_origin;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use oneiron_vault_contract::BINDING_HEADER;
use serde_json::Value;

use crate::api::{
    McpCallContext, McpCodeModeVerbs, RunGuests, mcp_admit_host_verb, mcp_host_verb_gate,
    resolve_mcp_gateway_actor,
};
use crate::mcp::{McpConnectorActorRecord, McpConnectorScope, McpSurfaceMode};
use crate::server::SyncServer;

/// A registered MCP connector credential: its presented slip token, its
/// holder key, and the person actor the slip names. Minted on the test vault
/// and registered in the server's MCP registry.
pub struct TestCredential {
    token: String,
    key: SigningKey,
    actor: EntityId,
}

/// One host-verb gate's refusal, as the gateway typed it: its code and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostVerbRefusal {
    /// The stable refusal code (`mcp_verb_not_bound`, `mcp_auth_required`).
    pub code: String,
    /// The gateway's message for the code.
    pub message: String,
}

/// One composed call's refusal, as the run's guest sees it: its code, and
/// the hook notice beside it. The guest layer carries no message
/// (`AgentVerbRefusal` has no message field), so there is no message to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRefusal {
    /// The stable refusal code (`mcp_verb_not_bound`, `mcp_auth_required`,
    /// `browser_pack_not_installed`, `browser_connection_unchecked`,
    /// `browser_unbound`).
    pub code: String,
    /// The host-side hook notice, always none on this path.
    pub hook_notice: Option<Value>,
}

/// Registers a connector credential for a fresh person actor on `server`: a
/// holder-bound slip with `scope_verbs` (`read`, `write`) on a vault-wide
/// scope, narrowed to `bound_verbs` (`None` binds every tool), as
/// `register_bound_verb_mcp_actor` registers it, and returns what the
/// credential presents. The actor is kept for the call's write origin.
///
/// # Errors
///
/// Vault writes, slip minting, and registry errors.
pub async fn register_credential(
    server: &SyncServer,
    holder_seed: u8,
    scope_verbs: &[&str],
    bound_verbs: Option<&[&'static str]>,
) -> anyhow::Result<TestCredential> {
    let vault = server.vault();
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"code-mode door actor",
    )?;
    let key = SigningKey::from_bytes(&[holder_seed; 32]);
    let issuer = vault.load_host_slip_issuer()?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    claims.slip_id = [holder_seed; 32];
    claims.parent_id = None;
    claims.holder_ref = actor.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(scope_verbs.iter().map(ToString::to_string).collect());
    claims.records = BTreeSet::new();
    let token = vault.mint_capability_slip(&issuer, claims)?.to_token()?;
    let record = McpConnectorActorRecord::new(
        actor,
        EdgeActorClass::Human,
        McpConnectorScope::vault_wide(),
    );
    let record = match bound_verbs {
        Some(bound) => record.with_bound_verbs(bound.iter().copied()),
        None => record,
    };
    server.mcp_registry.lock().await.register(&token, record)?;
    Ok(TestCredential { token, key, actor })
}

/// The ingress headers `credential` presents on `vault`: its bearer token plus
/// a fresh holder proof, as the MCP ingress verifies them.
///
/// # Errors
///
/// Slip parsing and proof-signing errors.
pub fn credential_headers(vault: &Vault, credential: &TestCredential) -> anyhow::Result<HeaderMap> {
    let slip = CapabilitySlip::from_token(&credential.token)?;
    let proof = holder_proof(&slip, &credential.key, vault.now_recorded_at())?;
    let token = &credential.token;
    let bearer: HeaderValue = format!("Bearer {token}").parse()?;
    let proof_value: HeaderValue = proof.to_string().parse()?;
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, bearer);
    headers.insert(HeaderName::from_static(BINDING_HEADER), proof_value);
    Ok(headers)
}

/// The verb-table row `name` names.
///
/// # Errors
///
/// Unknown verb names.
pub fn verb_row(name: &str) -> anyhow::Result<oneiron::task_verb::sdk::AgentVerb> {
    oneiron::task_verb::sdk::AgentVerb::from_name(name)
        .ok_or_else(|| anyhow::anyhow!("unknown verb-table row: {name}"))
}

/// The caller `credential` names on `server`, resolved from its presented
/// headers through the real ingress path (`resolve_mcp_gateway_actor`).
async fn resolve_context(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
) -> anyhow::Result<McpCallContext> {
    let headers = credential_headers(server.vault(), credential)?;
    resolve_mcp_gateway_actor(
        McpSurfaceMode::Primary,
        "code-mode-door",
        &headers,
        &Extensions::new(),
        oneiron::claim::CallerLocality::OnDevice,
        server,
    )
    .await
    .map_err(|error| anyhow::anyhow!("the door credential did not resolve: {error:?}"))
}

/// The composed code-mode call `verb` meets on run `run` of `server` as
/// `credential`: a `McpCodeModeVerbs` bound to the server, the resolved
/// caller and the run, driven through `AgentVerbDoor::call`, as the run's
/// guest drives it. `Ok` past every gate, the guest-visible refusal short of
/// one. The run's guest is never started on a refusal path: the guest
/// admission refuses before any hook or guest call. The call carries a null
/// input and a minted invocation: neither is read short of the guest.
///
/// # Errors
///
/// Unknown verb names, the credential failing to resolve (a test bug:
/// registration refused it), and the call stopping outside a refusal (a hook
/// stop, an unanswered model call, or an invariant: none happens on these
/// shapes on main).
pub async fn call_verb(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    verb: &str,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let context = resolve_context(server, credential).await?;
    let row = verb_row(verb)?;
    let verbs = McpCodeModeVerbs::new(server, &context, run);
    let call = SelfAgentVerbCall {
        verb: row,
        input: Value::Null,
    };
    let origin = host_write_origin(credential.actor)?;
    let outcome = verbs
        .call(&call, &origin, InvocationId::mint())
        .map_err(|error| {
            anyhow::anyhow!("the composed call stopped outside a refusal: {error:?}")
        })?;
    match outcome {
        Ok(_) => Ok(Ok(())),
        Err(refused) => Ok(Err(GuestRefusal {
            code: refused.code,
            hook_notice: refused.hook_notice,
        })),
    }
}

/// The bound-tool admission `verb` meets on `server` as `credential`
/// (`mcp_admit_host_verb`): `Ok` past it, the gateway's refusal short of it.
/// Only the message adds to what `call_verb` reports: the composed answer
/// keeps the code and drops it.
///
/// # Errors
///
/// Unknown verb names, and the credential failing to resolve (a test bug:
/// registration refused it).
pub async fn admit_host_verb(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    verb: &str,
) -> anyhow::Result<Result<(), HostVerbRefusal>> {
    let context = resolve_context(server, credential).await?;
    let row = verb_row(verb)?;
    Ok(mcp_admit_host_verb(&context, row).map_err(|error| {
        let (code, message) = error.code_and_message();
        HostVerbRefusal {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }))
}

/// The credential gate `verb` meets on `server` as `credential`
/// (`mcp_host_verb_gate`): `Ok` past it, the gateway's refusal short of it.
/// Only the message adds to what `call_verb` reports: the composed answer
/// keeps the code and drops it.
///
/// # Errors
///
/// Unknown verb names, and the credential failing to resolve (a test bug:
/// registration refused it).
pub async fn gate_host_verb(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    verb: &str,
) -> anyhow::Result<Result<(), HostVerbRefusal>> {
    let context = resolve_context(server, credential).await?;
    let row = verb_row(verb)?;
    Ok(mcp_host_verb_gate(server, &context, row).map_err(|error| {
        let (code, message) = error.code_and_message();
        HostVerbRefusal {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }))
}

/// The guest admission `verb` meets on run `run` of `server`
/// (`RunGuests::admits`): `Ok` past it, the guest layer's code-only refusal
/// short of it. For the positive control only: it stops at the admission,
/// where `call_verb` would run hooks and start a real guest. The run's guest
/// is never started.
///
/// # Errors
///
/// Unknown verb names.
pub fn admits_guest(
    server: &SyncServer,
    run: EntityId,
    verb: &str,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let row = verb_row(verb)?;
    let guests = RunGuests::new(server, run);
    Ok(guests.admits(row, server).map_err(|refused| GuestRefusal {
        code: refused.code,
        hook_notice: refused.hook_notice,
    }))
}
