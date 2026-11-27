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
use oneiron::code_run::{
    AgentVerbDoor, RunCall, RunSpeechDestination, SelfAgentVerbCall, SelfEffect,
};
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
    /// The stable refusal code (`mcp_verb_not_bound`, `mcp_auth_required`,
    /// `mcp_grant_missing`).
    pub code: String,
    /// The gateway's message for the code.
    pub message: String,
}

/// One composed call's refusal, as the run's guest sees it: its code, the
/// hook notice beside it, and its reason codes. The guest layer carries no
/// message (`AgentVerbRefusal` has no message field), so there is no message
/// to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRefusal {
    /// The stable refusal code (`mcp_verb_not_bound`, `mcp_auth_required`,
    /// `mcp_grant_missing`, `browser_pack_not_installed`,
    /// `browser_connection_unchecked`, `browser_unbound`, `tool_args_invalid`).
    pub code: String,
    /// The host-side hook notice, always none on this path.
    pub hook_notice: Option<Value>,
    /// The refusal's stable reason codes (FIX CODE-MODE-DENIAL-REASONS).
    pub reason_codes: Vec<String>,
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
    call_verb_with_input(server, credential, run, verb, Value::Null).await
}

/// [`call_verb`] with the guest's `input` in place of a null one, as a
/// run's program passes it to the verb.
///
/// # Errors
///
/// As [`call_verb`].
pub async fn call_verb_with_input(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    verb: &str,
    input: Value,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    call_verb_written_by(
        server,
        credential,
        run,
        verb,
        input,
        ProgramAuthor::EngineModel,
    )
    .await
}

/// Who wrote the program a door's run executes (FIX EXECUTE-CALLER-CODE):
/// the caller, as the MCP `execute` tool runs the code it is given, or the
/// engine's model, as a task run's steps are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramAuthor {
    /// The caller wrote the code.
    Caller,
    /// The engine's model wrote it from the caller's task.
    EngineModel,
}

/// The door a run of `server` binds for `credential`, its program written by
/// `author`.
async fn door(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    author: ProgramAuthor,
) -> anyhow::Result<McpCodeModeVerbs> {
    let context = resolve_context(server, credential).await?;
    let verbs = McpCodeModeVerbs::new(server, &context, run);
    Ok(match author {
        ProgramAuthor::Caller => verbs.authored_by_caller(),
        ProgramAuthor::EngineModel => verbs.authored_by_engine_model(),
    })
}

/// [`call_verb_with_input`] on a run whose program `author` wrote.
///
/// # Errors
///
/// As [`call_verb`].
pub async fn call_verb_written_by(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    verb: &str,
    input: Value,
    author: ProgramAuthor,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let row = verb_row(verb)?;
    let verbs = door(server, credential, run, author).await?;
    let call = SelfAgentVerbCall { verb: row, input };
    let origin = host_write_origin(credential.actor)?;
    let outcome = verbs
        .call(&call, &origin, InvocationId::mint())
        .map_err(|error| {
            anyhow::anyhow!("the composed call stopped outside a refusal: {error:?}")
        })?;
    match outcome {
        Ok(_) => Ok(Ok(())),
        Err(refused) => Ok(Err(guest_refusal(refused))),
    }
}

/// The admission one call the run serves itself with `effect` meets on a
/// run whose program `author` wrote (`AgentVerbDoor::admit_run_call`).
///
/// # Errors
///
/// The credential failing to resolve.
pub async fn admit_run_effect(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    effect: SelfEffect,
    author: ProgramAuthor,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let verbs = door(server, credential, run, author).await?;
    Ok(verbs
        .admit_run_call(RunCall::Bridge(effect))
        .map(drop)
        .map_err(guest_refusal))
}

/// The admission of the exact run row `row` a shared-effect call was made
/// through (`AgentVerbDoor::admit_run_row`, FIX EXECUTE-CALLER-CODE).
///
/// # Errors
///
/// The credential failing to resolve.
pub async fn admit_run_row(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    row: &'static str,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let verbs = door(server, credential, run, ProgramAuthor::EngineModel).await?;
    Ok(verbs.admit_run_row(row).map_err(guest_refusal))
}

/// The admission a `self.speak` in the run's own derived conversation meets
/// on a run whose program `author` wrote (`AgentVerbDoor::admit_run_speech`).
///
/// # Errors
///
/// The credential failing to resolve.
pub async fn admit_own_run_speech(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    author: ProgramAuthor,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    admit_run_speech_as(server, credential, run, SelfEffect::Speak, author).await
}

/// The admission a speech of `effect` in the run's own derived conversation
/// meets on a run whose program `author` wrote
/// (`AgentVerbDoor::admit_run_speech`).
///
/// # Errors
///
/// The credential failing to resolve.
pub async fn admit_run_speech_as(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    effect: SelfEffect,
    author: ProgramAuthor,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let verbs = door(server, credential, run, author).await?;
    Ok(verbs
        .admit_run_speech(effect, RunSpeechDestination::OwnRunConversation)
        .map(drop)
        .map_err(guest_refusal))
}

/// The door a callable skill that `credential` calls over MCP on run `run`
/// runs its nested calls behind (FIX CODE-MODE-LENDING-W8).
async fn skill_door(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
) -> anyhow::Result<Arc<dyn AgentVerbDoor>> {
    let context = resolve_context(server, credential).await?;
    crate::api::skill_door_for_test(server, context, run)
        .map_err(|error| anyhow::anyhow!("the skill door was not built: {error:?}"))
}

/// [`call_verb_written_by`] at a callable skill's door ([`skill_door`]).
///
/// # Errors
///
/// As [`call_verb`], and the skill door not being built.
pub async fn call_skill_verb(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    verb: &str,
    input: Value,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let row = verb_row(verb)?;
    let door = skill_door(server, credential, run).await?;
    let call = SelfAgentVerbCall { verb: row, input };
    let origin = host_write_origin(credential.actor)?;
    let outcome = door
        .call(&call, &origin, InvocationId::mint())
        .map_err(|error| {
            anyhow::anyhow!("the composed call stopped outside a refusal: {error:?}")
        })?;
    match outcome {
        Ok(_) => Ok(Ok(())),
        Err(refused) => Ok(Err(guest_refusal(refused))),
    }
}

/// [`admit_run_effect`] at a callable skill's door ([`skill_door`]).
///
/// # Errors
///
/// The credential failing to resolve, and the skill door not being built.
pub async fn admit_skill_run_effect(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    effect: SelfEffect,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let door = skill_door(server, credential, run).await?;
    Ok(door
        .admit_run_call(RunCall::Bridge(effect))
        .map(drop)
        .map_err(guest_refusal))
}

/// The outer skill call's admission at a callable skill's door
/// ([`skill_door`]): `AgentVerbDoor::admit_outer_skill_call`, as the host
/// projection admits the call its caller made itself (REVIEW-10594).
///
/// # Errors
///
/// The credential failing to resolve, and the skill door not being built.
pub async fn admit_outer_skill_call(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
) -> anyhow::Result<Result<(), GuestRefusal>> {
    let door = skill_door(server, credential, run).await?;
    Ok(door
        .admit_outer_skill_call()
        .map(drop)
        .map_err(guest_refusal))
}

fn guest_refusal(refused: oneiron::code_run::AgentVerbRefusal) -> GuestRefusal {
    GuestRefusal {
        code: refused.code,
        hook_notice: refused.hook_notice,
        reason_codes: refused.reason_codes,
    }
}

/// Runs one guest claim through the MCP connector's off-record write admission.
///
/// # Errors
///
/// The connector could not be resolved or the run could not enter or dispatch.
pub async fn call_off_record_claim(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    session: &oneiron::off_record::OffRecordSession<'_>,
    folder_digest: &str,
    mut input: Value,
) -> anyhow::Result<oneiron::code_run::SelfDispatchOutcome> {
    use oneiron::code_run::{HostSelfDispatcher, SelfCall, SelfDispatcher};
    use oneiron::task_verb::sdk::AgentVerb;

    let mut context = resolve_context(server, credential).await?;
    context.session_workspace = Some(vec![folder_digest.to_owned()]);
    let actor = oneiron::WriteActor::new(credential.actor, EdgeActorClass::Human);
    let verbs = McpCodeModeVerbs::new(server, &context, EntityId::now()).authored_by_engine_model();
    let dispatcher = HostSelfDispatcher::for_off_record_session(session, actor, "room-claim")?
        .with_agent_verb_door(Arc::new(verbs));
    input["subject_ref"] = Value::String(credential.actor.to_hex());
    Ok(dispatcher.dispatch(SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::VaultClaimsUpsert,
        input,
    }))?)
}

#[cfg(feature = "code-sandbox-wasmtime")]
/// Installs the production resume check on the test's engine-stack runtime.
pub fn install_verb_ask_resume(server: &Arc<SyncServer>) {
    server.vault().install_verb_ask_credential_check(Arc::new(
        crate::credential_resume::ServerVerbAskCredentialCheck::new(
            server,
            tokio::runtime::Handle::current(),
        ),
    ));
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
        reason_codes: refused.reason_codes,
    }))
}

/// One media door's refusal, as the door typed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDoorRefusal {
    /// The stable refusal code.
    pub code: String,
    /// The door's message.
    pub message: String,
    /// The refusal's stable reason codes (`grant_required.ai.<operation>`
    /// for a Grant read as absent).
    pub reason_codes: Vec<String>,
}

/// The `ai.*` media door `verb` (`ai.options`, `ai.image`, `ai.video`,
/// `ai.video.poll` or `ai.video.cancel`) on `input`, as `credential` calls
/// it from code-mode run `run` whose program the engine's model wrote:
/// inside the run's line, which that run's verb dispatch binds (FIX 780).
/// `Ok` is the door's answer, `Err` its refusal.
///
/// # Errors
///
/// The credential failing to resolve, or resolving to no auth.
pub async fn media_call_on_run_line(
    server: &Arc<SyncServer>,
    credential: &TestCredential,
    run: EntityId,
    verb: &str,
    input: Value,
) -> anyhow::Result<Result<Value, MediaDoorRefusal>> {
    let context = resolve_context(server, credential).await?;
    let auth = context
        .actor
        .auth
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("the door credential resolved no auth"))?;
    Ok(
        crate::api::media_door_on_run_line_for_test(server, auth, run, verb, input)
            .await
            .map_err(|refusal| MediaDoorRefusal {
                code: refusal.code,
                message: refusal.message,
                reason_codes: refusal.reason_codes,
            }),
    )
}
