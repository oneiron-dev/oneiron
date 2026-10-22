//! The host doors of `self.secrets.*` (DOOR-124, e2e SECRETS-03): an agent
//! run's secret grants, minted, renewed, torn down and used over the
//! engine's grant seam (FIX 4313). `host_doors` re-exports them, so the
//! generated HTTP facade handler and the MCP dispatcher call them by the
//! name every host door has.
//!
//! Each call is the caller's own, for the live run its host attached to this
//! credential: the door resolves exactly the attachment the call presents
//! (`live_run`), holds the run, which rechecks its lease, and makes the grant
//! holder from the credential's own verified actor and that run's leased
//! try. No caller-named actor, owner proof, tier or clock reaches the
//! engine. A T1 grant's bytes go only to the destinations the run's host
//! registered for it ([`crate::runtime::SecretDestinations`]); a run whose
//! host registered none refuses a T1 purpose by name. A use's
//! `connector.call` sends on this server's [`ServedConnectorCallHost`],
//! under the caller's own standing grant, gate and invocation, as
//! `self.use`'s does. The send happens on a blocking worker, never inside a
//! write transaction.
use std::sync::Arc;

use oneiron::code_run::live_run::LiveRunCredential;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use oneiron::outbound_consent::ConnectorCallRequest;
use oneiron::runtime_hooks::InvocationId;
use oneiron::secret_custody::SECRET_USE_CONNECTOR_CALL;
use oneiron::task_verb::sdk::{
    self, LiveRunRequest, SecretGrantMintRequest, SecretGrantRenewRequest,
    SecretGrantTeardownRequest, SecretGrantUseRequest, SecretGrantView, SecretUseAnswer,
};
use oneiron::{AttemptId, EdgeActorClass, EntityId, WriteActor};

use super::host_doors::support::{Listed, credential_listing, refused};
use crate::auth::CoreAuth;
use crate::connector_call_host::ServedConnectorCallHost;
use crate::server::{HeldLiveRun, LiveRunCaller, LiveRunRefusal, SyncServer};

/// `self.secrets.materialize`: one grant on a secret for the caller's live
/// run, to one purpose.
pub(crate) async fn self_secrets_materialize(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<SecretGrantMintRequest>,
) -> Listed<SecretGrantView> {
    let LiveRunRequest { live_run, spec } = input;
    on_live_run(
        server,
        auth,
        (caller, invocation),
        live_run,
        "self.secrets.materialize",
        move |server, memory, run| {
            let mut delivery = server.secret_destinations.delivery();
            sdk::mint_secret_grant_as_caller(memory, Some(run), spec, &mut delivery)
        },
    )
    .await
}

/// `self.secrets.renew`: a fresh grant at the secret's current generation
/// in the place of one the caller holds in its live run.
pub(crate) async fn self_secrets_renew(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<SecretGrantRenewRequest>,
) -> Listed<SecretGrantView> {
    let LiveRunRequest { live_run, spec } = input;
    on_live_run(
        server,
        auth,
        (caller, invocation),
        live_run,
        "self.secrets.renew",
        move |server, memory, run| {
            let mut delivery = server.secret_destinations.delivery();
            sdk::renew_secret_grant_as_caller(memory, Some(run), spec, &mut delivery)
        },
    )
    .await
}

/// `self.secrets.teardown`: one grant the caller holds in its live run,
/// revoked and cleaned up, whatever its state.
pub(crate) async fn self_secrets_teardown(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<SecretGrantTeardownRequest>,
) -> Listed<SecretGrantView> {
    let LiveRunRequest { live_run, spec } = input;
    on_live_run(
        server,
        auth,
        (caller, invocation),
        live_run,
        "self.secrets.teardown",
        move |server, memory, run| {
            let mut delivery = server.secret_destinations.delivery();
            sdk::teardown_secret_grant_as_caller(memory, Some(run), spec, &mut delivery)
        },
    )
    .await
}

/// `self.secrets.use`: `self.use` under a door grant the caller holds in its
/// live run. A table operation answers as the engine's grant use does;
/// `connector.call` sends one connector call with the grant redeemed at every
/// real send, on this server's connector host.
pub(crate) async fn self_secrets_use(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: LiveRunRequest<SecretGrantUseRequest>,
) -> Listed<SecretUseAnswer> {
    let LiveRunRequest { live_run, spec } = input;
    on_live_run(
        server,
        auth,
        (caller, invocation),
        live_run,
        "self.secrets.use",
        move |server, memory, run| use_grant(server, memory, run, spec),
    )
    .await
}

/// One use under a grant, for the caller `memory` is bound to, in `run`.
/// Blocking: an operation sends.
fn use_grant(
    server: &SyncServer,
    memory: &Memory<'_>,
    run: AttemptId,
    spec: SecretGrantUseRequest,
) -> MemoryResult<SecretUseAnswer> {
    let grant = sdk::secret_grant_id(&spec.grant)?;
    if spec.operation != SECRET_USE_CONNECTOR_CALL {
        return sdk::use_secret_grant_as_caller(
            memory,
            Some(run),
            &grant,
            &spec.operation,
            &spec.arguments,
        );
    }
    let request: ConnectorCallRequest = serde_json::from_value(spec.arguments).map_err(|_| {
        MemoryError::bad_request_with(
            "connector.call's arguments are one connector call",
            &[
                "Name the connector's catalog name, its tool, the tool's arguments and, for a \
                 change, its mutation, as connector.call takes them.",
            ],
        )
    })?;
    let invocation = memory
        .invocation()
        .map(|invocation| sdk::connector_call_invocation(memory.actor(), invocation))
        .transpose()
        .map_err(MemoryError::from)?;
    let mut host = ServedConnectorCallHost::new(server).map_err(MemoryError::from)?;
    sdk::use_secret_grant_for_connector_call(
        memory,
        Some(run),
        &grant,
        request,
        invocation,
        &mut host,
    )
}

/// `act` on the credential's own handle as `caller`, with the invocation its
/// call resolved, for the live run `live_run` names, held for the whole call
/// so no executor entry runs across it. Beside the answer, the rows its
/// reads listed; a refusal before the run is held lists none.
async fn on_live_run<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    (caller, invocation): ((EntityId, EdgeActorClass), Option<InvocationId>),
    live_run: String,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &Memory<'_>, AttemptId) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let (held, run) = match hold_live_run(server, auth, caller, &live_run).await {
        Ok(held) => held,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, verb, move |server, _, memory| {
        // Keep the run held until the engine call and all its writes finish.
        let _held = held;
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        act(server, &memory, run)
    })
    .await
}

/// The live run `handle` names, held, and its leased try: exactly the
/// attachment this credential holds, for the run's own agent, never a
/// caller-named attempt or a replacement credential.
async fn hold_live_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    (actor, class): (EntityId, EdgeActorClass),
    handle: &str,
) -> MemoryResult<(HeldLiveRun, AttemptId)> {
    let unbound = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a secret grant's live run requires this agent's own verified credential",
            &["Present the same credential that attached to the run."],
        )
    };
    let proof = auth.verified_slip().ok_or_else(unbound)?;
    // As on attach and actions, an unbound credential borrows no run.
    server
        .vault()
        .credential_read_key(proof)?
        .ok_or_else(unbound)?;
    let resolved = server
        .live_runs
        .resolve(
            handle,
            LiveRunCaller {
                actor: WriteActor::new(actor, class),
                credential: LiveRunCredential::of(&auth.idempotency_principal(), auth.locality()),
            },
        )
        .map_err(live_refusal)?;
    let held = resolved
        .hold(&server.live_runs, &server.vault)
        .await?
        .map_err(live_refusal)?;
    Ok((held, resolved.attempt()))
}

fn live_refusal(refusal: LiveRunRefusal) -> MemoryError {
    MemoryError::new(refusal.code(), refusal.message(), &[refusal.suggestion()])
}
