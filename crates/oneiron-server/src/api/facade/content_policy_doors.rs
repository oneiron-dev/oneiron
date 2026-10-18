//! Content-policy doors beside the Gate policy doors, on each caller's own credential.
use std::sync::Arc;

use oneiron::llm::{BudgetGuard, BudgetLease, LlmBackend, LlmGenerateFuture, LlmRequest, LlmStreamResult};
use oneiron::llm::manifest::ModelRole;
use oneiron::memory::{MemoryError, MemoryResult, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_OFF_RECORD_SESSION_DOOR};
use oneiron::policy_manifest_doors::{self, OwnerPolicyConfigurationReceipt, OwnerPolicyConfigurationView, OwnerPolicyConfigureRequest};
use oneiron::policy_model::doors::{self, HostedRelayDecision, PolicyOutboundRequest, PolicyRowChangeRequest};
use oneiron::policy_model::{PolicyModelEnforcement, PolicyRowReceipt, RelaySafeguardTier};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::{EdgeActorClass, EntityId, FatalLlmError, WriteActor};

use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_policy_owner_get(
    server: &Arc<SyncServer>, auth: &CoreAuth, _input: EmptyRequest,
) -> Listed<OwnerPolicyConfigurationView> {
    let owner = match owner_proof(auth, server, "vault.policy.owner.get") {
        Ok(owner) => owner, Err(error) => return refused(error),
    };
    owner_call(server, "vault.policy.owner.get", move |server| {
        policy_manifest_doors::owner_policy_configuration(server.vault(), &owner).map_err(Into::into)
    }).await
}

pub(crate) async fn vault_policy_owner_configure(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: OwnerPolicyConfigureRequest,
) -> Listed<OwnerPolicyConfigurationReceipt> {
    let owner = match owner_proof(auth, server, "vault.policy.owner.configure") {
        Ok(owner) => owner, Err(error) => return refused(error),
    };
    owner_call(server, "vault.policy.owner.configure", move |server| {
        policy_manifest_doors::configure_owner_policy(server.vault(), &owner, input).map_err(Into::into)
    }).await
}

pub(crate) async fn vault_policy_owner_row_change(
    server: &Arc<SyncServer>, auth: &CoreAuth, input: PolicyRowChangeRequest,
) -> Listed<PolicyRowReceipt> {
    let owner = match owner_proof(auth, server, "vault.policy.owner.row.change") {
        Ok(owner) => owner, Err(error) => return refused(error),
    };
    owner_call(server, "vault.policy.owner.row.change", move |server| {
        doors::change_owner_policy_row(server.vault(), &owner, input).map_err(Into::into)
    }).await
}

async fn owner_call<T: Send + 'static>(
    server: &Arc<SyncServer>, verb: &'static str,
    call: impl FnOnce(&SyncServer) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let worker = Arc::clone(server);
    let (answer, mut rows) = super::host_doors::off_runtime_listing(verb, move |_| call(&worker)).await;
    match doors::policy_manifest_sources(server.vault()) {
        Ok(sources) => { rows.extend(sources); (answer, rows) }
        Err(error) => (Err(error.into()), rows),
    }
}

pub(crate) async fn vault_policy_outbound_decide(
    server: &Arc<SyncServer>, auth: &CoreAuth, session: Option<EntityId>,
    caller: (EntityId, EdgeActorClass), _invocation: Option<InvocationId>, input: PolicyOutboundRequest,
) -> Listed<PolicyModelEnforcement> {
    if session.is_some() { return refused(off_record()); }
    let runtime = tokio::runtime::Handle::current();
    let result = credential_listing(server, auth, caller, "vault.policy.outbound.decide", move |server, auth, memory| {
        let request = input.into_request(&memory)?;
        let backend = CheckerBackend { server, auth, caller };
        let budget = meter(caller, "policy-owner-pass");
        let answer = runtime.block_on(server.vault().enforce_policy_model_with_budget(
            request, &server.policy_doors.owner, &backend, &budget,
        )).map_err(MemoryError::from)?;
        live(server, auth)?;
        Ok(answer)
    }).await;
    policy_rows(server, result)
}

pub(crate) async fn vault_policy_relay_decide(
    server: &Arc<SyncServer>, auth: &CoreAuth, session: Option<EntityId>,
    caller: (EntityId, EdgeActorClass), _invocation: Option<InvocationId>, input: PolicyOutboundRequest,
) -> Listed<HostedRelayDecision> {
    if session.is_some() { return refused(off_record()); }
    let runtime = tokio::runtime::Handle::current();
    let result = credential_listing(server, auth, caller, "vault.policy.relay.decide", move |server, auth, memory| {
        let relay = server.policy_doors.relay.as_ref().ok_or_else(|| MemoryError::new(
            MEMORY_CODE_INVALID_STATE, "no authenticated hosted relay is bound to this server",
            &["Use a hosted relay with a connector-edge-authenticated identity; local decisions are not hosted evidence."],
        ))?;
        let request = input.into_request(&memory)?;
        let backend = CheckerBackend { server, auth, caller };
        let budget = meter(caller, "policy-relay-pass");
        let admission = budget.admit().map_err(|_| MemoryError::new(
            oneiron::memory::MEMORY_CODE_BUDGET_SPENT, "the relay classifier lease was not admitted", &[],
        ))?;
        let answer = runtime.block_on(doors::enforce_hosted_relay(
            server.vault(), request, &relay.domain, &relay.registry, &relay.config,
            Some(RelaySafeguardTier { backend: &backend, lease: &admission.lease }),
            relay.verdicts.as_ref(), &relay.unavailable_notice,
        )).map_err(MemoryError::from);
        let _ = budget.abort(&admission.lease);
        live(server, auth)?;
        answer
    }).await;
    policy_rows(server, result)
}

fn policy_rows<T>(server: &SyncServer, (answer, mut rows): Listed<T>) -> Listed<T> {
    match doors::policy_manifest_sources(server.vault()) {
        Ok(sources) => { rows.extend(sources); (answer, rows) }
        Err(error) => (Err(error.into()), rows),
    }
}

fn off_record() -> MemoryError {
    MemoryError::new(MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
        "policy decisions write canonical hash-only receipts", &[])
}

fn live(server: &SyncServer, auth: &CoreAuth) -> MemoryResult<()> {
    if !auth.credential_is_live(server.vault()) {
        return Err(MemoryError::new(oneiron::memory::MEMORY_CODE_FORBIDDEN, "credential revoked", &[]));
    }
    Ok(())
}

fn meter((actor, class): (EntityId, EdgeActorClass), name: &str) -> BudgetGuard {
    BudgetGuard::uncapped(format!("{name}:{}", EntityId::now().to_hex()),
        oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS, WriteActor::new(actor, class))
}

/// The existing Checker seat and run admission, never a verdict supplied by the caller.
struct CheckerBackend<'a> {
    server: &'a SyncServer,
    auth: &'a CoreAuth,
    caller: (EntityId, EdgeActorClass),
}

impl LlmBackend for CheckerBackend<'_> {
    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            if !self.auth.credential_is_live(self.server.vault()) { return Err(FatalLlmError::Auth.into()); }
            let call = self.server.ai.admit_role(self.server.vault(), ModelRole::Checker, request)
                .map_err(|_| FatalLlmError::InvalidRequest)?;
            let run = self.server.ai.model_runtime().undeclared_run(
                format!("policy-checker:{}", EntityId::now().to_hex()), meter(self.caller, "policy-checker"),
            );
            call.ladder.generate_while(&run, call.request, None,
                &|| self.auth.credential_is_live(self.server.vault())).await
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}
