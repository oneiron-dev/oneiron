//! The owner's runner seat doors (FIX 7451, FIX 11067) and the continue rows
//! (census L10-17): `vault.runners.seats.quotas`, `vault.runners.seats.top_up`,
//! `vault.runners.seats.resume`, `vault.runners.continue` and
//! `vault.runners.continue.check`, beside the budget doors. No seat, quota,
//! resume or continue logic lives here: the engine reads and clears the seats'
//! quota records, resumes their parked work and continues outside sessions on
//! this node's own runner seats, rechecking the caller's proof in its own
//! transaction. The continue rows admit the owner, or an agent on its own Grant.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dispatch_byoa::{
    ContinueOutsideWorkCheckRequest, ContinueOutsideWorkCheckView, ContinueOutsideWorkRequest,
    ContinueOutsideWorkView, OnSeatSpent, RunnerContinueCaller, RunnerSeatCreditTopUpRequest,
    RunnerSeatPolicy, RunnerSeatQuotasRequest, RunnerSeatQuotasView, RunnerSeatTopUpReceipt,
    RunnerWorkResumeRequest, RunnerWorkResumeView,
};
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};

use super::host_doors::support::{Listed, internal, owner_proof, refused};
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_runners_seats_quotas(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerSeatQuotasRequest,
) -> Listed<RunnerSeatQuotasView> {
    as_owner_naming(
        server,
        auth,
        "vault.runners.seats.quotas",
        move |server, owner| server.vault().runner_seat_quotas_as_owner(owner, &input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_runners_seats_top_up(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerSeatCreditTopUpRequest,
) -> Listed<RunnerSeatTopUpReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.runners.seats.top_up",
        move |server, owner| server.vault().top_up_runner_seat_as_owner(owner, &input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_runners_seats_resume(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunnerWorkResumeRequest,
) -> Listed<RunnerWorkResumeView> {
    as_owner_naming(
        server,
        auth,
        "vault.runners.seats.resume",
        move |server, owner| server.vault().resume_runner_work_as_owner(owner, &input),
        |_| Vec::new(),
    )
    .await
}

/// Who calls a continue row: the owner on its proof, or the actor its credential binds,
/// whose live Grant naming `vault.runners.continue` the engine door checks in its own
/// transaction.
pub(in crate::api::facade) enum ContinueCaller {
    Owner(AuthenticatedOwner),
    Agent(EntityId),
}

/// The continue rows' caller (census L10-17, WHO = B), as `door_admits` checks it first and
/// each door acts under it: the owner's proof, else the credential's own actor; a credential
/// bound to none keeps the owner refusal.
pub(in crate::api::facade) fn continue_caller(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<ContinueCaller> {
    match owner_proof(auth, server, verb) {
        Ok(owner) => Ok(ContinueCaller::Owner(owner)),
        Err(refusal) => super::owner_binding::facade_caller_or(server, auth, || refusal)
            .map(|(actor, _class)| ContinueCaller::Agent(actor)),
    }
}

impl ContinueCaller {
    /// The engine door's caller: the owner's proof, or the granted agent.
    fn engine_caller(&self) -> RunnerContinueCaller<'_> {
        match self {
            Self::Owner(owner) => RunnerContinueCaller::Owner(owner),
            Self::Agent(actor) => RunnerContinueCaller::GrantedAgent(*actor),
        }
    }
}

/// This node's own runner-seat policy, as the seat host reads it from the AI host. The caller
/// never names the policy. A node with no seats answers each runner `no_runner_seat`, after the
/// caller check.
fn node_runner_seat_policy(server: &SyncServer) -> MemoryResult<RunnerSeatPolicy> {
    let Some(settings) = server.ai.runner_seats() else {
        return Ok(RunnerSeatPolicy {
            seats: Vec::new(),
            on_spent: OnSeatSpent::Stop,
        });
    };
    settings.policy().map_err(|text| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            text,
            &["Fix [models.dreamer] runner_seats in this node's config."],
        )
    })
}

/// `vault.runners.continue`: the owner, or an agent on its own Grant, starts the outside session
/// the local CLI pushed, on this node's own runner seats.
pub(crate) async fn vault_runners_continue(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ContinueOutsideWorkRequest,
) -> Listed<ContinueOutsideWorkView> {
    const VERB: &str = "vault.runners.continue";
    let caller = match continue_caller(server, auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let policy = match node_runner_seat_policy(server) {
        Ok(policy) => policy,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        server
            .vault()
            .continue_outside_work(caller.engine_caller(), &policy, &input)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    (answer, Vec::new())
}

/// `vault.runners.continue.check`: whether this node would take the outside session, on its own
/// runner seats. It writes nothing.
pub(crate) async fn vault_runners_continue_check(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ContinueOutsideWorkCheckRequest,
) -> Listed<ContinueOutsideWorkCheckView> {
    const VERB: &str = "vault.runners.continue.check";
    let caller = match continue_caller(server, auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let policy = match node_runner_seat_policy(server) {
        Ok(policy) => policy,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        server
            .vault()
            .continue_outside_work_check(caller.engine_caller(), &policy, &input)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    (answer, Vec::new())
}
