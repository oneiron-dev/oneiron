//! The owner's cross-kind review and run compensation, on the caller's own
//! credential handle. The facade refuses a non-owner before any hook runs.
//! A settlement or a revert records where his request reached this install
//! (`surface`, the host's own reading of it): audit only (FIX 4650).

use super::host_doors::{Listed, credential_listing, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::authority::ActSurface;
use oneiron::memory::run_review::{
    RevertRunOutcome, RevertRunRequest, RunReview, RunReviewRequest, RunSettleRequest,
    RunSettlement, RunSettlementRequest,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

pub(crate) async fn vault_runs_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: RunReviewRequest,
) -> Listed<RunReview> {
    const VERB: &str = "vault.runs.review";
    let proof = match crate::api::owner_routes::owner(auth, server) {
        Ok(proof) => proof,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "run review requires the caller's own owner credential",
                &[],
            ));
        }
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.review_run_as_owner(&proof, &input)
    })
    .await
}

pub(crate) async fn vault_runs_settle(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    surface: ActSurface,
    input: RunSettleRequest,
) -> Listed<RunSettlement> {
    const VERB: &str = "vault.runs.settle";
    let proof = match crate::api::owner_routes::owner(auth, server) {
        Ok(proof) => proof,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "run review requires the caller's own owner credential",
                &[],
            ));
        }
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory
            .with_owner_surface(surface)
            .settle_run_as_owner(&proof, &input)
    })
    .await
}

pub(crate) async fn vault_runs_settlement(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: RunSettlementRequest,
) -> Listed<RunSettlement> {
    const VERB: &str = "vault.runs.settlement";
    let proof = match crate::api::owner_routes::owner(auth, server) {
        Ok(proof) => proof,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "run review requires the caller's own owner credential",
                &[],
            ));
        }
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.run_settlement_as_owner(&proof, &input)
    })
    .await
}

pub(crate) async fn vault_revert_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    surface: ActSurface,
    input: RevertRunRequest,
) -> Listed<RevertRunOutcome> {
    const VERB: &str = "vault.revert_run";
    let proof = match crate::api::owner_routes::owner(auth, server) {
        Ok(proof) => proof,
        Err(_) => {
            return refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "run review requires the caller's own owner credential",
                &[],
            ));
        }
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory
            .with_owner_surface(surface)
            .revert_run_as_owner(&proof, &input)
    })
    .await
}
