//! Credential-bound host projections of the owner's merge queue checker
//! doors (FIX 6868). Each takes the owner's proof through the merge queue
//! doors' owner wrapper and returns the durable work at once; no native
//! command runs on the request path. The vault's review policy doors (FIX
//! 8268) bind the caller instead: a live Owner's proof, or the credential's
//! own principal, whose one Grant the engine door judges.
use std::sync::Arc;

use oneiron::memory::merge_queue_doors::*;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing};
use super::merge_queue_doors::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_code_merge_queue_init(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueInitializeRequest,
) -> Listed<MergeQueueCheckWorkView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.init",
        move |memory, owner| memory.merge_queue_init_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_check(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueCheckRequest,
) -> Listed<MergeQueueCheckWorkView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.check",
        move |memory, owner| memory.merge_queue_check_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_diagnose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueDiagnoseRequest,
) -> Listed<MergeQueueCheckWorkView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.diagnose",
        move |memory, owner| memory.merge_queue_diagnose_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_check_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueCheckStatusRequest,
) -> Listed<MergeQueueCheckWorkView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.check_status",
        move |memory, owner| memory.merge_queue_check_status_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_checks_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeCheckReceiptRequest,
) -> Listed<Option<CodeCheckReceiptView>> {
    as_owner(
        server,
        auth,
        "vault.code.checks.get",
        move |memory, owner| memory.merge_queue_check_receipt_as(owner, input),
    )
    .await
}

fn not_a_policy_caller(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} is a live Owner's, or a Grant holder's whose Grant lists it"),
        &["Present an Owner's credential, or an agent's own credential under its Grant."],
    )
}

/// MCP's filtered gate judges no channel caveat; the facade's lane guard
/// does. Both review policy doors meet it here.
fn review_policy_lane(auth: &CoreAuth) -> MemoryResult<()> {
    auth.require_lane_record_scope().map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a channel-bound credential reaches no review policy door",
            &[],
        )
    })
}

/// The check a review policy row's door runs before its pre chain
/// (`door_admits`): the lane guard, then a credential that binds a
/// principal. A host root alone binds none. Its Grant is the engine's.
pub(super) fn review_policy_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    review_policy_lane(auth)?;
    super::owner_binding::facade_caller_or(server, auth, || not_a_policy_caller(verb)).map(drop)
}

/// One review policy door: the caller bound from its own credential, the
/// Owner's proof when it carries one, and `act` run on that credential's
/// own lane.
async fn as_policy_caller<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    invocation: Option<InvocationId>,
    act: impl FnOnce(&Memory<'_>, &QueueReviewPolicyProof) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let bound = || {
        review_policy_lane(auth)?;
        let caller =
            super::owner_binding::facade_caller_or(server, auth, || not_a_policy_caller(verb))?;
        let proof = match super::owner_binding::facade_owner(server, auth, verb) {
            Ok(owner) => QueueReviewPolicyProof::Owner(owner),
            Err(_) => QueueReviewPolicyProof::Grant,
        };
        Ok::<_, MemoryError>((caller, proof))
    };
    let (caller, proof) = match bound() {
        Ok(bound) => bound,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        act(&memory, &proof)
    })
    .await
}

pub(crate) async fn vault_code_merge_queue_review_policy_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    _input: EmptyRequest,
) -> Listed<QueueReviewPolicyView> {
    as_policy_caller(
        server,
        auth,
        "vault.code.merge_queue.review_policy.get",
        invocation,
        |memory, proof| memory.merge_queue_review_policy_get_as(proof),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_review_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: QueueReviewPolicySetRequest,
) -> Listed<QueueReviewPolicyView> {
    as_policy_caller(
        server,
        auth,
        "vault.code.merge_queue.review_policy.set",
        invocation,
        move |memory, proof| memory.merge_queue_review_policy_set_as(proof, input),
    )
    .await
}
