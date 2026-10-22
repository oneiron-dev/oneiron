//! Credential-bound host projections of the typed speculative merge queue
//! doors (DOOR-132). HTTP, SDK, MCP and code mode all take the owner's proof
//! here; the engine door revalidates it before any id resolves.
use std::sync::Arc;

use oneiron::memory::merge_queue_doors::*;

use super::host_doors::Listed;
pub(super) use super::host_doors::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_code_merge_queue_enqueue(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueEnqueueRequest,
) -> Listed<MergeQueueBatchView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.enqueue",
        move |memory, owner| memory.merge_queue_enqueue_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_stage(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueBatchRequest,
) -> Listed<MergeQueueBatchView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.stage",
        move |memory, owner| memory.merge_queue_stage_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_observe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueObserveRequest,
) -> Listed<MergeQueueObservation> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.observe",
        move |memory, owner| memory.merge_queue_observe_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_requeue_survivors(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueBatchRequest,
) -> Listed<MergeQueueRequeueView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.requeue_survivors",
        move |memory, owner| memory.merge_queue_requeue_survivors_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_land_reviewed(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueBatchRequest,
) -> Listed<MergeQueueBatchView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.land_reviewed",
        move |memory, owner| memory.merge_queue_land_reviewed_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_settle_slow(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueRepoRequest,
) -> Listed<MergeQueuePointersView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.settle_slow",
        move |memory, owner| memory.merge_queue_settle_slow_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_recover(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueRepoRequest,
) -> Listed<MergeQueuePointersView> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.recover",
        move |memory, owner| memory.merge_queue_recover_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_merge_queue_export_green(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MergeQueueGreenExportRequest,
) -> Listed<oneiron::memory::origin_doors::CodeExportResult> {
    as_owner(
        server,
        auth,
        "vault.code.merge_queue.export_green",
        move |memory, owner| memory.merge_queue_export_green_as(owner, input),
    )
    .await
}
