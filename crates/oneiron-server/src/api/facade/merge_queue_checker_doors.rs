//! Credential-bound host projections of the owner's merge queue checker
//! doors (FIX 6868). Each takes the owner's proof through the merge queue
//! doors' owner wrapper and returns the durable work at once; no native
//! command runs on the request path.
use std::sync::Arc;

use oneiron::memory::merge_queue_doors::*;

use super::host_doors::Listed;
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
