//! FIX 13274: `vault.sync.documents.copy_edit.review` and
//! `vault.sync.documents.copy_edit.settle`, the owner's door to a retained
//! document-copy edit (#5025). Each runs under the request's owner proof
//! (`facade_owner`, as `/v1/owner` takes it), opens the source's shared
//! document handle as that owner, and calls the engine, which revalidates
//! the proof in its own read or writer. Each answer names the source it
//! reviewed or settled. Settlement's frame is a local commit; delivery stays
//! the sync bridge's.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::sync::documents::EntityDocument;
use oneiron::task_verb::sdk::{
    RepoCopyEditReviewRequest, RepoCopyEditReviewView, RepoCopyEditSettleRequest,
    RepoCopyEditSettleView, repo_copy_edit_review_as_owner, repo_copy_edit_settle_as_owner,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The source document's shared handle, opened as the proof's owner.
fn owner_document(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    source: &str,
) -> MemoryResult<Arc<EntityDocument>> {
    let source = EntityId::from_hex(source)
        .map_err(|_| MemoryError::bad_request("source must be the 32-hex id of a document"))?;
    let actor = owner.actor_for_read(server.vault())?;
    Ok(server
        .reassert_manager
        .documents()
        .open_for(source, actor.as_bytes())?)
}

fn named_source(source: &str) -> Vec<EntityId> {
    EntityId::from_hex(source).ok().into_iter().collect()
}

/// `vault.sync.documents.copy_edit.review`: the held copy edit on one
/// source document, for its owner.
pub(crate) async fn vault_sync_documents_copy_edit_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RepoCopyEditReviewRequest,
) -> Listed<Option<RepoCopyEditReviewView>> {
    const VERB: &str = "vault.sync.documents.copy_edit.review";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            let document = owner_document(server, owner, &input.source)?;
            repo_copy_edit_review_as_owner(&document, owner)
        },
        |answer| {
            answer
                .as_ref()
                .map(|view| named_source(&view.source))
                .unwrap_or_default()
        },
    )
    .await
}

/// `vault.sync.documents.copy_edit.settle`: the owner settles that edit to
/// an exact replacement, under the revision they reviewed.
pub(crate) async fn vault_sync_documents_copy_edit_settle(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RepoCopyEditSettleRequest,
) -> Listed<RepoCopyEditSettleView> {
    const VERB: &str = "vault.sync.documents.copy_edit.settle";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            let document = owner_document(server, owner, &input.source)?;
            repo_copy_edit_settle_as_owner(&document, owner, &input)
        },
        |answer| named_source(&answer.source),
    )
    .await
}
