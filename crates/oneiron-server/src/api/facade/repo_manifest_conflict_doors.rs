//! The owner's durable manifest-conflict review and exact keep-held discard.

use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, RepoManifestConflictDiscardRequest, RepoManifestConflictDiscardView,
    RepoManifestConflictReviewRequest, RepoManifestConflictReviewView,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_sync_repo_manifests_conflict_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RepoManifestConflictReviewRequest,
) -> Listed<Option<RepoManifestConflictReviewView>> {
    as_owner_naming(
        server,
        auth,
        "vault.sync.repo_manifests.conflict.review",
        move |server, owner| {
            sdk::repo_manifest_conflict_review_as_owner(server.vault(), owner, input)
        },
        |review| {
            review.as_ref().map_or_else(Vec::new, |review| {
                vec![review.held.code, review.carried.code]
            })
        },
    )
    .await
}

pub(crate) async fn vault_sync_repo_manifests_conflict_discard(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RepoManifestConflictDiscardRequest,
) -> Listed<RepoManifestConflictDiscardView> {
    let (answer, rows) = as_owner_naming(
        server,
        auth,
        "vault.sync.repo_manifests.conflict.discard",
        move |server, owner| {
            sdk::repo_manifest_conflict_discard_listed_as_owner(server.vault(), owner, input)
        },
        |(_, rows)| rows.clone(),
    )
    .await;
    (answer.map(|(view, _)| view), rows)
}
