//! Read-only measured-learning doors under the vault owner's existing proof.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::learning::doors::{
    self, LearningCellView, LearningProjectionRequest, LearningProjectionView,
    LearningProvenanceView, LearningReadRequest,
};
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::receipt::PackAttributionFields;
use oneiron::EntityId;

use super::host_doors::{Listed, internal, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
    rows: impl FnOnce(&T) -> Vec<EntityId>,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer: MemoryResult<T> = tokio::task::spawn_blocking(move || {
        act(&server, &owner).map_err(MemoryError::from)
    }).await.map_err(|_| internal(verb)).and_then(|answer| answer);
    let mut listed = answer.as_ref().map_or_else(|_| Vec::new(), rows);
    listed.sort_unstable();
    listed.dedup();
    (answer, listed)
}

fn pack_rows(pack: &PackAttributionFields, rows: &mut Vec<EntityId>) {
    rows.extend([pack.pattern, pack.decider]);
    rows.extend(pack.project);
    rows.extend(pack.output);
    rows.extend(pack.contributions.iter().map(|item| item.skill));
    for edge in &pack.used_edges {
        rows.extend([edge.derived, edge.source]);
    }
}

fn provenance_rows(view: &LearningProvenanceView, rows: &mut Vec<EntityId>) {
    rows.extend(EntityId::from_hex(&view.cell.subject).ok());
    for head in &view.heads {
        rows.extend(EntityId::from_hex(&head.claim_ref).ok());
        rows.extend(head.supersedes.iter().filter_map(|id| EntityId::from_hex(id).ok()));
    }
    for row in &view.evidence {
        if let Some(pack) = &row.evidence.pack_attribution {
            pack_rows(&pack.attribution, rows);
        }
    }
}

/// Reads the estimate and its own and borrowed provenance, without writing.
pub(crate) async fn vault_learning_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LearningReadRequest,
) -> Listed<LearningCellView> {
    let project = input.project_ref.as_deref().and_then(|id| EntityId::from_hex(id).ok());
    as_owner(server, auth, "vault.learning.read", move |server, owner| {
        doors::read_learning_as_owner(server.vault(), owner, &input)
    }, move |view| {
        let mut rows = Vec::new();
        rows.extend(project);
        provenance_rows(&view.view.provenance, &mut rows);
        if let Some(prior) = &view.view.prior_provenance {
            provenance_rows(prior, &mut rows);
        }
        rows
    }).await
}

/// Observes a committed projection receipt, including no-blame projections.
pub(crate) async fn vault_learning_projection(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LearningProjectionRequest,
) -> Listed<LearningProjectionView> {
    as_owner(server, auth, "vault.learning.projection", move |server, owner| {
        doors::learning_projection_as_owner(server.vault(), owner, &input)
    }, |view| {
        let mut rows = Vec::new();
        if let Some(receipt) = &view.receipt {
            pack_rows(&receipt.attribution, &mut rows);
            rows.extend(receipt.direct_subjects.iter().copied());
            for share in &receipt.shares {
                rows.push(share.subject);
                rows.extend(share.origin_skill);
                for edge in &share.chain {
                    rows.extend([edge.derived, edge.source]);
                }
            }
        }
        rows
    }).await
}
