//! Archive cleanup and evidence-backed re-mention, under the owner's own proof.

use std::sync::Arc;

use oneiron::ingest::{EntityMentionRequest, EntityResolutionWaterfallDecision};
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::vault_cleanup::CleanupKind;
use oneiron::vault_cleanup::surface::{CleanupRunRequest, CleanupRunView};

use super::host_doors::{Listed, internal, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_cleanup_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CleanupRunRequest,
) -> Listed<CleanupRunView> {
    const VERB: &str = "vault.cleanup.run";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer: MemoryResult<CleanupRunView> = tokio::task::spawn_blocking(move || {
        oneiron::vault_cleanup::surface::run_as_owner(server.vault(), &owner, &input)
            .map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal(VERB))
    .and_then(|answer| answer);
    let rows = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |report| {
            report
                .candidates
                .iter()
                .filter(|candidate| candidate.kind != CleanupKind::CompletedAttempt)
                .map(|candidate| candidate.entity)
                .collect()
        },
    );
    (answer, rows)
}

pub(crate) async fn vault_entities_mention(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EntityMentionRequest,
) -> Listed<EntityResolutionWaterfallDecision> {
    const VERB: &str = "vault.entities.mention";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let mut rows: Vec<_> = input
        .candidates
        .iter()
        .flat_map(|candidate| [candidate.subject, candidate.confidence_claim_ref])
        .collect();
    let server = Arc::clone(server);
    let answer: MemoryResult<EntityResolutionWaterfallDecision> =
        tokio::task::spawn_blocking(move || {
            oneiron::ingest::mention_as_owner(server.vault(), &owner, &input)
                .map_err(MemoryError::from)
        })
        .await
        .map_err(|_| internal(VERB))
        .and_then(|answer| answer);
    if let Ok(decision) = &answer {
        rows.extend(decision.selected);
        for scored in &decision.ranked {
            rows.extend([
                scored.candidate.subject,
                scored.candidate.confidence_claim_ref,
            ]);
        }
    }
    rows.sort_unstable();
    rows.dedup();
    (answer, rows)
}
