//! Archive cleanup and evidence-backed re-mention, under the owner's own proof.

use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::ingest::{EntityMentionRequest, EntityResolutionWaterfallDecision};
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::vault_cleanup::surface::{CleanupRunRequest, CleanupRunView};
use oneiron::vault_cleanup::{
    CleanupDecideRequest, CleanupDecideView, CleanupKind, CleanupReviewRequest, CleanupReviewView,
};

use super::host_doors::support::{Listed, internal, owner_proof, refused};
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
    let answer: MemoryResult<CleanupRunView> = super::clock_ingress::run_blocking(move || {
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

/// One open proposal reviewed slot by slot (FIX 1758), under the owner's
/// proof; each slot's content comes through the owner's own reads.
pub(crate) async fn vault_cleanup_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CleanupReviewRequest,
) -> Listed<CleanupReviewView> {
    const VERB: &str = "vault.cleanup.review";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let locality = auth.locality();
    let server = Arc::clone(server);
    let answer: MemoryResult<CleanupReviewView> = super::clock_ingress::run_blocking(move || {
        let vault = server.vault();
        let actor = owner.revalidate(vault).map_err(MemoryError::from)?;
        let memory = vault.memory(actor, EdgeActorClass::Human).at(locality);
        oneiron::vault_cleanup::review_cleanup_proposal_as(&memory, &owner, &input)
    })
    .await
    .map_err(|_| internal(VERB))
    .and_then(|answer| answer);
    // The records the review discloses; an attempt names no record.
    let rows = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |view| {
            view.items
                .iter()
                .filter(|item| item.kind != Some(CleanupKind::CompletedAttempt))
                .filter_map(|item| item.entity)
                .collect()
        },
    );
    (answer, rows)
}

/// One open proposal decided slot by slot in one complete verdict (FIX
/// 1758), under the owner's proof.
pub(crate) async fn vault_cleanup_decide(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CleanupDecideRequest,
) -> Listed<CleanupDecideView> {
    const VERB: &str = "vault.cleanup.decide";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let answer: MemoryResult<CleanupDecideView> = super::clock_ingress::run_blocking(move || {
        server.vault().decide_cleanup_proposal_as(&owner, &input)
    })
    .await
    .map_err(|_| internal(VERB))
    .and_then(|answer| answer);
    let rows = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |view| {
            view.items
                .iter()
                .filter(|item| item.kind != Some(CleanupKind::CompletedAttempt))
                .filter_map(|item| item.entity)
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
        super::clock_ingress::run_blocking(move || {
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
