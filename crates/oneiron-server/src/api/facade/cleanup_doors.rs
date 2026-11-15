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

/// Who decides a cleanup proposal (RESTRICTION-WAVE-10 C43): the owner under
/// its proof, or an agent on its own credential, whose owner key and Grant the
/// engine door reads in the write that decides.
pub(super) enum Decider {
    Owner(oneiron::consent::AuthenticatedOwner),
    Agent(oneiron::EntityId),
}

/// The caller `vault.cleanup.decide` admits before its door runs and its hooks
/// fire: the owner's proof, else a credential bound to an agent that the
/// owner's key and Grant admit now (the engine reads both again in the write
/// that decides). Every other caller keeps the owner refusal.
pub(super) fn decider(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<Decider> {
    let refusal = match owner_proof(auth, server, verb) {
        Ok(owner) => return Ok(Decider::Owner(owner)),
        Err(refusal) => refusal,
    };
    match super::owner_binding::facade_caller_or(server, auth, || refusal.clone())? {
        (agent, EdgeActorClass::Agent)
            if server
                .vault()
                .cleanup_decide_admits_agent(agent)
                .map_err(MemoryError::from)? =>
        {
            Ok(Decider::Agent(agent))
        }
        _ => Err(refusal),
    }
}

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
    let sourced: MemoryResult<(CleanupRunView, Vec<oneiron::EntityId>)> =
        super::clock_ingress::run_blocking(move || {
            oneiron::vault_cleanup::surface::run_sourced_as_owner(server.vault(), &owner, &input)
                .map_err(MemoryError::from)
        })
        .await
        .map_err(|_| internal(VERB))
        .and_then(|answer| answer);
    // FIX 10494: named non-attempt rows plus genuine known attempt sources.
    let (answer, rows) = match sourced {
        Ok((view, sources)) => {
            let mut rows: Vec<oneiron::EntityId> = view
                .candidates
                .iter()
                .filter(|candidate| candidate.kind != CleanupKind::CompletedAttempt)
                .map(|candidate| candidate.entity)
                .collect();
            rows.extend(sources);
            rows.sort_unstable();
            rows.dedup();
            (Ok(view), rows)
        }
        Err(error) => (Err(error), Vec::new()),
    };
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
    let sourced: MemoryResult<(CleanupReviewView, Vec<oneiron::EntityId>)> =
        super::clock_ingress::run_blocking(move || {
            let vault = server.vault();
            let actor = owner.revalidate(vault).map_err(MemoryError::from)?;
            let memory = vault.memory(actor, EdgeActorClass::Human).at(locality);
            oneiron::vault_cleanup::review_cleanup_proposal_sourced_as(&memory, &owner, &input)
        })
        .await
        .map_err(|_| internal(VERB))
        .and_then(|answer| answer);
    // The records the review discloses; an attempt names no record.
    // FIX 10494: plus its genuine known attempt sources.
    let (answer, rows) = match sourced {
        Ok((view, sources)) => {
            let mut rows: Vec<oneiron::EntityId> = view
                .items
                .iter()
                .filter(|item| item.kind != Some(CleanupKind::CompletedAttempt))
                .filter_map(|item| item.entity)
                .collect();
            rows.extend(sources);
            rows.sort_unstable();
            rows.dedup();
            (Ok(view), rows)
        }
        Err(error) => (Err(error), Vec::new()),
    };
    (answer, rows)
}

/// One open proposal decided slot by slot in one complete verdict (FIX
/// 1758), under the owner's proof, or by an agent the owner's
/// `vault_cleanup.decide.owner_only` and its Grant admit.
pub(crate) async fn vault_cleanup_decide(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CleanupDecideRequest,
) -> Listed<CleanupDecideView> {
    const VERB: &str = "vault.cleanup.decide";
    let decider = match decider(server, auth, VERB) {
        Ok(decider) => decider,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let sourced: MemoryResult<(CleanupDecideView, Vec<oneiron::EntityId>)> =
        super::clock_ingress::run_blocking(move || {
            let vault = server.vault();
            match decider {
                Decider::Owner(owner) => vault.decide_cleanup_proposal_sourced_as(&owner, &input),
                Decider::Agent(agent) => {
                    vault.decide_cleanup_proposal_sourced_as_agent(agent, &input)
                }
            }
        })
        .await
        .map_err(|_| internal(VERB))
        .and_then(|answer| answer);
    // FIX 10494: named non-attempt rows plus genuine known attempt sources.
    let (answer, rows) = match sourced {
        Ok((view, sources)) => {
            let mut rows: Vec<oneiron::EntityId> = view
                .items
                .iter()
                .filter(|item| item.kind != Some(CleanupKind::CompletedAttempt))
                .filter_map(|item| item.entity)
                .collect();
            rows.extend(sources);
            rows.sort_unstable();
            rows.dedup();
            (Ok(view), rows)
        }
        Err(error) => (Err(error), Vec::new()),
    };
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
