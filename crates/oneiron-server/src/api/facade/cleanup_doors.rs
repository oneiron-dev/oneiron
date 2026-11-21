//! Archive cleanup and evidence-backed re-mention, under the owner's own proof.

use std::sync::Arc;

use oneiron::authority::VerifiedSlip;
use oneiron::claim::CallerLocality;
use oneiron::ingest::{EntityMentionRequest, EntityResolutionWaterfallDecision};
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::vault_cleanup::surface::{CleanupRunRequest, CleanupRunView};
use oneiron::vault_cleanup::{
    CleanupDecideRequest, CleanupDecideView, CleanupKind, CleanupReviewRequest, CleanupReviewView,
};
use oneiron::{EdgeActorClass, EntityId, Vault};

use super::host_doors::support::{Listed, internal, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Who decides a cleanup proposal (RESTRICTION-WAVE-10 C43): the owner under
/// its proof, or an agent on its own credential, whose owner key, Grant and
/// presented credential the engine door reads again in the write that decides.
pub(super) enum Decider {
    Owner(oneiron::consent::AuthenticatedOwner),
    Agent(EntityId),
}

/// `agent`'s handle for this call, bound to the credential its caller
/// presented: the engine judges that credential (its holder, any invitation,
/// record or channel bound to it, and whether it is live) as it judges an
/// in-process call's.
fn agent_memory<'a>(
    vault: &'a Vault,
    agent: EntityId,
    locality: CallerLocality,
    presented: Option<&VerifiedSlip>,
) -> Memory<'a> {
    let memory = vault.memory(agent, EdgeActorClass::Agent).at(locality);
    match presented {
        Some(proof) => memory.with_read_proof(proof),
        None => memory,
    }
}

/// The caller `vault.cleanup.decide` admits before its door runs and its hooks
/// fire: the owner's proof, else a credential bound to an agent that the
/// owner's key, a Grant and the credential's own bounds admit now (the engine
/// reads all three again in the write that decides). Every other caller keeps
/// the owner refusal.
pub(super) fn decider(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<Decider> {
    let refusal = match owner_proof(auth, server, verb) {
        Ok(owner) => return Ok(Decider::Owner(owner)),
        Err(refusal) => refusal,
    };
    match super::owner_binding::facade_caller_or(server, auth, || refusal.clone())? {
        (agent, EdgeActorClass::Agent)
            if agent_memory(server.vault(), agent, auth.locality(), auth.verified_slip())
                .agent_decides_cleanup()? =>
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
    let locality = auth.locality();
    let presented = auth.verified_slip().cloned();
    let server = Arc::clone(server);
    let sourced: MemoryResult<(CleanupDecideView, Vec<oneiron::EntityId>)> =
        super::clock_ingress::run_blocking(move || {
            let vault = server.vault();
            match decider {
                Decider::Owner(owner) => vault.decide_cleanup_proposal_sourced_as(&owner, &input),
                Decider::Agent(agent) => agent_memory(vault, agent, locality, presented.as_ref())
                    .decide_cleanup_proposal_sourced_as_agent(&input),
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
