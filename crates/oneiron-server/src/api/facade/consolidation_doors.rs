//! Owner-bound generated-claim promotion, vetting and evidence reads.
use std::sync::Arc;

use oneiron::claim::ScopedReadResult;
use oneiron::memory::consolidation::{
    ConsolidationEvidenceRequest, ConsolidationEvidenceSource, ConsolidationPromoteRequest,
    ConsolidationPromotion,
};
use oneiron::memory::{
    ClaimProposalReview, ClaimProposalReviewRequest, ClaimSettleRequest, ClaimSettlement,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_consolidation_promote(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ConsolidationPromoteRequest,
) -> Listed<ConsolidationPromotion> {
    const VERB: &str = "vault.consolidation.promote";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        memory.consolidation_promote_as_owner(&owner, &input, server.decision_host().auto_checker())
    })
    .await
}

pub(crate) async fn vault_consolidation_evidence(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ConsolidationEvidenceRequest,
) -> Listed<ScopedReadResult<Vec<ConsolidationEvidenceSource>>> {
    const VERB: &str = "vault.consolidation.evidence";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.consolidation_evidence_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_claims_vet(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ClaimSettleRequest,
) -> Listed<ClaimSettlement> {
    const VERB: &str = "vault.claims.vet";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.claim_vet_as_owner(&owner, &input)
    })
    .await
}

/// Review the exact generated claim before vetting it, including an Auto head.
pub(crate) async fn vault_claims_vetting(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ClaimProposalReviewRequest,
) -> Listed<ClaimProposalReview> {
    const VERB: &str = "vault.claims.vetting";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.claim_vetting_review_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_consolidation_pin(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: oneiron::memory::consolidation_frontier::ConsolidationPinRequest,
) -> Listed<oneiron::memory::consolidation_frontier::ConsolidationRootAccounting> {
    const VERB: &str = "vault.consolidation.pin";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.consolidation_pin_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_consolidation_frontier(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: oneiron::memory::consolidation_frontier::ConsolidationFrontierRequest,
) -> Listed<oneiron::memory::consolidation_frontier::ConsolidationRootAccounting> {
    const VERB: &str = "vault.consolidation.frontier";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.consolidation_frontier_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_consolidation_accounting(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: oneiron::memory::consolidation_frontier::ConsolidationAccountingRequest,
) -> Listed<oneiron::memory::consolidation_frontier::ConsolidationRootAccounting> {
    const VERB: &str = "vault.consolidation.accounting";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.consolidation_accounting_as_owner(&owner, &input)
    })
    .await
}
