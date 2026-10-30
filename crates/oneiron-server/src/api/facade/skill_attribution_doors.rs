//! Proposal-delta settlement and skill attribution evidence, owner-only.
use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    self, AttributionEvidenceReceipt, AttributionEvidenceRequest, AttributionJudgmentsView,
    AttributionListRequest, AttributionProjectRequest, AttributionProjection,
    AttributionProposalsView, PositiveRetireReceipt, PositiveRetireRequest, ProposalDeltaRead,
    ProposalDeltaReadRequest, ProposalDeltaSettleRequest, ProposalDeltaSettlement,
};

use super::host_doors::support::{internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_skills_attribution_settle(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProposalDeltaSettleRequest,
) -> MemoryResult<ProposalDeltaSettlement> {
    let owner = owner_proof(auth, server, "vault.skills.attribution.settle")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        sdk::skill_attribution_settle_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.attribution.settle"))?
}

pub(crate) async fn vault_skills_attribution_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ProposalDeltaReadRequest,
) -> MemoryResult<ProposalDeltaRead> {
    let owner = owner_proof(auth, server, "vault.skills.attribution.read")?;
    // The artifact's texts are judged as the owner reads where this caller
    // sits (FIX 11351).
    let locality = auth.locality();
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        sdk::skill_attribution_read_as_owner(server.vault(), &owner, locality, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.attribution.read"))?
}

pub(crate) async fn vault_skills_attribution_evidence_record(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AttributionEvidenceRequest,
) -> MemoryResult<AttributionEvidenceReceipt> {
    let owner = owner_proof(auth, server, "vault.skills.attribution.evidence.record")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        sdk::skill_attribution_evidence_record_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.attribution.evidence.record"))?
}

pub(crate) async fn vault_skills_attribution_project(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AttributionProjectRequest,
) -> MemoryResult<AttributionProjection> {
    let owner = owner_proof(auth, server, "vault.skills.attribution.project")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        sdk::skill_attribution_project_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.attribution.project"))?
}

pub(crate) async fn vault_skills_attribution_judgments(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AttributionListRequest,
) -> MemoryResult<AttributionJudgmentsView> {
    let owner = owner_proof(auth, server, "vault.skills.attribution.judgments")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        sdk::skill_attribution_judgments_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.attribution.judgments"))?
}

pub(crate) async fn vault_skills_attribution_proposals(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AttributionListRequest,
) -> MemoryResult<AttributionProposalsView> {
    let owner = owner_proof(auth, server, "vault.skills.attribution.proposals")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        sdk::skill_attribution_proposals_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.attribution.proposals"))?
}

pub(crate) async fn vault_skills_attribution_positive_retire(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PositiveRetireRequest,
) -> MemoryResult<PositiveRetireReceipt> {
    let owner = owner_proof(auth, server, "vault.skills.attribution.positive.retire")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        sdk::skill_attribution_positive_retire_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.skills.attribution.positive.retire"))?
}
