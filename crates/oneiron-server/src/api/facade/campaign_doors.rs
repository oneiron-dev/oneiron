//! The stage-evidence host door binds an owner attestation to the request's
//! verified owner proof. Machine evidence still acts as its credential's own
//! principal, through the same campaign-owned facade as enrollment.

use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::campaign::claims::EvidenceBasis;
use oneiron::campaign::surface::{CampaignStageEvidenceReceipt, CampaignStageEvidenceRequest};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

pub(crate) async fn vault_campaign_stage_evidence(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: CampaignStageEvidenceRequest,
) -> Listed<CampaignStageEvidenceReceipt> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.campaign.stage.evidence",
        move |server, auth, memory| {
            let owner = match input.evidence.basis {
                EvidenceBasis::Machine => None,
                EvidenceBasis::OwnerAttested => Some(super::host_doors::support::owner_proof(
                    auth,
                    server,
                    "vault.campaign.stage.evidence",
                )?),
            };
            memory.campaign_stage_evidence_as(owner.as_ref(), &input)
        },
    )
    .await
}
