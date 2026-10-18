//! The host door of a campaign split's evaluation,
//! `vault.research.evaluate_split` (FIX 655): the owner scores one arm of a
//! bound claim-authoring campaign on one split, and the split report's taste
//! pack goes through the host's decision ladder for the owner. `host_doors`
//! re-exports it, so the generated HTTP facade handler and the MCP dispatcher
//! call it by the name every host door has. It takes the vault owner's proof
//! as `/v1/owner` takes it (`owner_routes::owner`), and runs the ladder on a
//! blocking thread. The report is returned, not stored. Beside it, the door
//! lists no row (`host_door_lists`): the gold, the run and the blind pack
//! come inline, the campaign's bound config lives in a side table, and the
//! taste the ladder answers names none.
use std::sync::Arc;

use oneiron::autoreason_campaign::CampaignSplitReport;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{CampaignSplitWire, evaluate_campaign_split};

use super::host_doors::{Listed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.research.evaluate_split";

/// `vault.research.evaluate_split`: the arm's split report, its taste asked
/// for the owner through the host's ladder.
pub(crate) async fn vault_research_evaluate_split(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CampaignSplitWire,
) -> Listed<CampaignSplitReport> {
    (
        vault_research_evaluate_split_answer(server, auth, input).await,
        Vec::new(),
    )
}

async fn vault_research_evaluate_split_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CampaignSplitWire,
) -> MemoryResult<CampaignSplitReport> {
    let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        let vault = server.vault();
        let principal = owner.revalidate_person(vault)?;
        let taste = server.decision_host().campaign_taste(principal);
        evaluate_campaign_split(vault, &input, &taste)
    })
    .await
    .map_err(|_| internal(VERB))?
}
