//! Standing-block configuration and per-agent dreaming choice, with the
//! caller's own proof (BOARD-04).
use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, AgentDreamingRequest, AgentDreamingSetRequest, AgentDreamingView,
    StandingBlockConfigureRequest, StandingBlockRequest, StandingBlockView, StandingBlocksRequest,
};

use super::host_doors::support::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_standing_blocks_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: StandingBlockConfigureRequest,
) -> MaybeListed<StandingBlockView> {
    const VERB: &str = "vault.standing_blocks.configure";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::configure_standing_block_as(server.vault(), &owner, input),
        |saved| Some(vec![saved.agent_ref, saved.world_ref]),
    )
    .await
}

pub(crate) async fn vault_standing_blocks_reconfigure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: StandingBlockConfigureRequest,
) -> MaybeListed<StandingBlockView> {
    const VERB: &str = "vault.standing_blocks.reconfigure";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::reconfigure_standing_block_as(server.vault(), &owner, input),
        |saved| Some(vec![saved.agent_ref, saved.world_ref]),
    )
    .await
}

pub(crate) async fn vault_standing_blocks_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: StandingBlockRequest,
) -> MaybeListed<StandingBlockView> {
    const VERB: &str = "vault.standing_blocks.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_standing_block_as(server.vault(), &owner, input),
        |saved| Some(vec![saved.agent_ref, saved.world_ref]),
    )
    .await
}

pub(crate) async fn vault_standing_blocks_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: StandingBlocksRequest,
) -> MaybeListed<Vec<StandingBlockView>> {
    const VERB: &str = "vault.standing_blocks.list";
    let agent_ref = input.agent_ref;
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::list_standing_blocks_as(server.vault(), &owner, input),
        |blocks| {
            let mut rows = vec![agent_ref];
            rows.extend(blocks.iter().map(|block| block.world_ref));
            Some(rows)
        },
    )
    .await
}

pub(crate) async fn vault_agents_dreaming_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgentDreamingRequest,
) -> MaybeListed<AgentDreamingView> {
    const VERB: &str = "vault.agents.dreaming.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::read_agent_dreaming_as(server.vault(), &owner, input),
        |saved| Some(vec![saved.agent_def_ref]),
    )
    .await
}

pub(crate) async fn vault_agents_dreaming_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgentDreamingSetRequest,
) -> MaybeListed<AgentDreamingView> {
    const VERB: &str = "vault.agents.dreaming.set";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::set_agent_dreaming_as(server.vault(), &owner, input),
        |saved| Some(vec![saved.agent_def_ref]),
    )
    .await
}
