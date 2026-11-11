//! The owner's explicit follower-keyframe door, shared by HTTP and MCP.

use std::sync::Arc;

use oneiron::task_verb::sdk::{self, DreamerFollowerKeyframeResult, EmptyRequest};

use super::host_doors::support::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Marks follower side-table sessions, without claiming any fold has completed.
pub(crate) async fn vault_dreamer_follower_keyframe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> MaybeListed<DreamerFollowerKeyframeResult> {
    const VERB: &str = "vault.dreamer.follower.keyframe";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::dreamer_follower_keyframe_as(server.vault(), &owner, input),
        |_| Some(Vec::new()),
    )
    .await
}
