//! The host doors of the owner's fan-out rulings (OF-393): `vault.fanout.resume`
//! on a held launch and `vault.fanout.ack` on the width check of one that went
//! out. `host_doors` re-exports them, so the generated HTTP facade handler and
//! the MCP dispatcher call them by the name every host door has, and a paired
//! owner meets the admission `/v1/owner` has: the vault owner's proof
//! (`owner_routes::owner`). The engine door revalidates that proof inside its
//! own transaction. An embedded handle keeps its embedded-owner call.
use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{self, FanoutAckRequest, FanoutLaunchView, FanoutResumeRequest};

use super::legal_hold_doors::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.fanout.resume`: the owner approves a held launch once, approves
/// and remembers it under a cap, or denies it, by the digest they saw.
pub(crate) async fn vault_fanout_resume(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FanoutResumeRequest,
) -> MemoryResult<FanoutLaunchView> {
    as_owner(server, auth, "vault.fanout.resume", move |server, owner| {
        let memory = server
            .vault()
            .memory(owner.revalidate(server.vault())?, EdgeActorClass::Human);
        sdk::resume_fanout_launch_as(&memory, owner, input)
    })
    .await
}

/// `vault.fanout.ack`: the owner acknowledges a launched fan-out's width
/// check, once or remembered under a cap.
pub(crate) async fn vault_fanout_ack(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FanoutAckRequest,
) -> MemoryResult<FanoutLaunchView> {
    as_owner(server, auth, "vault.fanout.ack", move |server, owner| {
        let memory = server
            .vault()
            .memory(owner.revalidate(server.vault())?, EdgeActorClass::Human);
        sdk::ack_fanout_check_as(&memory, owner, input)
    })
    .await
}
