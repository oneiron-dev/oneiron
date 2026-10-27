//! The owner's authority clock repair door (FIX 10106). The engine judges the
//! owner's proof in the repair's own writer, against the floor it proves, so
//! this door adds no read of the clock it repairs.

use std::sync::Arc;

use oneiron::task_verb::sdk::{self, AuthorityClockRepair, EmptyRequest};

use super::support::Listed;
use crate::api::facade::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.authority.clock.repair`: the authority log holds no user row.
pub(crate) async fn vault_authority_clock_repair(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<AuthorityClockRepair> {
    as_owner_naming(
        server,
        auth,
        "vault.authority.clock.repair",
        move |server, owner| sdk::repair_authority_clock_as_owner(server.vault(), owner),
        |_| Vec::new(),
    )
    .await
}
