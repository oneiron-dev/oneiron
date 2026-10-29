//! The owner's authority clock repair door (FIX 10106). The engine judges the
//! owner's proof in the repair's own writer, against the floor it proves, so
//! this door adds no read of the clock it repairs: the caller its transport
//! admitted reaches that writer as it is (FIX 11202), a managed vault's
//! attested owner, a host root or the dev mode, and the owner's own slip,
//! with no owner proof built first.

use std::sync::Arc;

use oneiron::task_verb::sdk::{AuthorityClockRepair, EmptyRequest};

use super::support::Listed;
use crate::api::facade::clock_ingress;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.authority.clock.repair`: the authority log holds no user row.
pub(crate) async fn vault_authority_clock_repair(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<AuthorityClockRepair> {
    let repaired = match clock_ingress::repair_caller_of(server, auth) {
        Ok(caller) => clock_ingress::repair(server, caller).await,
        Err(refusal) => Err(refusal),
    };
    (repaired, Vec::new())
}
