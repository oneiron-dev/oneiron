//! The owner's value-free hook cycle and depth checks.

use std::sync::Arc;

use oneiron::memory::MemoryError;
use oneiron::runtime_hooks::HookCheck;
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::{Listed, internal, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.hooks.checks";

pub(crate) async fn vault_hooks_checks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<HookCheck>> {
    let owner = match super::owner_binding::facade_owner(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        server
            .vault()
            .hook_checks_as_owner(&owner)
            .map_err(MemoryError::from)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    (answer, Vec::new())
}
