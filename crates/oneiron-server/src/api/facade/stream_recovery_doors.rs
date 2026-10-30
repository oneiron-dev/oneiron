//! The stream seeds the vault's open could not replay (FIX 11933), read
//! under the caller's own owner credential.
use std::sync::Arc;

use oneiron::memory::StreamRecoveryRefusal;
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::{Listed, off_runtime_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_message_streams_refused(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<StreamRecoveryRefusal>> {
    const VERB: &str = "vault.message_streams.refused";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    off_runtime_listing(VERB, move |_| {
        server
            .vault()
            .stream_recovery_refusals(&owner)
            .map_err(Into::into)
    })
    .await
}
