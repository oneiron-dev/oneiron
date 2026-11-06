//! The owner's saved proactivity digest, through the native screened read.

use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::digest::ProactivityDigestView;
use oneiron::memory::ProactivityDigestRequest;
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::support::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_proactivity_digest(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ProactivityDigestRequest,
) -> Listed<Option<ProactivityDigestView>> {
    const VERB: &str = "vault.proactivity.digest";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.proactivity_digest_as_owner(&owner, &input)
    })
    .await
}
