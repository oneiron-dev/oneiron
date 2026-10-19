//! The person's outline Keep and Decline use the same proof as other owner doors.
use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::blob_artifact::deck_creation::{DeckOutlineDeclined, DeckOutlineSettleRequest};
use oneiron::edit_roundtrip::deck_create::KeptOutline;
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

pub(crate) async fn vault_artifacts_keep_outline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: DeckOutlineSettleRequest,
) -> Listed<KeptOutline> {
    const VERB: &str = "vault.artifacts.keep_outline";
    let proof = match owner_proof(auth, server, VERB) {
        Ok(proof) => proof,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.artifacts_keep_outline_as_owner(&proof, &input)
    })
    .await
}

pub(crate) async fn vault_artifacts_decline_outline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: DeckOutlineSettleRequest,
) -> Listed<DeckOutlineDeclined> {
    const VERB: &str = "vault.artifacts.decline_outline";
    let proof = match owner_proof(auth, server, VERB) {
        Ok(proof) => proof,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.artifacts_decline_outline_as_owner(&proof, &input)
    })
    .await
}
