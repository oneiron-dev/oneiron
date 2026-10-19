//! PERSON identity setup, look-before-mint and saved-mention provenance.
//! Every owner-only door binds the caller's own credential-backed Memory.

use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::identity::{
    IdentityAnswerEvidenceRequest, IdentityMentionView, IdentitySettled, MentionProvenance,
};
use oneiron::memory::identity_doors::{
    IdentityLookup, IdentityLookupRequest, PersonCreateRequest, PersonCreated,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_people_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: PersonCreateRequest,
) -> Listed<PersonCreated> {
    const VERB: &str = "vault.people.create";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.people_create_as_owner(&owner, &input)
    }).await
}

pub(crate) async fn vault_entities_look_before_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: IdentityLookupRequest,
) -> Listed<IdentityLookup> {
    const VERB: &str = "vault.entities.look_before_mint";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.entities_look_before_mint_as_owner(&owner, &input)
    }).await
}

pub(crate) async fn vault_identity_mention(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: MentionProvenance,
) -> Listed<IdentityMentionView> {
    const VERB: &str = "vault.identity.mention";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.identity_mention_as_owner(&owner, &input)
    }).await
}

pub(crate) async fn self_identity_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: IdentityAnswerEvidenceRequest,
) -> Listed<IdentitySettled> {
    const VERB: &str = "self.identity.answer";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.identity_answer_with_evidence_as_owner(&owner, &input)
    }).await
}
