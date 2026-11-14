//! Door for `tests/room_facet_set.rs` (L7-39 PR 2, the room facet set, and
//! PR 3, its owner verb): the owner's door that sets a project's room facet
//! set, the request the verb's host door runs it from, the field a writer
//! signs it in, and the owner-signed birth a rooted vault requires of a new
//! project.

use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::workspace_roster::{OwnerProjectSigner, ProjectProofVersion, ProjectRecord};
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, EntityId, Vault};
use std::collections::BTreeSet;

/// `vault.projects.room_facets.set` as its host door runs it: `request` is
/// the verb's input, signed with the host's owner project signer. Answers
/// the verb's output, or the refusal as text.
pub fn set_room_facets_by_request(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    signer: &OwnerProjectSigner<'_>,
    request: serde_json::Value,
) -> std::result::Result<serde_json::Value, String> {
    let request = serde_json::from_value(request).map_err(|error| error.to_string())?;
    let state = crate::workspace_roster::set_project_room_facets_from_request_as(
        vault, owner, signer, request,
    )
    .map_err(|error| format!("{error:?}"))?;
    serde_json::to_value(state).map_err(|error| error.to_string())
}

/// The owner sets `project`'s room facet set; `None` drops it.
pub fn set_room_facets(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    signer: &OwnerProjectSigner<'_>,
    project: EntityId,
    facets: Option<BTreeSet<EntityId>>,
) -> Result<()> {
    vault
        .set_project_room_facets(owner, signer, project, facets)
        .map(drop)
}

/// Puts `facets` on a row a writer signs next; returns the version that
/// signs it.
pub fn with_room_facets(
    record: &mut ProjectRecord,
    facets: Option<BTreeSet<EntityId>>,
) -> ProjectProofVersion {
    record.room_facets = facets;
    record.signing_version()
}

/// The owner's birth of project `id` from `record` in a vault rooted under
/// `issuer`, as a rooted vault requires of a new project: the depth birth is
/// signed with the host key that `test_support::bind_host_owner` binds to
/// `owner`, and the first state with the owner's project signer (the shape
/// of the server tests' `create_owned_project`).
pub fn create_owner_project(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_proof: &AuthenticatedOwner,
    signer: &OwnerProjectSigner<'_>,
    owner: EntityId,
    id: EntityId,
    record: &ProjectRecord,
) -> Result<()> {
    vault.create_project_with_owner(
        id,
        record,
        &WriteActor::new(owner, EdgeActorClass::Human),
        1,
        issuer.public_key(),
        |message| Ok(issuer.sign_claim_handoff(message).to_vec()),
        owner_proof,
        signer,
    )
}
