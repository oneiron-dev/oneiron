//! Door for `tests/room_facet_set.rs` (L7-39 PR 2, the room facet set):
//! the owner's door that sets a project's room facet set, the field a
//! writer signs it in, and the owner-signed birth a rooted vault requires of
//! a new project.

use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::workspace_roster::{OwnerProjectSigner, ProjectProofVersion, ProjectRecord};
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, EntityId, Vault};
use std::collections::BTreeSet;

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
