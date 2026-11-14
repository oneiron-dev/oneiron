//! Door for `tests/room_facet_set.rs` (L7-39 PR 2, the room facet set):
//! the owner's door that sets a project's room facet set, the field a
//! writer signs it in, and the owner-signed birth a rooted vault requires of
//! a new project.
//!
//! RED SEAM: the base holds no room facet set, so this door writes nothing
//! and a writer signs v3 with no set. The fix commit routes both to the
//! engine.

use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::workspace_roster::{OwnerProjectSigner, ProjectProofVersion, ProjectRecord};
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, EntityId, Vault};
use std::collections::BTreeSet;

/// The owner sets `project`'s room facet set; `None` drops it.
pub fn set_room_facets(
    _vault: &Vault,
    _owner: &AuthenticatedOwner,
    _signer: &OwnerProjectSigner<'_>,
    _project: EntityId,
    _facets: Option<BTreeSet<EntityId>>,
) -> Result<()> {
    Ok(())
}

/// Puts `facets` on a row a writer signs next; returns the version that
/// signs it.
pub fn with_room_facets(
    _record: &mut ProjectRecord,
    _facets: Option<BTreeSet<EntityId>>,
) -> ProjectProofVersion {
    ProjectProofVersion::V3
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
