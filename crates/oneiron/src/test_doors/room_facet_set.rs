//! Door for `tests/room_facet_set.rs` (L7-39 PR 2, the room facet set):
//! the owner's door that sets a project's room facet set, and the field a
//! writer signs it in.

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::workspace_roster::{OwnerProjectSigner, ProjectProofVersion, ProjectRecord};
use crate::{EntityId, Vault};
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
