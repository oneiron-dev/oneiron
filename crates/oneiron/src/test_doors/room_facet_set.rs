//! Door for `tests/room_facet_set.rs` (L7-39 PR 2, the room facet set):
//! the owner's door that sets a project's room facet set, and the field a
//! writer signs it in.
//!
//! RED SEAM: the base holds no room facet set, so this door writes nothing
//! and a writer signs v3 with no set. The fix commit routes both to the
//! engine.

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::workspace_roster::{OwnerProjectSigner, ProjectProofVersion, ProjectRecord};
use crate::{EntityId, Vault};
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
