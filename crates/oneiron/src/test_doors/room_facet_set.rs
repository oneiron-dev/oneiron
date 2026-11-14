//! Door for `tests/room_facet_set.rs` (L7-39 PR 2, the room facet set, and
//! PR 3, its owner verb): the owner's door that sets a project's room facet
//! set, the request the verb's host door runs it from, and the field a
//! writer signs it in.

use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::workspace_roster::{OwnerProjectSigner, ProjectProofVersion, ProjectRecord};
use crate::{EntityId, Vault};
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
    // RED SEAM: no request door runs the owner's set yet.
    let _ = (vault, owner, signer, request);
    Err("vault.projects.room_facets.set has no door".to_owned())
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
