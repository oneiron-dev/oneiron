//! The home's host-signed mesh bindings, served beside its authority catch-up
//! to a proven machine of the owner's (`residence.authority.mesh`,
//! MESH-AUTHORITY-REPLICATION). Nothing served is trusted there: the machine
//! imports a binding only when a live owner host of its own fold signed it
//! (`Vault::import_mesh_authority_rows`).

use super::authority_tail::require_owner_machine;
use crate::authority::{MeshAuthorityPage, PeerMachine};
use crate::error::Result;
use crate::{EntityId, Vault};

/// The bindings this home serves `peer` after MACHINE `after`, one page
/// ([`Vault::mesh_authority_page`]). Refused for any peer that is not a
/// machine of the owner's whose proof stands here, as the authority tail is.
///
/// # Errors
///
/// A refused peer; an authority history this vault cannot fold; storage
/// errors.
pub fn mesh_authority_for(
    vault: &Vault,
    peer: PeerMachine,
    after: Option<EntityId>,
) -> Result<MeshAuthorityPage> {
    require_owner_machine(vault, peer)?;
    vault.mesh_authority_page(after)
}
