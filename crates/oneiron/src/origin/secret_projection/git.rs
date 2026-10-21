//! The exact-source identity (FIX 7608, owner ruling A2): an export back to
//! a repo's own original source is exact, public or private. Slice 2a names
//! the witness only; it checks nothing, gates no send and changes no
//! export. A later slice proves it from a G7 external source claim or a G4
//! import anchor, and a `None` there means "not proved the original
//! source", never "refuse the owner's export".

use crate::entity_id::EntityId;
use crate::git_wire::GitOid;

/// One canonical export OID proved to return to the source it came from.
#[allow(
    dead_code,
    reason = "FIX 7608 slice 2a: the identity is named here; its check lands with slice 9"
)]
#[derive(Debug)]
pub(crate) struct ExactSourceExportProof {
    source_claim: EntityId,
    original: GitOid,
}
