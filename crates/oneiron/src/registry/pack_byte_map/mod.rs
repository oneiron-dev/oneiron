//! Per-vault runtime-kind handles. Names are identity; bytes are local intern handles.
//!
//! ASSET snapshots are sync/export DATA. Only a local install command advances
//! the local head pin. A foreign snapshot cannot install code or grant authority.

mod doors;
mod hex_bytes;
mod persistence;
mod revisions;
mod state;
mod types;

pub use types::{
    PackByteMapSnapshot, PackInstanceEnvelope, PackInstanceOrigin, PackKindIdentity,
    PackKindRegistration, StructuralKindAllocation,
};

/// Whether ASSET `id` with a body whose BLAKE3 is `digest` is a local pack
/// map carrier: its id derives from its body's hash. Its reader and its
/// writer's collision guard read and hash the stored row, so the file plane
/// keeps it in its row (FIX 22091).
pub(crate) fn names_pack_map_carrier(id: &crate::EntityId, digest: &[u8; 32]) -> bool {
    persistence::carrier_id(digest).is_ok_and(|carrier| carrier == *id)
}

#[cfg(test)]
mod tests;
