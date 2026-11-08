//! The bytes of an interpreted ASSET body file in the batch door (FIX
//! 22075): text, a container or a body a stream rule hits lives in its file,
//! and its put queues the file's manifest. The door's secret scan and mask
//! read such a put's file bytes in place of its manifest, as they read a
//! body in its row: a key in the text or in a member is marked by the
//! file's digest, or refuses, exactly as it would in the row. The put then
//! keeps its manifest.

use std::collections::HashMap;

use zeroize::{Zeroize, Zeroizing};

use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_ASSET;

/// Puts each interpreted body file's bytes in its ASSET put, in place of
/// the manifest it queued, and returns those manifests. A put names one
/// file; an id the batch puts twice reads its bytes at its first put.
pub(super) fn read_file_bodies(
    ops: &mut [BatchOp],
    mut bodies: HashMap<EntityId, Vec<u8>>,
) -> HashMap<EntityId, Vec<u8>> {
    let mut manifests = HashMap::new();
    if bodies.is_empty() {
        return manifests;
    }
    for op in ops.iter_mut() {
        if let BatchOp::Put {
            id,
            entity_type,
            data,
            ..
        } = op
            && *entity_type == ENTITY_TYPE_ASSET
            && let Some(body) = bodies.remove(id)
        {
            manifests.insert(*id, std::mem::replace(data, body));
        }
    }
    // A body no put names reads nowhere.
    for body in bodies.values_mut() {
        body.zeroize();
    }
    manifests
}

/// Puts each manifest [`read_file_bodies`] took back in its ASSET put, and
/// returns the file bytes it held, wiped when dropped: that put's adapter
/// checks and custody read them (FIX 22091).
pub(super) fn restore_manifests(
    ops: &mut [BatchOp],
    mut manifests: HashMap<EntityId, Vec<u8>>,
) -> HashMap<EntityId, Zeroizing<Vec<u8>>> {
    let mut bodies = HashMap::new();
    if manifests.is_empty() {
        return bodies;
    }
    for op in ops.iter_mut() {
        if let BatchOp::Put {
            id,
            entity_type,
            data,
            ..
        } = op
            && *entity_type == ENTITY_TYPE_ASSET
            && let Some(manifest) = manifests.remove(id)
        {
            bodies.insert(*id, Zeroizing::new(std::mem::replace(data, manifest)));
        }
    }
    bodies
}
