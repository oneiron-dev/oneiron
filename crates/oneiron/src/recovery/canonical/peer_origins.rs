//! The peer origins a window carries (FIX 2902), through canonical capture
//! and rebuild (FIX 4550). Kept apart from sync: the artifact holds the map's
//! rows as values, and only a row it keeps with the exact bytes an origin
//! names keeps that origin.

use loro::LoroDoc;
use serde::{Deserialize, Serialize};

use super::{ByteBudget, CanonicalSnapshot, binary_rows_within, id, insert, invalid, parse_id};
use crate::error::Result;

/// The window root map of peer origins, as sync files it.
const PEER_ORIGINS: &str = "peer_origins";

/// One row's peer origin: the blake3 digest of the whole entity blob a
/// peer's import brought for it, which the snapshot's row still holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPeerOrigin {
    pub id: [u8; 16],
    pub digest: [u8; 32],
}

/// Carries each origin `doc` holds for a row of the snapshot's final entity
/// set, sorted by id, when that row's blob is the one it names. An origin of
/// a row left out, or of other bytes, such as the body a retained shell
/// replaced, is dropped. A key that is not a canonical id, or a value that is
/// not a 32-byte digest, refuses the capture. The rows must be sorted.
pub(super) fn capture(
    doc: &LoroDoc,
    snapshot: &mut CanonicalSnapshot,
    budget: &mut ByteBudget,
) -> Result<()> {
    for (key, value) in binary_rows_within(doc, PEER_ORIGINS, budget)? {
        let entity = parse_id(&key)?;
        let digest: [u8; 32] = value
            .try_into()
            .map_err(|_| invalid("peer origin digest"))?;
        let held = snapshot
            .entity_blobs
            .binary_search_by_key(&entity, |row| row.id)
            .ok()
            .map(|at| *blake3::hash(&snapshot.entity_blobs[at].blob).as_bytes());
        if held == Some(digest) {
            snapshot
                .peer_origins
                .push(CanonicalPeerOrigin { id: entity, digest });
        }
    }
    snapshot.peer_origins.sort_by_key(|row| row.id);
    Ok(())
}

/// Files each origin back in the rebuilt window's map, beside its row.
pub(super) fn rebuild(doc: &LoroDoc, snapshot: &CanonicalSnapshot) -> Result<()> {
    for row in &snapshot.peer_origins {
        insert(doc, PEER_ORIGINS, &id(row.id)?.to_hex(), &row.digest)?;
    }
    Ok(())
}
