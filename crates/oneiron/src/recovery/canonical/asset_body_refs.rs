//! The by-reference ASSET body references a window carries (FIX 5489),
//! through canonical capture and rebuild. A reference rides beside the
//! carrier it binds, never alone: the capture keeps each one that binds the
//! exact carrier the snapshot holds for its id, and a window rebuilt from
//! the artifact files it back beside that carrier, so its body still moves
//! by reference. Rows keep the window map's grammar
//! (`sync::asset_body::references`): the owner's canonical hex id, then the
//! reference's own bytes.

use loro::LoroDoc;
use serde::{Deserialize, Serialize};

#[cfg(feature = "sync")]
use super::{ByteBudget, binary_rows_within};
use super::{CanonicalSnapshot, id, insert, invalid};
use crate::EntityId;
use crate::error::Result;

/// The window root map of references, as sync files it.
const ASSET_BODY_REFS: &str = "asset_body_refs";

/// One reference of a window's map: its owner's id, and the reference's
/// bytes as the map holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAssetBodyRef {
    pub id: [u8; 16],
    pub value: Vec<u8>,
}

/// Carries each reference `doc` holds that binds the carrier the snapshot's
/// final entity set holds for its id, sorted by id. A reference that binds
/// another carrier, or one the snapshot left out, is dropped, as a filtered
/// copy of the window drops it; one that does not read is dropped with a
/// warning. Nothing is read while the file plane is off. The rows must be
/// sorted.
#[cfg(feature = "sync")]
pub(super) fn capture(
    doc: &LoroDoc,
    snapshot: &mut CanonicalSnapshot,
    budget: &mut ByteBudget,
) -> Result<()> {
    if !crate::store::ASSET_FILE_PLANE {
        return Ok(());
    }
    for (key, value) in binary_rows_within(doc, ASSET_BODY_REFS, budget)? {
        let Ok(owner) = EntityId::from_hex(&key) else {
            tracing::warn!(
                window = %snapshot.window,
                key = %key,
                "asset body reference malformed; left out of the canonical snapshot"
            );
            continue;
        };
        if bound(snapshot, owner, &value) {
            snapshot.asset_body_refs.push(CanonicalAssetBodyRef {
                id: *owner.as_bytes(),
                value,
            });
        }
    }
    snapshot.asset_body_refs.sort_by_key(|row| row.id);
    Ok(())
}

/// Whether `value`, read with the map's own codec under `owner`'s key,
/// binds the exact carrier `snapshot` holds for `owner`.
#[cfg(feature = "sync")]
fn bound(snapshot: &CanonicalSnapshot, owner: EntityId, value: &[u8]) -> bool {
    use crate::sync::asset_body::references::AssetBodyRef;
    AssetBodyRef::decode(&owner.to_hex(), value).is_some_and(|body| {
        snapshot
            .entity_blobs
            .binary_search_by_key(owner.as_bytes(), |row| row.id)
            .is_ok_and(|at| body.binds(&snapshot.entity_blobs[at].blob))
    })
}

/// A build without sync reads no reference: it takes one as it rests.
#[cfg(not(feature = "sync"))]
fn bound(_: &CanonicalSnapshot, _: EntityId, _: &[u8]) -> bool {
    true
}

impl CanonicalSnapshot {
    /// Each reference names a canonical id once, in id order, and binds the
    /// exact carrier the snapshot holds for that id.
    pub(in crate::recovery) fn validate_asset_body_refs(&self) -> Result<()> {
        crate::recovery::validation::strict(self.asset_body_refs.iter().map(|row| row.id))?;
        for row in &self.asset_body_refs {
            if !bound(self, id(row.id)?, &row.value) {
                return Err(invalid("asset body reference outside the window"));
            }
        }
        Ok(())
    }
}

/// Files one reference back in the rebuilt window's map, beside the carrier
/// it binds.
pub(super) fn rebuild_row(doc: &LoroDoc, row: &CanonicalAssetBodyRef) -> Result<()> {
    insert(doc, ASSET_BODY_REFS, &id(row.id)?.to_hex(), &row.value)
}
