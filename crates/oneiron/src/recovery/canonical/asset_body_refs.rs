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

/// Owned resumable validation of the window's asset body references: the
/// same strict-then-bind checks as the whole validator, a page at a time
/// over the same immutable snapshot. The strict pass pages id order with
/// the existing `strict` over the carried previous id chained with the
/// page, so no prefix is rechecked; the bind pass pages `id`/`bound` only
/// after every order check passed.
#[derive(Default)]
pub(super) struct AssetBodyRefsValidation {
    stage: AssetBodyRefsStage,
    strict_next: usize,
    strict_prev: Option<[u8; 16]>,
    bound_next: usize,
}

#[derive(Default)]
enum AssetBodyRefsStage {
    #[default]
    Strict,
    Bound,
}

impl AssetBodyRefsValidation {
    /// Validates one page; `true` once both passes passed.
    pub(super) fn advance(
        &mut self,
        snapshot: &CanonicalSnapshot,
        max_rows: usize,
    ) -> Result<bool> {
        let rows = &snapshot.asset_body_refs;
        let page = max_rows.max(1);
        if matches!(self.stage, AssetBodyRefsStage::Strict) {
            let end = self.strict_next.saturating_add(page).min(rows.len());
            crate::recovery::validation::strict(
                self.strict_prev
                    .into_iter()
                    .chain(rows[self.strict_next..end].iter().map(|row| row.id)),
            )?;
            if end > self.strict_next {
                self.strict_prev = Some(rows[end - 1].id);
            }
            self.strict_next = end;
            if self.strict_next < rows.len() {
                return Ok(false);
            }
            self.stage = AssetBodyRefsStage::Bound;
            if self.bound_next < rows.len() {
                return Ok(false);
            }
            return Ok(true);
        }
        let end = self.bound_next.saturating_add(page).min(rows.len());
        for row in &rows[self.bound_next..end] {
            if !bound(snapshot, id(row.id)?, &row.value) {
                return Err(invalid("asset body reference outside the window"));
            }
        }
        self.bound_next = end;
        Ok(self.bound_next >= rows.len())
    }

    pub(super) fn position(&self) -> String {
        match self.stage {
            AssetBodyRefsStage::Strict => format!("strict {}", self.strict_next),
            AssetBodyRefsStage::Bound => format!("bound {}", self.bound_next),
        }
    }
}

/// Files one reference back in the rebuilt window's map, beside the carrier
/// it binds.
pub(super) fn rebuild_row(doc: &LoroDoc, row: &CanonicalAssetBodyRef) -> Result<()> {
    insert(doc, ASSET_BODY_REFS, &id(row.id)?.to_hex(), &row.value)
}
