//! Withdrawn generations in a window's live map (OF-013).
//!
//! A withdrawn epoch summary keeps a content-free keyframe in its row, and its
//! carriers in every window owe the same: an `entities` carrier of the
//! withdrawn generation or older holds the keyframe envelope, never the words.
//! A newer generation stays as it is. The historical sweep rewrites these
//! carriers before each shallow export; egress rewrites a live one before the
//! window persists or ships, and pins the window history-free until the sweep
//! drops the history.

use std::collections::{BTreeMap, BTreeSet};

use loro::{CommitOptions, LoroDoc, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::map_insert_bytes;
use super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;

/// What one pass over a doc's `entities` carriers did.
#[derive(Debug, Default)]
pub(crate) struct WithdrawnCarriers {
    /// Carriers rewritten to their keyframe envelope.
    pub(crate) replaced: u64,
    /// Artifacts with a carrier of a withdrawn generation that keeps no
    /// keyframe to stand in for it. The carrier stays, and the artifact's
    /// obligation waits.
    pub(crate) held: BTreeSet<EntityId>,
}

/// Whether `blob`, a carrier of `id`, holds a withdrawn generation's words:
/// an envelope at or below `id`'s cutoff whose body is not the content-free
/// keyframe. A carrier whose header does not parse cannot show its
/// generation and counts as withdrawn.
pub(crate) fn withdrawn_body(
    cutoffs: &BTreeMap<EntityId, u64>,
    id: &EntityId,
    blob: &[u8],
) -> bool {
    let Some(cutoff) = cutoffs.get(id) else {
        return false;
    };
    match EntityMetadataHeader::parse(blob) {
        Some(header) => {
            header.learned_at <= *cutoff
                && !crate::compaction::is_withdrawn_keyframe(&blob[ENTITY_METADATA_HEADER_LEN..])
        }
        None => true,
    }
}

/// Rewrites every `entities` carrier in `doc` that holds a withdrawn
/// generation's words to its keyframe envelope, uncommitted. The stand-in is
/// the local row when it is that same generation's keyframe, else the
/// keyframe the carrier's own body keeps under the carrier's own header.
pub(crate) fn replace_withdrawn_carriers(
    vault: &Vault,
    doc: &LoroDoc,
    cutoffs: &BTreeMap<EntityId, u64>,
) -> Result<WithdrawnCarriers> {
    let mut found = WithdrawnCarriers::default();
    if cutoffs.is_empty() {
        return Ok(found);
    }
    let entities = doc.get_map("entities");
    let mut words = Vec::new();
    entities.for_each(|key, value| {
        let Ok(id) = EntityId::from_hex(key) else {
            return;
        };
        if !cutoffs.contains_key(&id) {
            return;
        }
        match value {
            ValueOrContainer::Value(LoroValue::Binary(blob)) => {
                if withdrawn_body(cutoffs, &id, &blob) {
                    words.push((key.to_owned(), id, blob.to_vec()));
                }
            }
            // No engine writes any other shape; it cannot show it is free
            // of words.
            _ => {
                found.held.insert(id);
            }
        }
    });
    if words.is_empty() {
        return Ok(found);
    }
    let rtxn = vault.store.env.read_txn()?;
    for (key, id, blob) in words {
        let local = vault.store.port_entity_raw(&rtxn, &id)?.filter(|local| {
            local.get(..ENTITY_METADATA_HEADER_LEN) == blob.get(..ENTITY_METADATA_HEADER_LEN)
                && crate::compaction::is_withdrawn_keyframe(&local[ENTITY_METADATA_HEADER_LEN..])
        });
        let stand_in = match local {
            Some(local) => Some(local),
            None => crate::compaction::withdrawn_keyframe_envelope(&blob)?,
        };
        match stand_in {
            Some(stand_in) => {
                map_insert_bytes(&entities, &key, &stand_in)?;
                found.replaced += 1;
            }
            None => {
                tracing::warn!(
                    entity = %id.to_hex(),
                    "withdrawn generation carrier keeps no keyframe; kept, its sweep waits"
                );
                found.held.insert(id);
            }
        }
    }
    Ok(found)
}

/// The export-side backstop while a withdrawn generation's sweep waits: a
/// live carrier of its words becomes the keyframe envelope before the window
/// persists or ships, and the window is pinned history-free so the words its
/// history still holds do not ship with it. `true` when the window holds such
/// a carrier.
pub(super) fn scrub_withdrawn_generation_carriers(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<bool> {
    let (cutoffs, floors) = {
        let rtxn = vault.store.env.read_txn()?;
        (
            crate::deletion::withdrawn_generation_cutoffs_in_txn(&vault.store, &rtxn)?,
            crate::compaction::epoch_floors_in_txn(&vault.store, &rtxn)?,
        )
    };
    // Each cutoff rides the windows that carry its artifact, so another
    // machine of this vault owes the same sweep (OF-013), and each epoch
    // floor the windows that carry its session, so it numbers past the same
    // removed epoch (FIX 2867).
    let mirrored = crate::sync::withdrawn_cutoffs::mirror_withdrawn_cutoffs(doc, &cutoffs)?;
    if crate::sync::withdrawn_cutoffs::mirror_epoch_floors(doc, &floors)? || mirrored {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    let found = replace_withdrawn_carriers(vault, doc, &cutoffs)?;
    if found.replaced == 0 && found.held.is_empty() {
        return Ok(false);
    }
    super::egress::require_history_free_window(vault, key)?;
    if found.replaced > 0 {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(true)
}
