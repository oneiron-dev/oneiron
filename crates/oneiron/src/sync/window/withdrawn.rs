//! Withdrawn generations in a window's live map (OF-013, FIX 931).
//!
//! A withdrawn epoch summary keeps a content-free keyframe in its row, and a
//! withdrawn reply copy keeps its header alone, its Shell. Their carriers in
//! every window owe the same: an `entities` carrier of the withdrawn
//! generation or older holds the keyframe envelope or the Shell its cutoff
//! names, never the words. A newer generation stays as it is. The historical
//! sweep rewrites these carriers before each shallow export; egress rewrites a
//! live one before the window persists or ships, and pins the window
//! history-free until the sweep drops the history.

use std::collections::{BTreeMap, BTreeSet};

use loro::{CommitOptions, LoroDoc, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::map_insert_bytes;
use super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::deletion::{WithdrawnCutoff, WithdrawnReplacement};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SUMMARY;

/// What one pass over a doc's `entities` carriers did.
#[derive(Debug, Default)]
pub(crate) struct WithdrawnCarriers {
    /// Carriers rewritten to their stand-in.
    pub(crate) replaced: u64,
    /// Artifacts with a carrier of a withdrawn generation that has no
    /// stand-in: its header does not parse, or a keyframe's cutoff finds no
    /// epoch summary. The carrier stays, and the artifact's obligation waits.
    pub(crate) held: BTreeSet<EntityId>,
}

/// Whether `blob`, a carrier of `id`, holds a withdrawn generation's words:
/// an envelope at or below `id`'s cutoff whose body is not the content-free
/// form its replacement names. A keyframe's cutoff takes the keyframe, or the
/// header-only stand-in of an epoch summary that kept none (FIX 2506); a
/// Shell's takes the header alone (FIX 931). A carrier whose header does not
/// parse cannot show its generation and counts as withdrawn.
pub(crate) fn withdrawn_body(
    cutoffs: &BTreeMap<EntityId, WithdrawnCutoff>,
    id: &EntityId,
    blob: &[u8],
) -> bool {
    let Some(cutoff) = cutoffs.get(id) else {
        return false;
    };
    match EntityMetadataHeader::parse(blob) {
        Some(header) => {
            let body = &blob[ENTITY_METADATA_HEADER_LEN..];
            let word_free = match cutoff.replacement {
                WithdrawnReplacement::EpochKeyframe => {
                    (body.is_empty() && header.entity_type == ENTITY_TYPE_SUMMARY)
                        || crate::compaction::is_withdrawn_keyframe(body)
                }
                WithdrawnReplacement::Shell => body.is_empty(),
            };
            header.learned_at <= cutoff.generation && !word_free
        }
        None => true,
    }
}

/// Rewrites every `entities` carrier in `doc` that holds a withdrawn
/// generation's words to its stand-in, uncommitted. A keyframe's stand-in is
/// the local row when it is that same generation's keyframe, else the
/// keyframe the carrier's own body keeps under the carrier's own header, or
/// that header alone when its body keeps none (FIX 2506). A Shell's is the
/// carrier's own parsed header, byte for byte, and never a local row.
pub(crate) fn replace_withdrawn_carriers(
    vault: &Vault,
    doc: &LoroDoc,
    cutoffs: &BTreeMap<EntityId, WithdrawnCutoff>,
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
        let shell = cutoffs
            .get(&id)
            .is_some_and(|cutoff| cutoff.replacement == WithdrawnReplacement::Shell);
        let stand_in = if shell {
            // A carrier whose header does not parse has no Shell: it is held.
            EntityMetadataHeader::parse(&blob).map(|_| blob[..ENTITY_METADATA_HEADER_LEN].to_vec())
        } else {
            let local = vault.store.port_entity_raw(&rtxn, &id)?.filter(|local| {
                local.get(..ENTITY_METADATA_HEADER_LEN) == blob.get(..ENTITY_METADATA_HEADER_LEN)
                    && crate::compaction::is_withdrawn_keyframe(
                        &local[ENTITY_METADATA_HEADER_LEN..],
                    )
            });
            match local {
                Some(local) => Some(local),
                None => crate::compaction::withdrawn_keyframe_envelope(&blob)?,
            }
        };
        match stand_in {
            Some(stand_in) => {
                map_insert_bytes(&entities, &key, &stand_in)?;
                found.replaced += 1;
            }
            None => {
                tracing::warn!(
                    entity = %id.to_hex(),
                    "withdrawn generation carrier has no stand-in; kept, its sweep waits"
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
