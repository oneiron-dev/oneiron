//! A window blob as a sync peer gets it, and a peer's blob as this window
//! takes it (FIX 7608 slice 4, part 2).
//!
//! **Outgoing**, every blob (snapshot, shallow snapshot or update) is split
//! by the vendored root-map checkpoint, as pad custody's inflation splits it
//! (`window::pad_custody::inflate`): each row value of a marked item becomes
//! its copy, every key naming a marked source names its copy across the
//! whole skeleton (retained operations, shallow-root winners and latest
//! winners alike), and the join rebuilds a blob of the same kind over the
//! same op ids, dependencies, versions and frontiers. A shallow root's
//! winners travel inside the capture, so no root state leaves raw and no
//! unrelated root is built (GAP 4a). Capture takes only root-map register
//! documents, so every operation keeps its one unit (C1). An update is
//! rebuilt on an isolated copy holding its dependencies and exported again
//! over exactly its own op spans.
//!
//! **Incoming**, an update is imported on an isolated copy of the window, its
//! own spans are read back as JSON and translated onto their sources
//! ([`SyncSecretProjection::translate_history`]: copy keys to source keys,
//! copy rows to the stored bytes or the shipped visible diff), then encoded
//! again over the same spans on a second copy that does not hold them. A
//! held row write becomes a causally equivalent delete in an empty map;
//! its source stays unchanged. Full snapshots can retain these neutral causal
//! units through a same-span snapshot; shallow tails can too when their root
//! is independently readable, with only the matching held frontier winner
//! retargeted to the same neutral causal unit. Other coupled and mixed-edge
//! holds retain their whole-blob hold path.
//!
//! A blob nothing marked touches goes as it came. One the checkpoint cannot
//! take goes as it came only when its operations and state carry nothing
//! marked; otherwise it is withheld (never released raw), and stays owed to
//! the peer: nothing here retires, acknowledges or deletes it.

mod shallow_tail;
mod snapshot;
mod window_blobs;

use std::borrow::Cow;
use std::collections::BTreeMap;

use loro::checkpoint::{AtomId, Capture, Classify, Field, OwnerId, Parts, Payload, Skeleton};
use loro::json::{JsonOpContent, JsonSchema, MapOp};
use loro::{
    ContainerID, ContainerType, EncodedBlobMode, ExportMode, IdSpan, ImportBlobMetadata, LoroDoc,
    LoroValue, VersionVector,
};
use oneiron_contracts::fingerprint::ContentHash;

use super::history::needs_whole_hold;
use super::rows::{HeldEdit, Landing};
use super::{CopyRow, InboundRow, SyncSecretProjection};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncError};
use crate::store::Store;

/// The root map whose values are rows.
const ROWS: &str = "entities";

/// Why a marked blob is withheld rather than released.
const UNMASKABLE: &str =
    "a window blob carrying a marked repo item the checkpoint cannot mask is withheld";

/// Why a blob carrying an item whose copy is unread this pass is withheld.
const UNREAD: &str = "a window blob carrying a marked repo item whose copy is unread is withheld";

/// Why a peer's write of a row whose copy is unread this pass is not admitted.
const UNREAD_EDIT: &str = "a write of a marked repo row whose copy is unread is not admitted";

/// What a peer's window blob becomes here.
pub(crate) enum WindowAdmission<'a> {
    /// Import these bytes as today: the blob as it came, or translated onto
    /// its sources, with the new bytes they land (FIX 10732).
    Admit(Cow<'a, [u8]>, Vec<Landing>, Vec<HeldEdit>),
    /// Edits of a copy the visible diff holds on a ruled cause: nothing of the
    /// blob persists, imports or relays, and no edit of it is ever applied.
    Held(Vec<HeldEdit>),
}

/// Every key a plain one, every value one holder's: the skeleton is joined at
/// once and never kept.
struct OneHolder;

impl Classify for OneHolder {
    fn plain_key(&mut self, _root: &str, _key: &str) -> bool {
        true
    }

    fn holders(&mut self, _field: Field<'_>) -> Option<Vec<OwnerId>> {
        Some(vec![1])
    }
}

/// Where one value atom sits: its root map and key.
struct Site {
    root: u32,
    key: String,
}

impl SyncSecretProjection {
    /// The copy generation `doc`'s state carries: one fingerprint over the
    /// stamp of every marked row it holds, a known copy id's row included
    /// (FIX 10795), and an unread copy as [`SyncSecretProjection::unread_stamp`]; `None`
    /// when it holds none.
    pub(crate) fn window_generation(&self, doc: &LoroDoc) -> Option<[u8; 32]> {
        if self.is_empty() {
            return None;
        }
        let LoroValue::Map(roots) = doc.get_deep_value() else {
            return None;
        };
        let Some(LoroValue::Map(rows)) = roots.get(ROWS) else {
            return None;
        };
        let mut carried = BTreeMap::new();
        for (key, value) in rows.iter() {
            let (Ok(id), LoroValue::Binary(raw)) = (EntityId::from_hex(key), value) else {
                continue;
            };
            let bound = self.source_hash(&id).or_else(|| {
                self.source_of_copy(&id)
                    .and_then(|source| self.source_hash(&source))
            });
            let hash = match bound {
                Some(hash) => *hash,
                None => match raw.get(ENTITY_METADATA_HEADER_LEN..) {
                    Some(body) => *ContentHash::of(body).as_bytes(),
                    None => continue,
                },
            };
            if let Some(stamp) = self.stamp_of(&hash) {
                carried.insert(id, stamp);
            }
        }
        if carried.is_empty() {
            return None;
        }
        let mut hasher = blake3::Hasher::new_derive_key(super::GENERATION_CONTEXT);
        hasher.update(&Self::SCHEMA.to_be_bytes());
        for (id, stamp) in carried {
            hasher.update(id.as_bytes());
            hasher.update(&stamp);
        }
        Some(*hasher.finalize().as_bytes())
    }

    /// Whether `row`'s body is a copy this pass makes.
    fn is_copy_row(&self, row: &[u8]) -> bool {
        row.get(ENTITY_METADATA_HEADER_LEN..).is_some_and(|body| {
            self.copy_body_source_hash(ContentHash::of(body).as_bytes())
                .is_some()
        })
    }

    /// Each row value of `json` held as a pad reference whose pad is here, and
    /// whose carrier is a copy, as that carrier: the visible diff reads copy
    /// bytes, never a reference. Every other value stays as it came.
    fn resolve_copy_carriers(&self, store: &Store, json: &mut JsonSchema) {
        resolve_carriers(store, json, |key, carrier| {
            EntityId::from_hex(key).is_ok_and(|id| self.binds(&id)) || self.is_copy_row(carrier)
        });
    }
}

/// Each row value of `json` held as a pad reference whose pad is here, and
/// whose carrier `take` takes, as that carrier.
fn resolve_carriers<F>(store: &Store, json: &mut JsonSchema, take: F)
where
    F: Fn(&str, &[u8]) -> bool,
{
    for change in &mut json.changes {
        for op in &mut change.ops {
            let ContainerID::Root {
                name,
                container_type: ContainerType::Map,
            } = &op.container
            else {
                continue;
            };
            if name.as_str() != ROWS {
                continue;
            }
            let JsonOpContent::Map(MapOp::Insert { key, value }) = &mut op.content else {
                continue;
            };
            let LoroValue::Binary(raw) = &*value else {
                continue;
            };
            let Some(carrier) = crate::world_keys::image_pad_row(store, raw) else {
                continue;
            };
            if take(key, &carrier) {
                *value = LoroValue::Binary(carrier.into());
            }
        }
    }
}

/// `doc` split into its skeleton and values, over every root map it holds.
fn parts_of(doc: &LoroDoc) -> Option<Parts> {
    let LoroValue::Map(roots) = doc.get_value() else {
        return None;
    };
    let roots: Vec<&str> = roots.keys().map(String::as_str).collect();
    match doc.export_root_map_checkpoint(&roots, &mut OneHolder) {
        Capture::Classified(parts) => Some(parts),
        Capture::Unclassified(_) => None,
    }
}

fn joined(parts: &Parts) -> Result<Vec<u8>> {
    LoroDoc::join_root_map_checkpoint(&parts.skeleton, &parts.atoms, &[])
        .map(|joined| joined.bytes)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportSnapshot, e))
}

fn meta(encoded: &[u8]) -> Option<ImportBlobMetadata> {
    LoroDoc::decode_import_blob_meta(encoded, true).ok()
}

fn same_span(input: &ImportBlobMetadata, out: &ImportBlobMetadata, kind: &EncodedBlobMode) -> bool {
    out.mode == *kind
        && out.partial_start_vv == input.partial_start_vv
        && out.partial_end_vv == input.partial_end_vv
        && out.start_frontiers == input.start_frontiers
}

fn decode(context: &'static str) -> impl FnOnce(loro::LoroError) -> Error {
    move |source| Error::Sync(SyncError::CrdtDecodeError { context, source })
}

/// One cut of a window: the snapshot an isolated copy of it is read from,
/// made once and read into each copy one release or admission takes (FIX
/// 10599).
struct WindowCut(Vec<u8>);

impl WindowCut {
    /// `context` cut through the checkpoint so a shallow root stays one, or
    /// as a plain snapshot when the checkpoint does not take it (FIX 10794),
    /// with its first isolated copy. `None` when neither copy reads.
    fn of(context: &LoroDoc) -> Option<(Self, LoroDoc)> {
        let read = |bytes: Vec<u8>| {
            LoroDoc::from_snapshot(&bytes)
                .ok()
                .map(|doc| (Self(bytes), doc))
        };
        parts_of(context)
            .and_then(|parts| joined(&parts).ok())
            .and_then(read)
            .or_else(|| context.export(ExportMode::Snapshot).ok().and_then(read))
    }

    /// Another isolated copy of the cut window.
    fn copy(&self) -> Option<LoroDoc> {
        LoroDoc::from_snapshot(&self.0).ok()
    }
}

/// An isolated copy of `context` ([`WindowCut::of`]); a fresh document
/// without one. `None` when neither copy reads.
pub(super) fn isolated(context: Option<&LoroDoc>) -> Option<LoroDoc> {
    let Some(context) = context else {
        return Some(LoroDoc::new());
    };
    WindowCut::of(context).map(|(_, doc)| doc)
}

/// Whether every operation `doc` holds from `start` on is still history,
/// not folded into a shallow root: its JSON from `start` is then whole.
fn readable_from(doc: &LoroDoc, start: &VersionVector) -> bool {
    doc.shallow_since_vv()
        .to_vv()
        .iter()
        .all(|(peer, counter)| start.get(peer).copied().unwrap_or(0) >= *counter)
}

/// An isolated copy of `context` holding the update `encoded` as well, with
/// the window's cut when the copy was made from the window rather than a
/// fresh document; `None` when the update does not import whole on it (a
/// dependency it does not hold).
fn with_update(context: Option<&LoroDoc>, encoded: &[u8]) -> Option<(LoroDoc, Option<WindowCut>)> {
    let input = meta(encoded);
    // A self-contained update (a detached selector document's) imports on a
    // fresh document first, so it never merges into the window's own state.
    let fresh = input
        .as_ref()
        .is_some_and(|input| input.partial_start_vv.values().all(|start| *start == 0));
    let mut tries = Vec::with_capacity(2);
    if fresh {
        tries.push(None);
    }
    if context.is_some() || !fresh {
        tries.push(context);
    }
    for context in tries {
        let (scratch, cut) = match context {
            Some(window) => match WindowCut::of(window) {
                Some((cut, scratch)) => (scratch, Some(cut)),
                None => continue,
            },
            None => (LoroDoc::new(), None),
        };
        let Ok(status) = scratch.import(encoded) else {
            continue;
        };
        let held = scratch.oplog_vv();
        let complete = input.as_ref().is_some_and(|input| {
            input
                .partial_end_vv
                .iter()
                .all(|(peer, end)| held.get(peer).is_some_and(|held| held >= end))
        });
        if status.pending.is_none() && complete {
            return Some((scratch, cut));
        }
    }
    None
}

/// The op spans an update blob carries.
fn spans_of(input: &ImportBlobMetadata) -> Vec<IdSpan> {
    let mut spans: Vec<IdSpan> = input
        .partial_end_vv
        .iter()
        .filter_map(|(peer, end)| {
            let start = input.partial_start_vv.get(peer).copied().unwrap_or(0);
            (*end > start).then(|| IdSpan::new(*peer, start, *end))
        })
        .collect();
    spans.sort_by_key(|span| span.peer);
    spans
}

/// Each value atom's root map and key: retained operations first, then
/// shallow-root and latest winners not otherwise placed.
fn sites(skeleton: &Skeleton) -> BTreeMap<AtomId, Site> {
    let mut sites = BTreeMap::new();
    for change in &skeleton.changes {
        for op in &change.ops {
            if let Some(atom) = op.value {
                sites.insert(
                    atom,
                    Site {
                        root: op.root,
                        key: op.key.clone(),
                    },
                );
            }
        }
    }
    let winners = skeleton
        .shallow
        .iter()
        .flat_map(|root| &root.winners)
        .chain(&skeleton.latest);
    for winner in winners {
        if let Some(atom) = winner.value {
            sites.entry(atom).or_insert_with(|| Site {
                root: winner.root,
                key: winner.key.clone(),
            });
        }
    }
    sites
}

/// The entity a row atom is the value of; `None` for any other atom.
fn row_site(sites: &BTreeMap<AtomId, Site>, rows: Option<usize>, atom: AtomId) -> Option<EntityId> {
    let site = sites.get(&atom)?;
    (rows == usize::try_from(site.root).ok())
        .then(|| EntityId::from_hex(&site.key).ok())
        .flatten()
}

/// Every key of `skeleton` (operations, shallow-root and latest winners)
/// `alias` names, replaced; whether any was. One rule for every site keeps
/// the joined document's state and history the same map.
fn rekey_skeleton<F>(skeleton: &mut Skeleton, alias: F) -> bool
where
    F: Fn(&str) -> Option<String>,
{
    let mut changed = false;
    let ops = skeleton
        .changes
        .iter_mut()
        .flat_map(|change| change.ops.iter_mut())
        .map(|op| &mut op.key);
    let shallow = skeleton
        .shallow
        .iter_mut()
        .flat_map(|root| root.winners.iter_mut())
        .map(|winner| &mut winner.key);
    let latest = skeleton.latest.iter_mut().map(|winner| &mut winner.key);
    for key in ops.chain(shallow).chain(latest) {
        if let Some(aliased) = alias(key.as_str()) {
            *key = aliased;
            changed = true;
        }
    }
    changed
}
