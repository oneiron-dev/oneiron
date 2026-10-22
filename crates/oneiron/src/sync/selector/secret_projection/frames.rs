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
//! ruled hold keeps the whole update the peer's pending work.
//!
//! A blob nothing marked touches goes as it came. One the checkpoint cannot
//! take goes as it came only when its operations and state carry nothing
//! marked; otherwise it is withheld (never released raw), and stays owed to
//! the peer: nothing here retires, acknowledges or deletes it.

use std::borrow::Cow;
use std::collections::BTreeMap;

use loro::checkpoint::{AtomId, Capture, Classify, Field, OwnerId, Parts, Payload, Skeleton};
use loro::json::{JsonOpContent, JsonSchema, MapOp};
use loro::{
    ContainerID, ContainerType, EncodedBlobMode, ExportMode, IdSpan, ImportBlobMetadata, LoroDoc,
    LoroValue, VersionVector,
};

use super::{CopyRow, InboundRow, SyncSecretProjection};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncError};
use crate::origin::secret_projection::edit::RepoProjectionDiffResult;
use crate::store::Store;

/// The root map whose values are rows.
const ROWS: &str = "entities";

/// Why a marked blob is withheld rather than released.
const UNMASKABLE: &str =
    "a window blob carrying a marked repo item the checkpoint cannot mask is withheld";

/// What a peer's window blob becomes here.
pub(crate) enum WindowAdmission<'a> {
    /// Import these bytes as today: the blob as it came, or translated onto
    /// its sources.
    Admit(Cow<'a, [u8]>),
    /// Edits of a copy the visible diff holds on a ruled cause: nothing of the
    /// blob persists, imports, relays or is acknowledged.
    Held(Vec<(EntityId, RepoProjectionDiffResult)>),
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
    /// `encoded`, a window blob leaving this device, as a sync peer gets it;
    /// `context` holds an update's dependencies, copied and never changed.
    /// `None` when nothing marked is in it: the caller sends it as it is.
    ///
    /// # Errors
    /// A store failure, or a blob carrying a marked item that cannot be
    /// masked: the caller withholds it and keeps it owed.
    pub(crate) fn release_window_blob(
        &self,
        store: &Store,
        encoded: &[u8],
        context: Option<&LoroDoc>,
    ) -> Result<Option<Vec<u8>>> {
        if self.is_empty() {
            return Ok(None);
        }
        let Some(input) = meta(encoded) else {
            return Ok(None);
        };
        match input.mode {
            EncodedBlobMode::Snapshot | EncodedBlobMode::ShallowSnapshot => {
                let doc =
                    LoroDoc::from_snapshot(encoded).map_err(decode("window copy snapshot"))?;
                let Some(mut parts) = parts_of(&doc) else {
                    return self.unclassified(&doc, &VersionVector::default(), &doc.oplog_vv());
                };
                if !self.release_parts(store, &mut parts) {
                    return Ok(None);
                }
                let bytes = joined(&parts)?;
                let out = meta(&bytes).ok_or(Error::InvariantViolation(UNMASKABLE))?;
                same_span(&input, &out, &input.mode)
                    .then_some(Some(bytes))
                    .ok_or(Error::InvariantViolation(UNMASKABLE))
            }
            EncodedBlobMode::Updates => {
                let Some(scratch) = with_update(context, encoded)? else {
                    return Err(Error::InvariantViolation(UNMASKABLE));
                };
                let spans = spans_of(&input);
                let Some(mut parts) = parts_of(&scratch) else {
                    return self.unclassified(
                        &scratch,
                        &input.partial_start_vv,
                        &input.partial_end_vv,
                    );
                };
                if !self.release_parts(store, &mut parts) {
                    return Ok(None);
                }
                let slice = scratch
                    .export(ExportMode::updates_in_range(spans.clone()))
                    .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
                let released = LoroDoc::from_snapshot(&joined(&parts)?)
                    .map_err(decode("window copy rebuild"))?;
                let bytes = released
                    .export(ExportMode::updates_in_range(spans))
                    .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
                let same = match (meta(&bytes), meta(&slice)) {
                    (Some(out), Some(slice)) => {
                        same_span(&input, &out, &EncodedBlobMode::Updates)
                            && out.change_num == slice.change_num
                    }
                    _ => false,
                };
                same.then_some(Some(bytes))
                    .ok_or(Error::InvariantViolation(UNMASKABLE))
            }
            EncodedBlobMode::OutdatedSnapshot | EncodedBlobMode::OutdatedRle => {
                let doc = LoroDoc::new();
                match doc.import(encoded) {
                    Ok(status) if status.pending.is_none() => {
                        self.unclassified(&doc, &VersionVector::default(), &doc.oplog_vv())
                    }
                    _ => Err(Error::InvariantViolation(UNMASKABLE)),
                }
            }
        }
    }

    /// `encoded`, a window blob a peer sent, as this window takes it;
    /// `context` is this window, copied and never changed. A blob that is
    /// not a copy, or one this device cannot read without the ordinary
    /// admission (missing dependencies, an unknown shape), is admitted as it
    /// came and judged there as today.
    ///
    /// # Errors
    /// A store failure, or the visible diff's own failure.
    pub(crate) fn admit_window_blob<'a>(
        &self,
        store: &Store,
        encoded: &'a [u8],
        context: Option<&LoroDoc>,
    ) -> Result<WindowAdmission<'a>> {
        let as_sent = || Ok(WindowAdmission::Admit(Cow::Borrowed(encoded)));
        if self.is_empty() {
            return as_sent();
        }
        let Some(input) = meta(encoded) else {
            return as_sent();
        };
        match input.mode {
            EncodedBlobMode::Snapshot | EncodedBlobMode::ShallowSnapshot => {
                let Ok(doc) = LoroDoc::from_snapshot(encoded) else {
                    return as_sent();
                };
                let Some(mut parts) = parts_of(&doc) else {
                    return as_sent();
                };
                let mut held = Vec::new();
                if !self.admit_parts(store, &mut parts, &mut held)? {
                    return as_sent();
                }
                if !held.is_empty() {
                    return Ok(WindowAdmission::Held(held));
                }
                Ok(WindowAdmission::Admit(Cow::Owned(joined(&parts)?)))
            }
            EncodedBlobMode::Updates => {
                let Some(scratch) = with_update(context, encoded)? else {
                    return as_sent();
                };
                let mut json =
                    scratch.export_json_updates(&input.partial_start_vv, &input.partial_end_vv);
                self.resolve_copy_carriers(store, &mut json);
                let translated = self.translate_history(&mut json)?;
                if !translated.held.is_empty() {
                    return Ok(WindowAdmission::Held(translated.held));
                }
                if translated.sources.is_empty() {
                    return as_sent();
                }
                let Some(target) = isolated(context)? else {
                    return as_sent();
                };
                let status = target
                    .import_json_updates(json)
                    .map_err(decode("window copy translation"))?;
                if status.pending.is_some() {
                    return as_sent();
                }
                let bytes = target
                    .export(ExportMode::updates_in_range(spans_of(&input)))
                    .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
                Ok(WindowAdmission::Admit(Cow::Owned(bytes)))
            }
            EncodedBlobMode::OutdatedSnapshot | EncodedBlobMode::OutdatedRle => as_sent(),
        }
    }

    /// Each marked row value of `parts` as its copy, and each key naming a
    /// marked source as its copy's, in place; whether any changed. A row held
    /// as a pad reference whose pad is here is judged by its carrier, so a
    /// marked row is never shipped as a reference whose pad carries it raw.
    fn release_parts(&self, store: &Store, parts: &mut Parts) -> bool {
        let rows = parts.skeleton.roots.iter().position(|root| root == ROWS);
        let sites = sites(&parts.skeleton);
        let mut changed = false;
        for atom in &mut parts.atoms {
            let Some(id) = row_site(&sites, rows, atom.id) else {
                continue;
            };
            let Payload::Value(LoroValue::Binary(raw)) = &atom.payload else {
                continue;
            };
            let raw: &[u8] = raw;
            let carrier = crate::world_keys::image_pad_row(store, raw);
            let projected = self.project_row(&id, carrier.as_deref().unwrap_or(raw));
            if let CopyRow::Copy { row, .. } = projected {
                atom.payload = Payload::Value(LoroValue::Binary(row.into()));
                changed = true;
            }
        }
        rekey_skeleton(&mut parts.skeleton, |key| self.rekey(key)) || changed
    }

    /// Each copy row value of `parts` as its source row, and each copy key as
    /// its source's, in place; whether any changed. Ruled holds go to `held`.
    fn admit_parts(
        &self,
        store: &Store,
        parts: &mut Parts,
        held: &mut Vec<(EntityId, RepoProjectionDiffResult)>,
    ) -> Result<bool> {
        let rows = parts.skeleton.roots.iter().position(|root| root == ROWS);
        let sites = sites(&parts.skeleton);
        let mut changed = false;
        for atom in &mut parts.atoms {
            let Some(id) = row_site(&sites, rows, atom.id) else {
                continue;
            };
            let Payload::Value(LoroValue::Binary(raw)) = &atom.payload else {
                continue;
            };
            let raw: &[u8] = raw;
            let carrier = crate::world_keys::image_pad_row(store, raw);
            match self.source_row(&id, carrier.as_deref().unwrap_or(raw))? {
                InboundRow::Source { row, .. } => {
                    atom.payload = Payload::Value(LoroValue::Binary(row.into()));
                    changed = true;
                }
                InboundRow::Held { id, cause } => held.push((id, cause)),
                InboundRow::Ordinary => {}
            }
        }
        Ok(rekey_skeleton(&mut parts.skeleton, |key| self.source_key(key)) || changed)
    }

    /// A blob the checkpoint does not take: released as it is only when
    /// neither its operations between `from` and `to` nor its state carry
    /// anything marked.
    fn unclassified(
        &self,
        doc: &LoroDoc,
        from: &VersionVector,
        to: &VersionVector,
    ) -> Result<Option<Vec<u8>>> {
        let mut json = doc.export_json_updates(from, to);
        let projected = self.project_history(&mut json);
        if !projected.changed.is_empty() || !projected.preserving || self.state_carries_marked(doc)
        {
            return Err(Error::InvariantViolation(UNMASKABLE));
        }
        Ok(None)
    }

    /// Whether any root map of `doc` holds a marked row or a key naming a
    /// marked source.
    fn state_carries_marked(&self, doc: &LoroDoc) -> bool {
        let LoroValue::Map(roots) = doc.get_deep_value() else {
            return false;
        };
        roots.iter().any(|(root, value)| {
            let LoroValue::Map(entries) = value else {
                return false;
            };
            entries.iter().any(|(key, value)| {
                if self.rekey(key).is_some() {
                    return true;
                }
                let (true, LoroValue::Binary(raw), Ok(id)) =
                    (root == ROWS, value, EntityId::from_hex(key))
                else {
                    return false;
                };
                self.project_row(&id, raw) != CopyRow::Keep
            })
        })
    }

    /// Whether `row`'s body is a copy this pass makes.
    fn is_copy_row(&self, row: &[u8]) -> bool {
        row.get(ENTITY_METADATA_HEADER_LEN..)
            .is_some_and(|body| self.copy_bodies.contains_key(blake3::hash(body).as_bytes()))
    }

    /// Each row value of `json` held as a pad reference whose pad is here, and
    /// whose carrier is a copy, as that carrier: the visible diff reads copy
    /// bytes, never a reference. Every other value stays as it came.
    fn resolve_copy_carriers(&self, store: &Store, json: &mut JsonSchema) {
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
                let copy = EntityId::from_hex(key).is_ok_and(|id| self.binds(&id))
                    || self.is_copy_row(&carrier);
                if copy {
                    *value = LoroValue::Binary(carrier.into());
                }
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

/// An isolated copy of `context`, through the checkpoint so a shallow root
/// stays one; a fresh document without one. `None` when the checkpoint does
/// not take `context`.
fn isolated(context: Option<&LoroDoc>) -> Result<Option<LoroDoc>> {
    let Some(context) = context else {
        return Ok(Some(LoroDoc::new()));
    };
    let Some(parts) = parts_of(context) else {
        return Ok(None);
    };
    LoroDoc::from_snapshot(&joined(&parts)?)
        .map(Some)
        .map_err(decode("window copy context"))
}

/// An isolated copy of `context` holding the update `encoded` as well;
/// `None` when the update does not import whole on it (a dependency it does
/// not hold).
fn with_update(context: Option<&LoroDoc>, encoded: &[u8]) -> Result<Option<LoroDoc>> {
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
        let Some(scratch) = isolated(context)? else {
            continue;
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
            return Ok(Some(scratch));
        }
    }
    Ok(None)
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
