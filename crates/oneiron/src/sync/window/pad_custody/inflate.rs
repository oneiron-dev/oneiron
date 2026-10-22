//! A window blob's pad references as today's carriers again (KS-5, FIX 7107,
//! KEEP TODAY): what a send that may not seal for its recipient ships, where
//! the blob as held here carries the references a sealed import left. The
//! vendored root-map checkpoint splits the blob; each pad row value that is a
//! reference whose pad is here becomes its carrier, the one a live route
//! ships (`world_keys::image_pad_row`); the join rebuilds a blob of the same
//! kind over the same op ids, deps, versions and frontiers. An update is
//! inflated on an isolated copy holding its dependencies and exported again
//! over exactly its own op spans, as the projector does. A blob with no
//! reference, or one the checkpoint does not take, goes as it was.

use std::collections::BTreeMap;

use loro::checkpoint::{AtomId, Capture, Classify, Field, OwnerId, Parts, Payload};
use loro::{EncodedBlobMode, ExportMode, ID, IdSpan, ImportBlobMetadata, LoroDoc, LoroValue};

use crate::store::Store;

/// The root map whose values are rows.
const ROWS: &str = "entities";

/// Every key a plain one, every value one holder's: the skeleton is joined
/// at once and never kept.
struct OneHolder;

impl Classify for OneHolder {
    fn plain_key(&mut self, _root: &str, _key: &str) -> bool {
        true
    }

    fn holders(&mut self, _field: Field<'_>) -> Option<Vec<OwnerId>> {
        Some(vec![1])
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

/// Each value atom's root map and op id (`None` for a shallow-root winner
/// whose op is not retained).
fn sites(parts: &Parts) -> BTreeMap<AtomId, (u32, Option<ID>)> {
    let mut sites = BTreeMap::new();
    for change in &parts.skeleton.changes {
        for (at, op) in (0..).zip(&change.ops) {
            if let Some(atom) = op.value {
                sites.insert(
                    atom,
                    (op.root, Some(ID::new(change.peer, change.counter + at))),
                );
            }
        }
    }
    for winner in parts.skeleton.shallow.iter().flat_map(|root| &root.winners) {
        if let Some(atom) = winner.value {
            sites.entry(atom).or_insert((winner.root, None));
        }
    }
    sites
}

/// Each row value of `parts` that `take` admits by its op id, a pad
/// reference whose pad is here, as its carrier, in place; whether any was.
fn inflate_atoms(store: &Store, parts: &mut Parts, take: impl Fn(Option<ID>) -> bool) -> bool {
    let rows = parts.skeleton.roots.iter().position(|root| root == ROWS);
    let sites = sites(parts);
    let mut inflated = false;
    for atom in &mut parts.atoms {
        let Some((root, id)) = sites.get(&atom.id) else {
            continue;
        };
        if rows != Some(*root as usize) || !take(*id) {
            continue;
        }
        let Payload::Value(LoroValue::Binary(raw)) = &atom.payload else {
            continue;
        };
        if let Some(carrier) = crate::world_keys::image_pad_row(store, raw) {
            atom.payload = Payload::Value(LoroValue::Binary(carrier.into()));
            inflated = true;
        }
    }
    inflated
}

fn joined(parts: &Parts) -> Option<Vec<u8>> {
    LoroDoc::join_root_map_checkpoint(&parts.skeleton, &parts.atoms, &[])
        .ok()
        .map(|joined| joined.bytes)
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

/// `encoded`, a window's snapshot, shallow snapshot or update blob, with
/// each pad reference whose pad is here as its carrier; `context` holds an
/// update's dependencies, copied and never changed. `None` when nothing in
/// it is such a reference, or it is of a shape the checkpoint or its proof
/// does not take: the caller sends it as it is.
pub(super) fn inflate_window_pad_refs(
    store: &Store,
    encoded: &[u8],
    context: Option<&LoroDoc>,
) -> Option<Vec<u8>> {
    let input = meta(encoded)?;
    match input.mode {
        EncodedBlobMode::Snapshot | EncodedBlobMode::ShallowSnapshot => {
            let doc = LoroDoc::from_snapshot(encoded).ok()?;
            let mut parts = parts_of(&doc)?;
            if !inflate_atoms(store, &mut parts, |_| true) {
                return None;
            }
            let bytes = joined(&parts)?;
            same_span(&input, &meta(&bytes)?, &input.mode).then_some(bytes)
        }
        EncodedBlobMode::Updates => {
            let scratch = match context {
                Some(context) => LoroDoc::from_snapshot(&joined(&parts_of(context)?)?).ok()?,
                None => LoroDoc::new(),
            };
            let status = scratch.import(encoded).ok()?;
            let held = scratch.oplog_vv();
            let complete = input
                .partial_end_vv
                .iter()
                .all(|(peer, end)| held.get(peer).is_some_and(|held| held >= end));
            if status.pending.is_some() || !complete {
                return None;
            }
            let mut spans: Vec<IdSpan> = input
                .partial_end_vv
                .iter()
                .filter_map(|(peer, end)| {
                    let start = input.partial_start_vv.get(peer).copied().unwrap_or(0);
                    (*end > start).then(|| IdSpan::new(*peer, start, *end))
                })
                .collect();
            spans.sort_by_key(|span| span.peer);
            let slice = scratch
                .export(ExportMode::updates_in_range(spans.clone()))
                .ok()?;
            let mut parts = parts_of(&scratch)?;
            let in_update =
                |id: Option<ID>| id.is_some_and(|id| spans.iter().any(|span| span.contains(id)));
            if !inflate_atoms(store, &mut parts, in_update) {
                return None;
            }
            let inflated = LoroDoc::from_snapshot(&joined(&parts)?).ok()?;
            let bytes = inflated.export(ExportMode::updates_in_range(spans)).ok()?;
            let out = meta(&bytes)?;
            (same_span(&input, &out, &EncodedBlobMode::Updates)
                && out.change_num == meta(&slice)?.change_num)
                .then_some(bytes)
        }
        EncodedBlobMode::OutdatedSnapshot | EncodedBlobMode::OutdatedRle => None,
    }
}
