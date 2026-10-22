//! A world key pad row as its reference alone, for the bytes that persist
//! (KS-5, the 02A projector agreed with L04 and L02): a pad row becomes its
//! bare reference, the key's full id and a namespace hint, its metadata
//! header kept; every other row stays byte for byte. A pure codec: no
//! transaction, no I/O, and the same input gives the same bytes.
//!
//! A window document's blob is projected through the vendored root-map
//! checkpoint (`loro::checkpoint`): a full or shallow snapshot splits into
//! its skeleton and its values, the pad rows' values are projected, and the
//! join rebuilds a snapshot of the same kind with the same op ids, deps,
//! lamports, timestamps, versions, frontiers, every historical insert and
//! the shallow root, proven against the skeleton before it returns. An
//! update is projected on an isolated copy holding its dependencies and is
//! exported again over exactly its own op spans; a passed context document
//! is read, never committed, forked or exported. What cannot be projected
//! that way, an update missing its dependencies, a document of another
//! shape, a malformed pad or a root the join cannot keep, is a typed
//! `CorruptedIndex`, never a lossy projection and never `NothingToProject`
//! ([`PAD_CAPTURE_FAULT`]). Nothing here wires the projection into what
//! persists (02A2).

use super::{decode_pad_body, encode_reference, pad_row_body, pad_row_id};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::world_keys::WorldKeyId;

#[cfg(feature = "sync")]
#[allow(unused_imports, reason = "02A2 wires the projection (L02, L03)")]
pub(crate) use self::window::{WindowPadProjection, project_window_pad_refs};

/// What a caller does with a projection fault (CALLS: PAD_CAPTURE_FAULT,
/// ruled by the Engine 10-22).
#[allow(dead_code, reason = "02A2's callers match on it (L02, L03)")]
pub(crate) enum PadCaptureFault {
    /// The codec returns a typed `CorruptedIndex`; the caller warns, value
    /// free, and keeps today's carrier, tier or kit path and its bytes. No
    /// row is dropped and no working operation is refused for it; strict
    /// closure stays open.
    WarnKeepExistingPathAndLeaveStrictClosureOpen,
}

#[allow(dead_code, reason = "02A2's callers match on it (L02, L03)")]
pub(crate) const PAD_CAPTURE_FAULT: PadCaptureFault =
    PadCaptureFault::WarnKeepExistingPathAndLeaveStrictClosureOpen;

/// What projected equality says (CALLS: PAD_CANONICAL_EQUIVALENCE, ruled by
/// the Engine 10-22).
enum CanonicalEquivalence {
    /// The same header, full id and normalized hint for a pad row, the same
    /// bytes for any other: a carrier, a row at rest and a bare reference of
    /// one key compare equal. It never says a pad is held, admitted or
    /// installed: readiness is checked apart.
    ProjectedIdentityWithSeparateReadiness,
}

const PAD_CANONICAL_EQUIVALENCE: CanonicalEquivalence =
    CanonicalEquivalence::ProjectedIdentityWithSeparateReadiness;

/// One pad the projected bytes reference: the key's exact full id, and the
/// source's namespace hint, a hint and never authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct WorldPadRef {
    pub(crate) key: WorldKeyId,
    pub(crate) namespace_hint: [u8; 16],
}

/// A row as it persists: a pad row's bare reference with its metadata header
/// kept, any other row as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PadReferenceProjection {
    pub(crate) row: Vec<u8>,
    /// The pad it references; `None` for any other row and a header-only
    /// shell.
    pub(crate) reference: Option<WorldPadRef>,
}

/// The row `raw` of `id` as it persists: a pad row in any form (its carrier,
/// its row at rest, a bare reference) becomes its bare reference into
/// `namespace_hint`, its metadata header kept; every other row and a
/// header-only shell stay byte for byte, with no reference.
///
/// # Errors
///
/// A pad body that does not decode, or a pad row whose id is not the one
/// its key derives: `CorruptedIndex`.
#[allow(dead_code, reason = "02A2 wires the projection (L02, L03)")]
pub(crate) fn pad_reference_projection(
    id: &EntityId,
    raw: &[u8],
    namespace_hint: &[u8; 16],
) -> Result<PadReferenceProjection> {
    let Some(body) = pad_row_body(raw).filter(|body| !body.is_empty()) else {
        return Ok(PadReferenceProjection {
            row: raw.to_vec(),
            reference: None,
        });
    };
    let key = *decode_pad_body(body)?.key();
    if pad_row_id(&key)? != *id {
        return Err(Error::CorruptedIndex("world key pad row id"));
    }
    let mut row = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    row.extend_from_slice(&encode_reference(&key, namespace_hint));
    Ok(PadReferenceProjection {
        row,
        reference: Some(WorldPadRef {
            key,
            namespace_hint: *namespace_hint,
        }),
    })
}

/// Whether `left` and `right`, two copies of the row `id`, are equal as they
/// persist ([`PAD_CANONICAL_EQUIVALENCE`]). It says nothing of custody.
///
/// # Errors
///
/// As [`pad_reference_projection`].
#[allow(dead_code, reason = "02A2 wires the projection (L02, L03)")]
pub(crate) fn projected_pad_row_equal(
    id: &EntityId,
    left: &[u8],
    right: &[u8],
    namespace_hint: &[u8; 16],
) -> Result<bool> {
    match PAD_CANONICAL_EQUIVALENCE {
        CanonicalEquivalence::ProjectedIdentityWithSeparateReadiness => {
            Ok(pad_reference_projection(id, left, namespace_hint)?.row
                == pad_reference_projection(id, right, namespace_hint)?.row)
        }
    }
}

#[cfg(feature = "sync")]
mod window {
    use std::collections::{BTreeMap, BTreeSet};

    use loro::checkpoint::{AtomId, Capture, Classify, Field, OwnerId, Parts, Payload};
    use loro::{EncodedBlobMode, ExportMode, ID, IdSpan, ImportBlobMetadata, LoroDoc, LoroValue};

    use super::{PAD_CAPTURE_FAULT, PadCaptureFault, WorldPadRef, pad_reference_projection};
    use crate::entity_id::EntityId;
    use crate::error::{Error, Result};
    use crate::sync::WindowKey;

    /// The root maps a window document may hold (CALLS:
    /// PAD_PROJECTOR_WINDOW_ROOTS): any other root, or a container inside
    /// one, is a shape the projector does not take.
    const PAD_PROJECTOR_WINDOW_ROOTS: &[&str] = &[
        "asset_body_refs",
        "authorship",
        "custody",
        "document_heads",
        "document_pins",
        "documents",
        "edges",
        "entities",
        "message_docs",
        "note_proposals",
        "peer_origins",
        "pins",
        "retained_claim_worlds",
        "room_facts",
        "room_turns",
        "row_born_with",
        "row_births",
        "tombstones",
        "withdrawn_cutoffs",
    ];
    /// The root map whose values are rows.
    const ROWS: &str = "entities";

    /// What one window blob persists as.
    #[allow(dead_code, reason = "02A2 wires the projection (L02, L03)")]
    pub(crate) enum WindowPadProjection {
        /// No pad value anywhere in the blob's history or root: the caller
        /// keeps the input bytes exactly as today.
        NothingToProject,
        /// Reference-only bytes of the same blob kind, with the same op ids,
        /// deps, versions and frontiers, every historical insert and the
        /// shallow root, and the sorted, deduplicated pads they reference.
        Projected {
            bytes: Vec<u8>,
            required_refs: Vec<WorldPadRef>,
        },
    }

    /// A projection fault ([`PAD_CAPTURE_FAULT`]): typed, the caller keeps
    /// today's path.
    fn fault(why: &'static str) -> Error {
        match PAD_CAPTURE_FAULT {
            PadCaptureFault::WarnKeepExistingPathAndLeaveStrictClosureOpen => {
                Error::CorruptedIndex(why)
            }
        }
    }

    /// Every key a plain one, every value one holder's: the skeleton is
    /// joined at once and never kept, so no key or value leaves this codec.
    struct OneHolder;

    impl Classify for OneHolder {
        fn plain_key(&mut self, _root: &str, _key: &str) -> bool {
            true
        }

        fn holders(&mut self, _field: Field<'_>) -> Option<Vec<OwnerId>> {
            Some(vec![1])
        }
    }

    /// `doc` split into its skeleton and values.
    fn parts_of(doc: &LoroDoc) -> Result<Parts> {
        match doc.export_root_map_checkpoint(PAD_PROJECTOR_WINDOW_ROOTS, &mut OneHolder) {
            Capture::Classified(parts) => Ok(parts),
            Capture::Unclassified(_) => {
                Err(fault("a window document the pad projector does not take"))
            }
        }
    }

    /// Each value atom's root map, key and op id (`None` for a shallow-root
    /// winner whose op is not retained).
    fn sites(parts: &Parts) -> BTreeMap<AtomId, (u32, String, Option<ID>)> {
        let mut sites = BTreeMap::new();
        for change in &parts.skeleton.changes {
            for (at, op) in (0..).zip(&change.ops) {
                if let Some(atom) = op.value {
                    let id = ID::new(change.peer, change.counter + at);
                    sites.insert(atom, (op.root, op.key.clone(), Some(id)));
                }
            }
        }
        for winner in parts.skeleton.shallow.iter().flat_map(|root| &root.winners) {
            if let Some(atom) = winner.value {
                sites
                    .entry(atom)
                    .or_insert_with(|| (winner.root, winner.key.clone(), None));
            }
        }
        sites
    }

    /// Projects each row value of `parts` that `take` admits by its op id,
    /// in place; returns the pads they reference, sorted and deduplicated.
    fn project_atoms(
        window: &WindowKey,
        parts: &mut Parts,
        namespace_hint: &[u8; 16],
        take: impl Fn(Option<ID>) -> bool,
    ) -> Result<Vec<WorldPadRef>> {
        let rows = parts.skeleton.roots.iter().position(|root| root == ROWS);
        let sites = sites(parts);
        let mut refs = BTreeSet::new();
        for atom in &mut parts.atoms {
            let Some((root, key, id)) = sites.get(&atom.id) else {
                continue;
            };
            if rows != Some(*root as usize) || !take(*id) {
                continue;
            }
            let Payload::Value(LoroValue::Binary(raw)) = &atom.payload else {
                continue;
            };
            if super::pad_row_body(raw).is_none_or(<[u8]>::is_empty) {
                continue;
            }
            let id = EntityId::from_hex(key)
                .map_err(|_| fault("a pad row under a key that is no id"))?;
            let projected = pad_reference_projection(&id, raw, namespace_hint)?;
            if let Some(reference) = projected.reference {
                if window
                    .world()
                    .is_some_and(|world| world != reference.key.world)
                {
                    return Err(fault("a pad row outside its world's window"));
                }
                refs.insert(reference);
                atom.payload = Payload::Value(LoroValue::Binary(projected.row.into()));
            }
        }
        Ok(refs.into_iter().collect())
    }

    /// `parts` joined again into snapshot bytes.
    fn joined(parts: &Parts) -> Result<Vec<u8>> {
        LoroDoc::join_root_map_checkpoint(&parts.skeleton, &parts.atoms, &[])
            .map(|joined| joined.bytes)
            .map_err(|_| fault("a projected window document the join does not prove"))
    }

    fn meta(encoded: &[u8]) -> Result<ImportBlobMetadata> {
        LoroDoc::decode_import_blob_meta(encoded, true)
            .map_err(|_| fault("a window blob that does not decode"))
    }

    /// Whether `out` is a blob of `kind` over the same versions and
    /// frontiers as `input`.
    fn same_span(
        input: &ImportBlobMetadata,
        out: &ImportBlobMetadata,
        kind: &EncodedBlobMode,
    ) -> bool {
        out.mode == *kind
            && out.partial_start_vv == input.partial_start_vv
            && out.partial_end_vv == input.partial_end_vv
            && out.start_frontiers == input.start_frontiers
    }

    /// The op spans an update blob holds.
    fn spans(meta: &ImportBlobMetadata) -> Vec<IdSpan> {
        let mut spans: Vec<_> = meta
            .partial_end_vv
            .iter()
            .filter_map(|(peer, end)| {
                let start = meta.partial_start_vv.get(peer).copied().unwrap_or(0);
                (*end > start).then(|| IdSpan::new(*peer, start, *end))
            })
            .collect();
        spans.sort_by_key(|span| span.peer);
        spans
    }

    /// A copy of `context` that shares nothing with it: split and joined
    /// again unchanged, so no commit barrier of `context` runs.
    fn isolated(context: &LoroDoc) -> Result<LoroDoc> {
        let parts = parts_of(context)?;
        LoroDoc::from_snapshot(&joined(&parts)?)
            .map_err(|_| fault("a window context the pad projector cannot copy"))
    }

    /// Projects a full or shallow snapshot.
    fn project_snapshot(
        window: &WindowKey,
        encoded: &[u8],
        meta: &ImportBlobMetadata,
        namespace_hint: &[u8; 16],
    ) -> Result<WindowPadProjection> {
        let doc = LoroDoc::from_snapshot(encoded)
            .map_err(|_| fault("a window snapshot that does not open"))?;
        let mut parts = parts_of(&doc)?;
        let required_refs = project_atoms(window, &mut parts, namespace_hint, |_| true)?;
        if required_refs.is_empty() {
            return Ok(WindowPadProjection::NothingToProject);
        }
        let bytes = joined(&parts)?;
        if !same_span(meta, &self::meta(&bytes)?, &meta.mode) {
            return Err(fault("a projected window snapshot of another span or kind"));
        }
        Ok(WindowPadProjection::Projected {
            bytes,
            required_refs,
        })
    }

    /// Projects an update on an isolated copy holding its dependencies: a
    /// copy of `context` when it is passed, else an empty document, which
    /// takes the update whole or not at all.
    fn project_update(
        window: &WindowKey,
        encoded: &[u8],
        meta: &ImportBlobMetadata,
        context: Option<&LoroDoc>,
        namespace_hint: &[u8; 16],
    ) -> Result<WindowPadProjection> {
        let scratch = match context {
            Some(context) => isolated(context)?,
            None => LoroDoc::new(),
        };
        let status = scratch
            .import(encoded)
            .map_err(|_| fault("a window update that does not import"))?;
        let held = scratch.oplog_vv();
        let complete = meta
            .partial_end_vv
            .iter()
            .all(|(peer, end)| held.get(peer).is_some_and(|held| held >= end));
        if status.pending.is_some() || !complete {
            return Err(fault("a window update missing its dependency history"));
        }
        let spans = spans(meta);
        let in_update =
            |id: Option<ID>| id.is_some_and(|id| spans.iter().any(|span| span.contains(id)));
        // The update's own slice, before projection, must export again as
        // exactly the ops it holds.
        let slice = scratch
            .export(ExportMode::updates_in_range(spans.clone()))
            .map_err(|_| fault("a window update whose slice does not export"))?;
        if !same_span(meta, &self::meta(&slice)?, &EncodedBlobMode::Updates) {
            return Err(fault("a window update whose slice is another"));
        }
        let mut parts = parts_of(&scratch)?;
        let required_refs = project_atoms(window, &mut parts, namespace_hint, in_update)?;
        if required_refs.is_empty() {
            return Ok(WindowPadProjection::NothingToProject);
        }
        let projected = LoroDoc::from_snapshot(&joined(&parts)?)
            .map_err(|_| fault("a projected window document that does not open"))?;
        let bytes = projected
            .export(ExportMode::updates_in_range(spans))
            .map_err(|_| fault("a projected window update that does not export"))?;
        let out = self::meta(&bytes)?;
        if !same_span(meta, &out, &EncodedBlobMode::Updates)
            || out.change_num != self::meta(&slice)?.change_num
        {
            return Err(fault("a projected window update of another span"));
        }
        Ok(WindowPadProjection::Projected {
            bytes,
            required_refs,
        })
    }

    /// `encoded`, a window's snapshot, shallow snapshot or update blob, as it
    /// persists: each pad row in its history and its root projected to its
    /// bare reference into `namespace_hint` ([`super::pad_reference_projection`]),
    /// everything else the same. `context` is a document holding an update's
    /// dependencies when the update does not hold them itself; it is copied,
    /// never committed, forked or exported. The window names the world whose
    /// pads it may hold.
    ///
    /// # Errors
    ///
    /// A blob that does not decode, an update missing its dependency history
    /// or whose slice cannot be proven, a document of another shape, a
    /// malformed pad, or a projection the join or the span check does not
    /// prove: `CorruptedIndex` ([`PAD_CAPTURE_FAULT`]).
    #[allow(dead_code, reason = "02A2 wires the projection (L02, L03)")]
    pub(crate) fn project_window_pad_refs(
        window: &WindowKey,
        encoded: &[u8],
        context: Option<&LoroDoc>,
        namespace_hint: &[u8; 16],
    ) -> Result<WindowPadProjection> {
        let meta = meta(encoded)?;
        match meta.mode {
            EncodedBlobMode::Snapshot | EncodedBlobMode::ShallowSnapshot => {
                project_snapshot(window, encoded, &meta, namespace_hint)
            }
            EncodedBlobMode::Updates => {
                project_update(window, encoded, &meta, context, namespace_hint)
            }
            EncodedBlobMode::OutdatedSnapshot | EncodedBlobMode::OutdatedRle => {
                Err(fault("a window blob of an outdated kind"))
            }
        }
    }
}
