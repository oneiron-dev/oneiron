//! Native part writes added explicitly to the original window history.
//!
//! Each original head keeps its operation identity. Its rebuilt pieces use
//! a separate peer, shared by every capture of that same original head.
//! These operations extend the history; they are not an unchanged-VV join.

use std::collections::{BTreeMap, BTreeSet};

use loro::checkpoint::{
    Atom, AtomId, Payload, SkelChange, SkelOp, Skeleton, Slot, SlotKind, Winner,
};
use loro::{IdSpan, Lamport, LoroDoc, LoroValue, PeerID};

use super::{RecordDocumentSlot, RecordDocumentSlots};
use crate::error::Result;
use crate::store::checkpoint_payload::rows::bad_part;
use crate::sync::checkpoint_payload::LoroSlice;
use crate::sync::checkpoint_payload::operations::{export_slice, holds_slice};
use crate::sync::skill_docs::SKILL_DOCS_MAP;
use crate::sync::skill_docs::checkpoint::RecordDocumentTransport;

/// Identity of the original source, independent of capture-local atom ids.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SourceSite {
    Operation {
        entity: String,
        peer: PeerID,
        counter: i32,
    },
    Shallow {
        entity: String,
        peer: PeerID,
        lamport: Lamport,
    },
}

/// One allocator for BOTH the snapshot and combined-pending captures of a
/// window. Peer ids are chosen from the original histories, never a digest.
pub(crate) struct SourcePeers {
    occupied: BTreeSet<PeerID>,
    sources: BTreeMap<SourceSite, PeerID>,
}

impl SourcePeers {
    pub(crate) fn new<'s>(skeletons: impl IntoIterator<Item = &'s Skeleton>) -> Self {
        let mut occupied = BTreeSet::new();
        for skeleton in skeletons {
            occupied.extend(skeleton.vv.iter().map(|&(peer, _)| peer));
            occupied.extend(skeleton.frontiers.iter().map(|&(peer, _)| peer));
            if let Some(root) = &skeleton.shallow {
                occupied.extend(root.vv.iter().map(|&(peer, _)| peer));
                occupied.extend(root.winners.iter().map(|winner| winner.peer));
            }
        }
        Self {
            occupied,
            sources: BTreeMap::new(),
        }
    }

    fn peer(&mut self, source: SourceSite) -> Result<PeerID> {
        if let Some(&peer) = self.sources.get(&source) {
            return Ok(peer);
        }
        let mut peer: PeerID = 0;
        while self.occupied.contains(&peer) {
            peer = peer.checked_add(1).ok_or_else(bad_part)?;
        }
        self.occupied.insert(peer);
        self.sources.insert(source, peer);
        Ok(peer)
    }
}

/// Actual added operations of one opened head. The row slices below name
/// these spans separately from their original spans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AddedSource {
    pub(crate) source: SourceSite,
    pub(crate) span: IdSpan,
}

pub(crate) struct ReconstructedWindow {
    pub(crate) snapshot: Vec<u8>,
    pub(crate) rows: Vec<Vec<u8>>,
    pub(crate) slices: Vec<LoroSlice>,
    pub(crate) added: Vec<AddedSource>,
    /// Every native source and actor opened; this says nothing about
    /// equality of the original and extended version vectors.
    pub(crate) native_lossless: bool,
    /// Original native part operations are rewritten even when all content
    /// opened. Restore must not report this as the original history.
    pub(crate) rewritten_native_history: bool,
}

/// A view of one real source and its opened native transport. The ordinary
/// restore constructs this only after opening that source's own copies;
/// capture proof instead supplies its original complete actor fill.
pub(crate) struct ReconstructionSource<'a> {
    pub(crate) entity_key: &'a str,
    pub(crate) slots: &'a RecordDocumentSlots,
    pub(crate) opened: Option<(&'a RecordDocumentTransport, bool)>,
}

struct HeadSite {
    identity: SourceSite,
    dependency: (PeerID, i32),
    lamport: Lamport,
    timestamp: i64,
}

fn head_site(skeleton: &Skeleton, source: &ReconstructionSource<'_>) -> Result<HeadSite> {
    let atom = source.slots.head.value;
    let mut found = None;
    for change in &skeleton.changes {
        for (offset, op) in change.ops.iter().enumerate() {
            if op.value != Some(atom) {
                continue;
            }
            let offset = i32::try_from(offset).map_err(|_| bad_part())?;
            let counter = change.counter.checked_add(offset).ok_or_else(bad_part)?;
            let lamport = change
                .lamport
                .checked_add(offset as u32)
                .ok_or_else(bad_part)?;
            if found.is_some() {
                return Err(bad_part());
            }
            found = Some(HeadSite {
                identity: SourceSite::Operation {
                    entity: source.entity_key.to_owned(),
                    peer: change.peer,
                    counter,
                },
                dependency: (change.peer, counter),
                lamport,
                timestamp: change.timestamp,
            });
        }
    }
    if let Some(site) = found {
        return Ok(site);
    }
    let root = skeleton.shallow.as_ref().ok_or_else(bad_part)?;
    let mut winners = root
        .winners
        .iter()
        .filter(|winner| winner.value == Some(atom));
    let winner = winners.next().ok_or_else(bad_part)?;
    if winners.next().is_some() {
        return Err(bad_part());
    }
    let &[dependency] = root.frontiers.as_slice() else {
        return Err(bad_part());
    };
    let frontier = skeleton
        .changes
        .iter()
        .find(|change| change.peer == dependency.0 && change.counter == dependency.1)
        .ok_or_else(bad_part)?;
    Ok(HeadSite {
        identity: SourceSite::Shallow {
            entity: source.entity_key.to_owned(),
            peer: winner.peer,
            lamport: winner.lamport,
        },
        dependency,
        lamport: frontier.lamport,
        timestamp: frontier.timestamp,
    })
}

pub(super) fn source_site(
    skeleton: &Skeleton,
    entity_key: &str,
    slots: &RecordDocumentSlots,
) -> Result<SourceSite> {
    head_site(
        skeleton,
        &ReconstructionSource {
            entity_key,
            slots,
            opened: None,
        },
    )
    .map(|site| site.identity)
}

fn native_slots(sources: &[ReconstructionSource<'_>]) -> BTreeSet<AtomId> {
    let mut slots = BTreeSet::new();
    for source in sources {
        let uses = source
            .slots
            .snapshot
            .iter()
            .chain(source.slots.refinement.iter().flatten())
            .flatten();
        for slot in std::iter::once(&source.slots.head)
            .chain(&source.slots.rows)
            .chain(uses)
        {
            slots.insert(slot.value);
            slots.extend(slot.key);
        }
    }
    slots
}

fn value(
    values: &mut BTreeMap<AtomId, Vec<u8>>,
    slot: &RecordDocumentSlot,
    bytes: &[u8],
) -> Result<()> {
    if slot.key.is_some() {
        return Err(bad_part());
    }
    match values.get(&slot.value) {
        Some(known) if known.as_slice() != bytes => Err(bad_part()),
        Some(_) => Ok(()),
        None => {
            values.insert(slot.value, bytes.to_vec());
            Ok(())
        }
    }
}

fn carries(slice: &LoroSlice, source: &SourceSite) -> bool {
    match (slice, source) {
        (LoroSlice::Snapshot, _) => true,
        (LoroSlice::Updates(spans), SourceSite::Operation { peer, counter, .. }) => {
            spans.iter().any(|span| {
                span.peer == *peer && span.counter.start <= *counter && *counter < span.counter.end
            })
        }
        (LoroSlice::Updates(_), SourceSite::Shallow { .. }) => false,
    }
}

/// Rebuilds REAL map operations and exports each original row's exact spans
/// plus ONLY its own heads' additions. All old native part slots become
/// deletes; no original actor-bearing part bytes survive in a base sidecar.
/// `available` and `erased` cover only the original non-native slots.
pub(crate) fn reconstruct(
    skeleton: &Skeleton,
    sources: &[ReconstructionSource<'_>],
    mut available: Vec<Atom>,
    mut erased: Vec<AtomId>,
    slices: &[LoroSlice],
    peers: &mut SourcePeers,
) -> Result<ReconstructedWindow> {
    let native = native_slots(sources);
    if available.iter().any(|atom| native.contains(&atom.id))
        || erased.iter().any(|atom| native.contains(atom))
    {
        return Err(bad_part());
    }
    let mut extended = skeleton.clone();
    let mut values = BTreeMap::new();
    let mut additions = Vec::new();
    let mut identities = BTreeSet::new();
    let mut frontiers: BTreeSet<_> = skeleton.frontiers.iter().copied().collect();
    let root = skeleton
        .roots
        .iter()
        .position(|root| root == SKILL_DOCS_MAP)
        .and_then(|index| u32::try_from(index).ok());
    let mut piece_values: BTreeMap<&str, &[u8]> = BTreeMap::new();
    for source in sources {
        let root = root.ok_or_else(bad_part)?;
        let site = head_site(skeleton, source)?;
        if !identities.insert(site.identity.clone()) {
            return Err(bad_part());
        }
        let Some((transport, _)) = source.opened else {
            continue;
        };
        if transport.entity()?.to_hex() != source.entity_key {
            return Err(bad_part());
        }
        value(&mut values, &source.slots.head, &transport.head)?;
        for row in &source.slots.rows {
            value(&mut values, row, &transport.row)?;
        }
        let peer = peers.peer(site.identity.clone())?;
        if skeleton.vv.iter().any(|&(original, _)| original == peer) {
            return Err(bad_part());
        }
        let lamport = site.lamport.checked_add(1).ok_or_else(bad_part)?;
        let mut ops = Vec::new();
        let holders = usize::try_from(source.slots.head.value)
            .ok()
            .and_then(|index| skeleton.slots.get(index))
            .ok_or_else(bad_part)?
            .holders
            .clone();
        for (key, bytes) in transport.snapshot.iter().chain(&transport.refinement) {
            crate::sync::carrier_parts::admit_part(key, &LoroValue::Binary(bytes.clone().into()))?;
            if piece_values
                .insert(key.as_str(), bytes.as_slice())
                .is_some_and(|known| known != bytes.as_slice())
            {
                return Err(bad_part());
            }
            let id = AtomId::try_from(extended.slots.len()).map_err(|_| bad_part())?;
            extended.slots.push(Slot {
                kind: SlotKind::Value,
                holders: holders.clone(),
            });
            available.push(Atom {
                id,
                holders: holders.clone(),
                payload: Payload::Value(LoroValue::Binary(bytes.clone().into())),
            });
            ops.push(SkelOp {
                root,
                key: key.clone(),
                value: Some(id),
            });
        }
        let count = i32::try_from(ops.len()).map_err(|_| bad_part())?;
        if count == 0 {
            return Err(bad_part());
        }
        lamport
            .checked_add(u32::try_from(count - 1).map_err(|_| bad_part())?)
            .ok_or_else(bad_part)?;
        extended.changes.push(SkelChange {
            peer,
            counter: 0,
            lamport,
            timestamp: site.timestamp,
            deps: vec![site.dependency],
            message: None,
            ops,
        });
        extended.vv.push((peer, count));
        frontiers.remove(&site.dependency);
        frontiers.insert((peer, count - 1));
        additions.push(AddedSource {
            source: site.identity,
            span: IdSpan::new(peer, 0, count),
        });
    }
    for id in native {
        if let Some(bytes) = values.remove(&id) {
            let shape = usize::try_from(id)
                .ok()
                .and_then(|index| skeleton.slots.get(index))
                .ok_or_else(bad_part)?;
            available.push(Atom {
                id,
                holders: shape.holders.clone(),
                payload: Payload::Value(LoroValue::Binary(bytes.into())),
            });
        } else {
            erased.push(id);
        }
    }
    if !values.is_empty() {
        return Err(bad_part());
    }
    extended.vv.sort_unstable();
    extended.frontiers = frontiers.into_iter().collect();
    extended
        .changes
        .sort_by_key(|change| (change.lamport, change.peer, change.counter));
    let mut latest: BTreeMap<_, _> = skeleton
        .latest
        .iter()
        .cloned()
        .map(|winner| ((winner.root, winner.key.clone()), winner))
        .collect();
    for change in extended
        .changes
        .iter()
        .filter(|change| !skeleton.vv.iter().any(|&(peer, _)| peer == change.peer))
    {
        for (offset, op) in change.ops.iter().enumerate() {
            let winner = Winner {
                root: op.root,
                key: op.key.clone(),
                peer: change.peer,
                lamport: change.lamport + offset as u32,
                value: op.value,
            };
            let key = (winner.root, winner.key.clone());
            match latest.get_mut(&key) {
                Some(old) if (old.lamport, old.peer) < (winner.lamport, winner.peer) => {
                    *old = winner
                }
                None => {
                    latest.insert(key, winner);
                }
                _ => {}
            }
        }
    }
    extended.latest = latest.into_values().collect();
    if let Some(root) = root {
        if !extended.latest_maps.contains(&root) && !additions.is_empty() {
            extended.latest_maps.push(root);
            extended.latest_maps.sort_unstable();
        }
    }
    let joined = LoroDoc::join_root_map_checkpoint(&extended, &available, &erased)
        .map_err(|_| bad_part())?;
    if !joined.report.equivalent {
        return Err(bad_part());
    }
    let doc = LoroDoc::from_snapshot(&joined.bytes).map_err(|_| bad_part())?;
    let mut output_slices = Vec::with_capacity(slices.len());
    let mut rows = Vec::with_capacity(slices.len());
    for original in slices {
        let slice = match original {
            LoroSlice::Snapshot => LoroSlice::Snapshot,
            LoroSlice::Updates(original_spans) => {
                let mut spans = original_spans.clone();
                spans.extend(
                    additions
                        .iter()
                        .filter(|addition| carries(original, &addition.source))
                        .map(|addition| addition.span.clone()),
                );
                spans.sort_by_key(|span| (span.peer, span.counter.start));
                LoroSlice::Updates(spans)
            }
        };
        let bytes = export_slice(&doc, &slice)?;
        if !holds_slice(&bytes, &slice) {
            return Err(bad_part());
        }
        output_slices.push(slice);
        rows.push(bytes);
    }
    Ok(ReconstructedWindow {
        snapshot: joined.bytes,
        rows,
        slices: output_slices,
        added: additions,
        native_lossless: sources
            .iter()
            .all(|source| source.opened.is_some_and(|(_, lossless)| lossless)),
        rewritten_native_history: !sources.is_empty(),
    })
}

/// One original capture group of a window: its snapshot, or its pending and
/// queued updates over that original snapshot. Native source views must come
/// from the same per-window open, not independently re-encoded transports.
pub(crate) struct ReconstructionGroup<'a> {
    pub(crate) skeleton: &'a Skeleton,
    pub(crate) sources: Vec<ReconstructionSource<'a>>,
    pub(crate) available: Vec<Atom>,
    pub(crate) erased: Vec<AtomId>,
    pub(crate) slices: &'a [LoroSlice],
}

fn same_transport(left: &RecordDocumentTransport, right: &RecordDocumentTransport) -> bool {
    left.source == right.source
        && left.row == right.row
        && left.head == right.head
        && left.snapshot == right.snapshot
        && left.refinement == right.refinement
}

/// Reconstructs BOTH groups before returning ANY row. Source identity, new
/// operation ids, native bytes and row membership agree across the overlap.
/// Replaying the actual snapshot and exact extended update slices must give
/// the complete extended history, including historical heads, not only its
/// latest values. No whole-window extension is appended to unrelated rows.
pub(crate) fn reconstruct_window(
    groups: Vec<ReconstructionGroup<'_>>,
) -> Result<Vec<ReconstructedWindow>> {
    if groups.is_empty() {
        return Err(bad_part());
    }
    let mut peers = SourcePeers::new(groups.iter().map(|group| group.skeleton));
    let mut seen: BTreeMap<SourceSite, Option<(&RecordDocumentTransport, bool)>> = BTreeMap::new();
    for group in &groups {
        if group.slices.is_empty() {
            return Err(bad_part());
        }
        for source in &group.sources {
            let identity = head_site(group.skeleton, source)?.identity;
            match seen.entry(identity) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(source.opened);
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    match (entry.get(), source.opened) {
                        (Some((left, left_lossless)), Some((right, right_lossless)))
                            if *left_lossless == right_lossless && same_transport(left, right) => {}
                        (None, None) => {}
                        _ => return Err(bad_part()),
                    }
                }
            }
        }
    }
    let mut rebuilt = Vec::with_capacity(groups.len());
    for group in groups {
        rebuilt.push(reconstruct(
            group.skeleton,
            &group.sources,
            group.available,
            group.erased,
            group.slices,
            &mut peers,
        )?);
    }
    let mut snapshots = rebuilt
        .iter()
        .flat_map(|group| group.rows.iter().zip(&group.slices))
        .filter(|(_, slice)| matches!(slice, LoroSlice::Snapshot));
    let doc = match snapshots.next() {
        Some((bytes, _)) => LoroDoc::from_snapshot(bytes).map_err(|_| bad_part())?,
        None => LoroDoc::new(),
    };
    if snapshots.next().is_some() {
        return Err(bad_part());
    }
    for group in &rebuilt {
        for (bytes, slice) in group.rows.iter().zip(&group.slices) {
            if matches!(slice, LoroSlice::Updates(_)) {
                doc.import(bytes).map_err(|_| bad_part())?;
            }
        }
    }
    let complete = LoroDoc::from_snapshot(&rebuilt.last().ok_or_else(bad_part)?.snapshot)
        .map_err(|_| bad_part())?;
    if doc.oplog_vv() != complete.oplog_vv()
        || doc.oplog_frontiers() != complete.oplog_frontiers()
        || doc.shallow_since_vv().to_vv() != complete.shallow_since_vv().to_vv()
        || doc.shallow_since_frontiers() != complete.shallow_since_frontiers()
        || doc.is_shallow() != complete.is_shallow()
        || doc.get_deep_value() != complete.get_deep_value()
    {
        return Err(bad_part());
    }
    let history = |doc: &LoroDoc| {
        serde_json::to_value(doc.export_json_updates(&Default::default(), &doc.oplog_vv()))
            .map_err(|_| bad_part())
    };
    if history(&doc)? != history(&complete)? {
        return Err(bad_part());
    }
    Ok(rebuilt)
}
