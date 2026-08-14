use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use heed::{RoTxn, RwTxn};

use crate::config::VaultConfig;
use crate::distance::cosine_distance;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
use crate::pipeline::ScoredEntity;
use crate::store::VECTOR_VERSION_KEY;
use crate::store::{ManifestDbs, Store};

const ENTRY_POINT_KEY: &[u8] = b"entry_point";
pub(crate) const COUNT_KEY: &[u8] = b"count";
/// `hnsw_meta` marker: present (value `[1]`) when the persisted graph
/// maintains the symmetric-link invariant — every stored link `a → b` has
/// its reverse `b → a`, except the documented orphan-protection case where
/// a node's last remaining link is kept one-way instead of emptying its
/// neighbor list. Under the invariant a node's backlinks are exactly its
/// forward neighbor list, so deletes and refreshes never scan the full
/// `hnsw_neighbors` DB (ONE-325). Vaults without the marker keep the legacy
/// asymmetric behavior (full-scan delete, full-rebuild refresh) until the
/// one-time migration runs via `maintain().rebuild_hnsw()`.
pub(crate) const SYMMETRIC_LINKS_KEY: &[u8] = b"symmetric_links";
const SYMMETRIC_LINKS_ENABLED: u8 = 1;
/// `hnsw_meta` counter (u64 LE): number of times the localized refresh path
/// had to fall back to a full symmetric snapshot rebuild. The fallback is an
/// explicit, measured, rare path (ONE-324 AC10) — this counter is how it is
/// measured.
pub(crate) const REFRESH_FALLBACK_REBUILDS_KEY: &[u8] = b"refresh_fallback_rebuilds";
/// `hnsw_meta` counter (u64 LE): number of legacy full-snapshot rebuilds
/// this vault has run (pre-migration refresh contract). Observability for
/// the batched-rebuild coalescing guarantee (ONE-324 AC11): one transaction
/// bumps this at most once no matter how many vector refreshes it carries.
pub(crate) const LEGACY_REBUILDS_KEY: &[u8] = b"legacy_snapshot_rebuilds";
const ERR_ENTRY_POINT_MISSING: &str = "hnsw count > 0 but entry point is missing";
const ERR_ENTRY_POINT_VECTOR_MISSING: &str = "hnsw count > 0 but entry point vector is missing";
const ERR_ENTRY_POINT_BYTES: &str = "hnsw entry point bytes are malformed";
const ERR_COUNT_BYTES: &str = "hnsw count bytes are malformed";
const ERR_NEIGHBOR_KEY_BYTES: &str = "hnsw neighbor key bytes are malformed";
const ERR_NEIGHBOR_VALUE_BYTES: &str = "hnsw neighbor list bytes are malformed";
const ERR_VECTOR_BYTES: &str = "hnsw vector bytes are malformed";
const ERR_VECTOR_ROW_TOO_SHORT: &str = "hnsw vector row shorter than scoring dimensions";
const ERR_VECTOR_ROW_MISSING_AT_RESCORE: &str =
    "hnsw vector row disappeared between beam traversal and rescore in one snapshot";
const ERR_VECTOR_KEY_BYTES: &str = "hnsw vector key bytes are malformed";
const ERR_VECTOR_VERSION_BYTES: &str = "hnsw vector version bytes are malformed";
const ERR_COUNT_UNDERFLOW: &str = "hnsw node count underflowed during delete";
const ERR_COUNT_OVERFLOW: &str = "hnsw node count overflowed";
const ERR_REMAINING_NODES_MISSING: &str = "hnsw count > 0 but no nodes remain";
const ERR_EXISTING_NODE_ZERO_COUNT: &str = "hnsw node exists but count is zero";
const ERR_ZERO_COUNT_GRAPH_NOT_EMPTY: &str =
    "hnsw metadata says count is zero but graph rows still exist";
const ERR_SYMMETRIC_MARKER_BYTES: &str = "hnsw symmetric-links marker bytes are malformed";
const ERR_FALLBACK_COUNTER_BYTES: &str = "hnsw refresh fallback counter bytes are malformed";
const ERR_LEGACY_REBUILDS_BYTES: &str = "hnsw legacy rebuild counter bytes are malformed";
const ERR_ONE_WAY_EXCEPTION_BYTES: &str = "hnsw one-way exception record bytes are malformed";

/// `hnsw_meta` key prefix for one-way-link exception records (ONE-325). When
/// orphan protection keeps a node's last remaining link `holder -> target`
/// one-way (so `holder`'s neighbor list never empties), `holder` is recorded
/// under `ONE_WAY_EXCEPTION_PREFIX ++ target` (a 20-byte key: 4-byte prefix +
/// 16-byte id). Without it the symmetric delete path — which derives backlinks
/// from the deleted node's OWN forward list — would miss `holder` when
/// deleting `target` and leave the deleted id lingering in `holder`'s row
/// forever, breaking the active-index purge contract. Recording the exception
/// lets delete scrub those holders too; the extra work is bounded by the
/// holder count, never the full neighbors DB, so deletes stay
/// neighborhood-local. The prefix is distinct from every other (short, ASCII)
/// `hnsw_meta` key, so rebuilds can clear exactly these rows without touching
/// unrelated metadata.
const ONE_WAY_EXCEPTION_PREFIX: &[u8] = b"ow1:";

/// Link discipline of the persisted graph, derived from
/// [`SYMMETRIC_LINKS_KEY`]. Decoding is fail-closed: a present-but-malformed
/// marker is a typed corruption error, never a silent legacy downgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkDiscipline {
    /// Symmetric-link invariant holds: backlinks ≡ forward neighbors.
    Symmetric,
    /// Pre-migration graph: links may be one-way; deletes scan the full
    /// neighbors DB and refreshes rebuild from snapshot.
    Legacy,
}

fn read_link_discipline(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<LinkDiscipline> {
    match store.hnsw_meta().get(txn, SYMMETRIC_LINKS_KEY)? {
        None => Ok(LinkDiscipline::Legacy),
        Some(raw) if *raw == [SYMMETRIC_LINKS_ENABLED] => Ok(LinkDiscipline::Symmetric),
        Some(_) => Err(Error::CorruptedIndex(ERR_SYMMETRIC_MARKER_BYTES)),
    }
}

/// Stamps the vault as maintaining the symmetric-link invariant. Called when
/// a graph is created from empty (fresh vaults) and when a full rebuild
/// rewrites every row symmetrically (the one-time migration path).
pub(crate) fn mark_symmetric_links(store: &impl ManifestDbs, wtxn: &mut RwTxn<'_>) -> Result<()> {
    store
        .hnsw_meta()
        .put(wtxn, SYMMETRIC_LINKS_KEY, &[SYMMETRIC_LINKS_ENABLED])?;
    Ok(())
}

pub(crate) fn read_refresh_fallback_rebuilds(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, REFRESH_FALLBACK_REBUILDS_KEY)? else {
        return Ok(0);
    };
    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_FALLBACK_COUNTER_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

fn increment_refresh_fallback_rebuilds(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    let next = read_refresh_fallback_rebuilds(store, &*wtxn)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hnsw refresh fallback counter"))?;
    store
        .hnsw_meta()
        .put(wtxn, REFRESH_FALLBACK_REBUILDS_KEY, &next.to_le_bytes())?;
    Ok(())
}

pub(crate) fn read_legacy_snapshot_rebuilds(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, LEGACY_REBUILDS_KEY)? else {
        return Ok(0);
    };
    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_LEGACY_REBUILDS_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

fn increment_legacy_snapshot_rebuilds(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    let next = read_legacy_snapshot_rebuilds(store, &*wtxn)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hnsw legacy rebuild counter"))?;
    store
        .hnsw_meta()
        .put(wtxn, LEGACY_REBUILDS_KEY, &next.to_le_bytes())?;
    Ok(())
}

/// `hnsw_meta` key for the one-way-link exception record of `target`: the set
/// of holders whose single surviving link points at `target` one-way.
fn one_way_exception_key(target: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(ONE_WAY_EXCEPTION_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(ONE_WAY_EXCEPTION_PREFIX);
    key.extend_from_slice(target.as_bytes());
    key
}

fn decode_exception_holders(raw: &[u8]) -> Result<Vec<EntityId>> {
    let (chunks, rem) = raw.as_chunks::<ENTITY_ID_LEN>();
    if !rem.is_empty() {
        return Err(Error::CorruptedIndex(ERR_ONE_WAY_EXCEPTION_BYTES));
    }
    let mut holders = Vec::with_capacity(chunks.len());
    for bytes in chunks {
        match EntityId::from_bytes(*bytes) {
            Ok(holder) => holders.push(holder),
            Err(_) => return Err(Error::CorruptedIndex(ERR_ONE_WAY_EXCEPTION_BYTES)),
        }
    }
    Ok(holders)
}

/// Holders whose single one-way link points at `target` (`holder -> target`
/// without the reverse). Empty when no exception record exists.
fn read_one_way_exception_holders(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    target: &EntityId,
) -> Result<Vec<EntityId>> {
    match store.hnsw_meta().get(txn, &one_way_exception_key(target))? {
        Some(raw) => decode_exception_holders(&raw),
        None => Ok(Vec::new()),
    }
}

/// Records that `holder` keeps a one-way link to `target` (orphan protection).
/// Idempotent: a holder already present is not duplicated.
fn record_one_way_exception(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
    holder: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let mut holders = read_one_way_exception_holders(store, &*wtxn, target)?;
    if holders.contains(holder) {
        return Ok(());
    }
    holders.push(*holder);
    let mut bytes = Vec::with_capacity(holders.len() * ENTITY_ID_LEN);
    for holder in &holders {
        bytes.extend_from_slice(holder.as_bytes());
    }
    store
        .hnsw_meta()
        .put(wtxn, &one_way_exception_key(target), &bytes)?;
    *ops += 1;
    Ok(())
}

/// Scrubs a node being deleted out of every holder that kept a one-way link to
/// it (orphan protection), then drops the exception record. This is the half
/// of a symmetric delete that the deleted node's own forward list cannot reach
/// (the holders are, by definition, NOT in it). Bounded by the holder count.
fn purge_one_way_exceptions_for_target(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let holders = read_one_way_exception_holders(store, &*wtxn, id)?;
    if holders.is_empty() {
        return Ok(());
    }
    // `scrub_neighbor_bytes` no-ops on a holder whose link was already removed
    // (e.g. it later became bidirectional and was pruned), so a stale holder is
    // harmless.
    scrub_backlinks_in_place(store, wtxn, id, &holders, ops)?;
    store.hnsw_meta().delete(wtxn, &one_way_exception_key(id))?;
    *ops += 1;
    Ok(())
}

/// Drops every persisted one-way exception record. Used before a full rebuild,
/// which replaces the whole graph shape and so invalidates the old records;
/// the symmetric paths re-derive them from the rebuilt rows. Only the
/// `ONE_WAY_EXCEPTION_PREFIX` keyspace is touched — unrelated `hnsw_meta` rows
/// (graph/model/schema markers) are preserved.
fn clear_one_way_exceptions(store: &impl ManifestDbs, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let mut stale_keys: Vec<Vec<u8>> = Vec::new();
    for entry in store.hnsw_meta().iter(wtxn)? {
        let (key, _) = entry?;
        if key.starts_with(ONE_WAY_EXCEPTION_PREFIX) {
            stale_keys.push(key.to_vec());
        }
    }
    for key in stale_keys {
        store.hnsw_meta().delete(wtxn, &key)?;
    }
    Ok(())
}

/// Re-derives the one-way exception records from a freshly rebuilt symmetric
/// graph: every link `node -> neighbor` whose neighbor row does not point back
/// is a tracked orphan-protection exception keyed by `neighbor`.
fn rebuild_one_way_exception_index(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    neighbors: &[(EntityId, Vec<EntityId>)],
) -> Result<()> {
    let forward: HashMap<EntityId, &Vec<EntityId>> =
        neighbors.iter().map(|(id, list)| (*id, list)).collect();
    let mut holders_by_target: HashMap<EntityId, Vec<EntityId>> = HashMap::new();
    for (node, list) in neighbors {
        for neighbor in list {
            // A one-way exception requires the neighbor row to exist but lack
            // the reverse link; a missing row is dangling corruption, which the
            // graph never emits and the symmetry assertion would catch.
            let is_one_way = forward
                .get(neighbor)
                .is_some_and(|back| !back.contains(node));
            if is_one_way {
                holders_by_target.entry(*neighbor).or_default().push(*node);
            }
        }
    }
    for (target, holders) in holders_by_target {
        let mut bytes = Vec::with_capacity(holders.len() * ENTITY_ID_LEN);
        for holder in &holders {
            bytes.extend_from_slice(holder.as_bytes());
        }
        store
            .hnsw_meta()
            .put(wtxn, &one_way_exception_key(&target), &bytes)?;
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct RebuiltHnswGraph {
    pub entry_point: Option<EntityId>,
    pub count: u64,
    pub neighbors: Vec<(EntityId, Vec<EntityId>)>,
}

#[derive(Clone, Copy, Debug)]
struct HeapEntry {
    id: EntityId,
    distance: f32,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.distance.total_cmp(&other.distance).is_eq()
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.distance
            .total_cmp(&other.distance)
            .then_with(|| self.id.as_bytes().cmp(other.id.as_bytes()))
    }
}

/// Outcome of [`hnsw_insert_inner`]: either the graph mutation was applied
/// in place, or the op is a refresh on a legacy (pre-migration) graph whose
/// contract is a full snapshot rebuild — which the caller schedules so that
/// batched vector updates coalesce into at most one rebuild per transaction.
enum InsertOutcome {
    Applied,
    NeedsLegacyRebuild,
}

/// Direct (non-batched) insert/refresh entry point. Production writes go
/// through [`hnsw_insert_batched`]; this wrapper keeps the historical
/// one-shot semantics (a legacy-graph refresh rebuilds inline) for direct
/// callers and tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn hnsw_insert(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
) -> Result<()> {
    hnsw_insert_probed(store, config, wtxn, id, vector, &mut 0)
}

/// [`hnsw_insert`] with unit-operation accounting: `ops` increments once per
/// row read/write/delete and once per beam-search node/vector access, so
/// tests can pin the localized-update complexity class (ONE-324 AC5).
pub(crate) fn hnsw_insert_probed(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    ops: &mut u64,
) -> Result<()> {
    match hnsw_insert_inner(store, config, wtxn, id, vector, ops)? {
        InsertOutcome::Applied => Ok(()),
        InsertOutcome::NeedsLegacyRebuild => {
            rebuild_hnsw_from_current_snapshot(store, config, wtxn)
        }
    }
}

/// Batched variant: a legacy-graph refresh sets `pending_rebuild` instead of
/// rebuilding inline, and once a rebuild is pending all further graph
/// mutations in the same transaction are skipped — the single
/// end-of-transaction snapshot rebuild re-derives the whole graph from the
/// `vectors` DB, so per-op mutations would be dead writes (ONE-324 AC11).
pub(crate) fn hnsw_insert_batched(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    pending_rebuild: &mut bool,
) -> Result<()> {
    if *pending_rebuild {
        return Ok(());
    }
    match hnsw_insert_inner(store, config, wtxn, id, vector, &mut 0)? {
        InsertOutcome::Applied => Ok(()),
        InsertOutcome::NeedsLegacyRebuild => {
            *pending_rebuild = true;
            Ok(())
        }
    }
}

/// Runs a pending legacy snapshot rebuild scheduled by
/// [`hnsw_insert_batched`]. Call after the batch op loop.
pub(crate) fn run_pending_legacy_rebuild(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    pending_rebuild: bool,
) -> Result<()> {
    if pending_rebuild {
        rebuild_hnsw_from_current_snapshot(store, config, wtxn)?;
    }
    Ok(())
}

fn hnsw_insert_inner(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    ops: &mut u64,
) -> Result<InsertOutcome> {
    let discipline = read_link_discipline(store, &*wtxn)?;
    *ops += 1;
    if store.hnsw_neighbors().get(&*wtxn, id.as_bytes())?.is_some() {
        *ops += 1;
        let count = read_count(store, &*wtxn)?;
        if count == 0 {
            return Err(Error::CorruptedIndex(ERR_EXISTING_NODE_ZERO_COUNT));
        }
        let entry_point = read_entry_point(store, &*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
        return match discipline {
            LinkDiscipline::Legacy => Ok(InsertOutcome::NeedsLegacyRebuild),
            LinkDiscipline::Symmetric => {
                hnsw_refresh_localized(store, config, wtxn, id, vector, count, entry_point, ops)?;
                Ok(InsertOutcome::Applied)
            }
        };
    }

    let mut count = read_count(store, &*wtxn)?;
    *ops += 1;
    if count == 0 {
        if read_entry_point(store, &*wtxn)?.is_some()
            || store.hnsw_neighbors().first(&*wtxn)?.is_some()
        {
            return Err(Error::CorruptedIndex(ERR_ZERO_COUNT_GRAPH_NOT_EMPTY));
        }
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, id.as_bytes())?;
        store
            .hnsw_meta()
            .put(wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
        store.hnsw_neighbors().put(wtxn, id.as_bytes(), &[])?;
        // A graph created from empty is symmetric by construction and every
        // subsequent write in this module preserves the invariant.
        mark_symmetric_links(store, wtxn)?;
        return Ok(InsertOutcome::Applied);
    }

    let entry_point =
        read_entry_point(store, &*wtxn)?.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
    let mut nearest = beam_search(
        store,
        &*wtxn,
        vector,
        entry_point,
        BeamOptions {
            ef: config.hnsw.ef_construction,
            lenient_neighbors: false,
            check_existence: false,
            score_dims: score_dims_for(config),
        },
        config.dimensions,
        ops,
    )?;

    nearest.retain(|entry| entry.id != *id);
    nearest.truncate(config.hnsw.m_max_0);

    let selected: Vec<EntityId> = nearest.into_iter().map(|entry| entry.id).collect();
    write_neighbors(store, wtxn, id, &selected)?;
    *ops += 1;

    match discipline {
        LinkDiscipline::Symmetric => {
            attach_backlinks_symmetric(store, config, wtxn, id, &selected, ops)?;
        }
        LinkDiscipline::Legacy => {
            attach_backlinks_legacy(store, config, wtxn, id, &selected, ops)?;
        }
    }

    count = count
        .checked_add(1)
        .ok_or(Error::IndexOverflow(ERR_COUNT_OVERFLOW))?;
    store
        .hnsw_meta()
        .put(wtxn, COUNT_KEY, &count.to_le_bytes())?;

    Ok(InsertOutcome::Applied)
}

/// Legacy (pre-migration) backlink attachment: prune may drop links without
/// removing the reverse direction, leaving one-way edges. Preserved verbatim
/// for vaults that have not run the symmetry migration.
fn attach_backlinks_legacy(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    selected: &[EntityId],
    ops: &mut u64,
) -> Result<()> {
    for neighbor_id in selected {
        let mut neighbors = load_neighbors(store, &*wtxn, neighbor_id)?;
        *ops += 1;
        if !neighbors.contains(id) {
            neighbors.push(*id);
        }

        if neighbors.len() > config.hnsw.m_max_0 {
            neighbors = prune_neighbors_for_node(
                store,
                &*wtxn,
                neighbor_id,
                &neighbors,
                config.hnsw.m_max_0,
                score_dims_for(config),
                config.dimensions,
                ops,
            )?;
        }

        write_neighbors(store, wtxn, neighbor_id, &neighbors)?;
        *ops += 1;
    }
    Ok(())
}

/// Symmetric backlink attachment (ONE-325): every link written here exists
/// in both directions. When adding `id` to a neighbor's list overflows
/// `m_max_0`, the pruned-out victims also lose their reverse link — except a
/// victim whose list would become empty keeps its link one-way (orphan
/// protection), so no prune ever disconnects a node's outgoing side.
fn attach_backlinks_symmetric(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    selected: &[EntityId],
    ops: &mut u64,
) -> Result<()> {
    for neighbor_id in selected {
        let mut neighbors = load_neighbors(store, &*wtxn, neighbor_id)?;
        *ops += 1;
        if !neighbors.contains(id) {
            neighbors.push(*id);
        }

        if neighbors.len() > config.hnsw.m_max_0 {
            let pruned = prune_neighbors_for_node(
                store,
                &*wtxn,
                neighbor_id,
                &neighbors,
                config.hnsw.m_max_0,
                score_dims_for(config),
                config.dimensions,
                ops,
            )?;
            let removed: Vec<EntityId> = neighbors
                .iter()
                .filter(|candidate| !pruned.contains(candidate))
                .copied()
                .collect();
            write_neighbors(store, wtxn, neighbor_id, &pruned)?;
            *ops += 1;
            for victim in &removed {
                detach_reverse_link(store, wtxn, neighbor_id, victim, ops)?;
            }
        } else {
            write_neighbors(store, wtxn, neighbor_id, &neighbors)?;
            *ops += 1;
        }
    }
    Ok(())
}

/// Removes `from` out of `victim`'s neighbor list to mirror a prune of the
/// `from → victim` direction. Orphan protection: when `victim`'s list is
/// exactly `[from]`, the link is kept one-way instead of emptying the list.
fn detach_reverse_link(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    from: &EntityId,
    victim: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let Some(raw) = store.hnsw_neighbors().get(&*wtxn, victim.as_bytes())? else {
        return Ok(());
    };
    let list = decode_neighbors(&raw, false)?;
    if !list.contains(from) {
        return Ok(());
    }
    if list.len() == 1 {
        // Orphan protection: never empty a node's outgoing links via a
        // cascade removal. The one-way remainder (`victim -> from`) is the
        // documented exception to the symmetric invariant — track it so a
        // later delete of `from` can purge this otherwise-unreachable backlink
        // instead of leaving the deleted id stranded in `victim`'s row.
        record_one_way_exception(store, wtxn, from, victim, ops)?;
        return Ok(());
    }
    let filtered: Vec<EntityId> = list.into_iter().filter(|entry| entry != from).collect();
    write_neighbors(store, wtxn, victim, &filtered)?;
    *ops += 1;
    Ok(())
}

/// Localized refresh of an existing node on a symmetric graph (ONE-324):
/// detach via the node's own neighbor list (≡ backlinks under the
/// invariant), re-insert at the new position with one beam search, then
/// repair any old neighbor the detach orphaned. No full iteration over
/// `vectors` or `hnsw_neighbors` happens on this path.
#[allow(clippy::too_many_arguments)]
fn hnsw_refresh_localized(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    count: u64,
    mut entry_point: EntityId,
    ops: &mut u64,
) -> Result<()> {
    // 1. Detach: under the symmetric invariant the node's forward neighbors
    //    are exactly the nodes holding links back to it.
    let old_neighbors = load_neighbors(store, &*wtxn, id)?;
    *ops += 1;
    let mut orphaned: Vec<EntityId> = Vec::new();
    for neighbor_id in &old_neighbors {
        *ops += 1;
        let Some(raw) = store.hnsw_neighbors().get(&*wtxn, neighbor_id.as_bytes())? else {
            continue;
        };
        let list = decode_neighbors(&raw, false)?;
        if !list.contains(id) {
            // One-way protected link (id → neighbor without the reverse):
            // nothing to detach on the neighbor's side.
            continue;
        }
        let filtered: Vec<EntityId> = list.into_iter().filter(|entry| entry != id).collect();
        if filtered.is_empty() {
            orphaned.push(*neighbor_id);
        }
        write_neighbors(store, wtxn, neighbor_id, &filtered)?;
        *ops += 1;
    }
    store.hnsw_neighbors().delete(wtxn, id.as_bytes())?;
    *ops += 1;

    if count == 1 {
        // Sole node: trivially re-anchor at the new position.
        write_neighbors(store, wtxn, id, &[])?;
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, id.as_bytes())?;
        return Ok(());
    }

    if entry_point == *id {
        let (replacement_key, _) = store
            .hnsw_neighbors()
            .first(&*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_REMAINING_NODES_MISSING))?;
        entry_point =
            parse_entity_id(&replacement_key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
                other => other,
            })?;
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, entry_point.as_bytes())?;
        *ops += 2;
    }

    // 2. Re-insert at the new position.
    let mut nearest = beam_search(
        store,
        &*wtxn,
        vector,
        entry_point,
        BeamOptions {
            ef: config.hnsw.ef_construction,
            lenient_neighbors: false,
            check_existence: false,
            score_dims: score_dims_for(config),
        },
        config.dimensions,
        ops,
    )?;
    nearest.retain(|entry| entry.id != *id);
    nearest.truncate(config.hnsw.m_max_0);
    if nearest.is_empty() {
        // Local repair cannot restore reachability — explicit measured rare
        // path (ONE-324 AC10). With count > 1 the beam always reaches at
        // least the (≠ id) entry point, so this is defensive.
        return hnsw_symmetric_fallback_rebuild(store, config, wtxn);
    }
    let selected: Vec<EntityId> = nearest.into_iter().map(|entry| entry.id).collect();
    write_neighbors(store, wtxn, id, &selected)?;
    *ops += 1;
    attach_backlinks_symmetric(store, config, wtxn, id, &selected, ops)?;

    // 3. Repair: re-link old neighbors that the detach phase orphaned and
    //    that the re-insert did not already reconnect.
    for orphan in orphaned {
        *ops += 1;
        let Some(raw) = store.hnsw_neighbors().get(&*wtxn, orphan.as_bytes())? else {
            continue;
        };
        if !decode_neighbors(&raw, false)?.is_empty() {
            continue;
        }
        let Some(orphan_vector) = load_vector(store, &*wtxn, &orphan, config.dimensions)? else {
            // No stored vector to anchor a repair by; leave the empty row
            // for the next full rebuild to reconcile.
            continue;
        };
        let mut repair_nearest = beam_search(
            store,
            &*wtxn,
            &orphan_vector,
            entry_point,
            BeamOptions {
                ef: config.hnsw.ef_construction,
                lenient_neighbors: false,
                check_existence: false,
                score_dims: score_dims_for(config),
            },
            config.dimensions,
            ops,
        )?;
        repair_nearest.retain(|entry| entry.id != orphan);
        let Some(anchor) = repair_nearest.first().map(|entry| entry.id) else {
            // Local repair cannot restore entry reachability for this
            // orphan — explicit measured rare path (ONE-324 AC10).
            return hnsw_symmetric_fallback_rebuild(store, config, wtxn);
        };
        write_neighbors(store, wtxn, &orphan, &[anchor])?;
        *ops += 1;
        attach_backlinks_symmetric(store, config, wtxn, &orphan, &[anchor], ops)?;
    }

    Ok(())
}

/// Full symmetric snapshot rebuild used when localized refresh repair cannot
/// restore reachability. Increments the persistent fallback counter so the
/// rare path stays measured; the symmetric marker is already set and the
/// rebuilt graph upholds it.
fn hnsw_symmetric_fallback_rebuild(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    increment_refresh_fallback_rebuilds(store, wtxn)?;
    let vector_ids = collect_vector_ids(store, &*wtxn)?;
    let rebuilt = build_hnsw_graph_from_snapshot(
        store,
        config,
        &*wtxn,
        &vector_ids,
        LinkDiscipline::Symmetric,
    )?;
    write_rebuilt_hnsw(store, wtxn, &rebuilt, LinkDiscipline::Symmetric)
}

pub(crate) fn build_hnsw_graph_from_snapshot(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    rtxn: &RoTxn<'_>,
    vector_ids: &[EntityId],
    discipline: LinkDiscipline,
) -> Result<RebuiltHnswGraph> {
    let mut neighbors_by_id = HashMap::<EntityId, Vec<EntityId>>::with_capacity(vector_ids.len());
    let mut entry_point = None;
    let mut count = 0_u64;

    for id in vector_ids {
        if count == 0 {
            entry_point = Some(*id);
            neighbors_by_id.insert(*id, Vec::new());
            count = 1;
            continue;
        }

        let graph_entry_point = entry_point.ok_or(Error::InvariantViolation(
            "rebuild entry point missing while validated vector set is non-empty",
        ))?;
        let mut nearest = beam_search_snapshot(
            store,
            rtxn,
            &neighbors_by_id,
            id,
            graph_entry_point,
            config.hnsw.ef_construction,
            score_dims_for(config),
            config.dimensions,
        )?;

        nearest.retain(|entry| entry.id != *id);
        nearest.truncate(config.hnsw.m_max_0);

        let selected: Vec<EntityId> = nearest.into_iter().map(|entry| entry.id).collect();
        neighbors_by_id.insert(*id, selected.clone());

        for neighbor_id in &selected {
            let mut neighbor_neighbors = neighbors_by_id.remove(neighbor_id).unwrap_or_default();
            if !neighbor_neighbors.contains(id) {
                neighbor_neighbors.push(*id);
            }

            if neighbor_neighbors.len() > config.hnsw.m_max_0 {
                let pruned = prune_neighbors_for_node(
                    store,
                    rtxn,
                    neighbor_id,
                    &neighbor_neighbors,
                    config.hnsw.m_max_0,
                    score_dims_for(config),
                    config.dimensions,
                    &mut 0,
                )?;
                if discipline == LinkDiscipline::Symmetric {
                    for victim in neighbor_neighbors
                        .iter()
                        .filter(|candidate| !pruned.contains(candidate))
                    {
                        detach_reverse_link_in_memory(&mut neighbors_by_id, neighbor_id, victim);
                    }
                }
                neighbor_neighbors = pruned;
            }

            neighbors_by_id.insert(*neighbor_id, neighbor_neighbors);
        }

        count = count
            .checked_add(1)
            .ok_or(Error::IndexOverflow(ERR_COUNT_OVERFLOW))?;
    }

    entry_point = select_best_entry_point(&neighbors_by_id, entry_point);

    let neighbors = vector_ids
        .iter()
        .map(|id| (*id, neighbors_by_id.remove(id).unwrap_or_default()))
        .collect();

    Ok(RebuiltHnswGraph {
        entry_point,
        count,
        neighbors,
    })
}

pub(crate) fn write_rebuilt_hnsw(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    rebuilt: &RebuiltHnswGraph,
    discipline: LinkDiscipline,
) -> Result<()> {
    store.hnsw_neighbors().clear(wtxn)?;
    // Rebuild owns only the live graph shape. Preserve unrelated metadata such as
    // graph/version markers, persisted model ids, and schema/config keys.
    store.hnsw_meta().delete(wtxn, COUNT_KEY)?;
    store.hnsw_meta().delete(wtxn, ENTRY_POINT_KEY)?;
    // The old one-way exception records describe the replaced graph; drop them
    // (only the `ow1:` keyspace, never unrelated metadata) and re-derive them
    // from the rebuilt rows for symmetric graphs below.
    clear_one_way_exceptions(store, wtxn)?;

    if let Some(entry_point) = rebuilt.entry_point {
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, entry_point.as_bytes())?;
    }
    store
        .hnsw_meta()
        .put(wtxn, COUNT_KEY, &rebuilt.count.to_le_bytes())?;

    for (id, neighbors) in &rebuilt.neighbors {
        write_neighbors(store, wtxn, id, neighbors)?;
    }

    if discipline == LinkDiscipline::Symmetric {
        rebuild_one_way_exception_index(store, wtxn, &rebuilt.neighbors)?;
    }

    Ok(())
}

pub(crate) fn read_vector_version(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, VECTOR_VERSION_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_VECTOR_VERSION_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn has_population(hnsw_meta: &OverlayDb, txn: &RoTxn<'_>) -> Result<bool> {
    if let Some(raw) = hnsw_meta.get(txn, COUNT_KEY)? {
        let bytes: [u8; 8] = raw
            .as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_COUNT_BYTES))?;
        if u64::from_le_bytes(bytes) > 0 {
            return Ok(true);
        }
    }

    Ok(hnsw_meta.get(txn, ENTRY_POINT_KEY)?.is_some())
}

pub(crate) fn increment_vector_version(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<u64> {
    let current = read_vector_version(store, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("vector version"))?;
    store
        .hnsw_meta()
        .put(wtxn, VECTOR_VERSION_KEY, &next.to_le_bytes())?;
    Ok(next)
}
/// Vector search over the NSW graph.
///
/// EMB-2 MRL funnel: with `fast_dims` configured, traversal scores on the
/// vector prefix and `query_vector` may be either full-length or
/// `fast_dims`-length. Full-length queries get an exact full-dim rescore of
/// the whole beam result set (the funnel's rescore breadth — no extra
/// constant) unless `skip_rescore` opts into the prefix-only hot lane. A
/// `fast_dims`-length query can never be rescored — no full query exists —
/// so the flag is implicit there. With `fast_dims: None` the behavior is
/// identical to the pre-funnel path and `skip_rescore` is inert.
///
/// Recall contract: the rescore restores exact full-dim ORDERING of the
/// retrieved beam only — it is not global exactness. Candidate selection
/// happens in prefix space, so a vector that is distant in the prefix but
/// near in full dimensions may never enter the `ef_search.max(limit)`-wide
/// beam and can never be rescored back in. Recall is beam-bounded and
/// rises with `ef_search`; a beam covering the whole reachable corpus
/// recovers brute-force parity.
pub(crate) fn hnsw_search(
    store: &impl ManifestDbs,
    config: &VaultConfig,
    rtxn: &RoTxn<'_>,
    query_vector: &[f32],
    limit: usize,
    skip_rescore: bool,
) -> Result<Vec<ScoredEntity>> {
    // Defense-in-depth: callers (pipeline vector channel, vault search)
    // validate too.
    if query_vector.len() != config.dimensions
        && config.fast_dims.map(usize::from) != Some(query_vector.len())
    {
        return Err(Error::DimensionMismatch {
            expected: config.dimensions,
            got: query_vector.len(),
        });
    }
    if limit == 0 {
        return Ok(Vec::new());
    }

    let count = read_count(store, rtxn)?;
    let entry_point = read_entry_point(store, rtxn)?;
    if count == 0 {
        if entry_point.is_some() || store.hnsw_neighbors().first(rtxn)?.is_some() {
            return Err(Error::CorruptedIndex(ERR_ZERO_COUNT_GRAPH_NOT_EMPTY));
        }
        return Ok(Vec::new());
    }

    let entry_point = entry_point.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;

    let mut nearest = beam_search(
        store,
        rtxn,
        query_vector,
        entry_point,
        BeamOptions {
            ef: config.hnsw.ef_search.max(limit),
            lenient_neighbors: true,
            check_existence: true,
            score_dims: score_dims_for(config),
        },
        config.dimensions,
        &mut 0,
    )?;

    let rescore_active =
        config.fast_dims.is_some() && query_vector.len() == config.dimensions && !skip_rescore;
    if rescore_active {
        let mut vector_buffer = Vec::with_capacity(query_vector.len());
        for entry in &mut nearest {
            let Some(row) = load_vector_into(
                store,
                rtxn,
                &entry.id,
                config.dimensions,
                &mut vector_buffer,
            )?
            else {
                // Unreachable under LMDB snapshot isolation: every beam
                // result loaded its row within THIS rtxn to be scored at
                // all. If it fires anyway the index is inconsistent — fail
                // closed rather than leave this entry's PREFIX distance to
                // be ranked against the others' full-dim distances (two
                // incompatible scales in one ordering).
                return Err(Error::CorruptedIndex(ERR_VECTOR_ROW_MISSING_AT_RESCORE));
            };
            // Same fail-closed rule as `score_prefix`: a row shorter than
            // the full query is a truncated/corrupted row and must not
            // rescore on a partial comparison.
            if row.len() < query_vector.len() {
                return Err(Error::CorruptedIndex(ERR_VECTOR_ROW_TOO_SHORT));
            }
            entry.distance = cosine_distance(query_vector, row);
        }
        // HeapEntry orders by (distance asc, id bytes asc) — the pinned
        // rescore tiebreak.
        nearest.sort_unstable();
    }

    nearest.truncate(limit);
    Ok(nearest
        .into_iter()
        .map(|entry| ScoredEntity {
            id: entry.id,
            score: (1.0 - entry.distance).clamp(-1.0, 1.0),
        })
        .collect())
}

/// Removes a node from the HNSW graph, scrubbing its ID from surviving
/// neighbor lists and repairing the entry point when needed.
///
/// Search still keeps defensive existence checks because vectors/entities can
/// become partially inconsistent for reasons outside HNSW bookkeeping.
pub(crate) fn hnsw_deindex(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    hnsw_deindex_probed(store, wtxn, id, &mut 0)
}

/// [`hnsw_deindex`] with unit-operation accounting (`ops` increments once
/// per row read/write/delete and once per scanned row on the legacy path),
/// so tests can pin that symmetric-graph deletes never iterate the full
/// `hnsw_neighbors` DB (ONE-325 AC1).
pub(crate) fn hnsw_deindex_probed(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let own_neighbors = match store.hnsw_neighbors().get(&*wtxn, id.as_bytes())? {
        Some(raw) => decode_neighbors(&raw, false)?,
        None => return Ok(()),
    };
    let discipline = read_link_discipline(store, &*wtxn)?;
    let backlink_targets = match discipline {
        // Symmetric invariant: the nodes holding links back to `id` are
        // exactly `id`'s own forward neighbors — no full scan.
        LinkDiscipline::Symmetric => own_neighbors,
        // Pre-migration graphs may hold one-way links into `id` from
        // anywhere; only a full scan finds them all.
        LinkDiscipline::Legacy => collect_backlink_targets(store, &*wtxn, id, ops)?,
    };
    *ops += 1;

    let count = read_count(store, &*wtxn)?;
    *ops += 1;
    let new_count = count
        .checked_sub(1)
        .ok_or(Error::CorruptedIndex(ERR_COUNT_UNDERFLOW))?;
    store.hnsw_neighbors().delete(wtxn, id.as_bytes())?;
    *ops += 1;
    scrub_backlinks_in_place(store, wtxn, id, &backlink_targets, ops)?;
    if discipline == LinkDiscipline::Symmetric {
        // Orphan-protected holders kept a one-way link INTO `id` and are, by
        // definition, absent from `id`'s own forward list — the symmetric
        // backlink set above cannot reach them. Purge them from the tracked
        // exception record so deleting `id` leaves no row pointing at the
        // now-removed node (ONE-325 active-index purge contract).
        purge_one_way_exceptions_for_target(store, wtxn, id, ops)?;
    }

    store
        .hnsw_meta()
        .put(wtxn, COUNT_KEY, &new_count.to_le_bytes())?;

    if new_count == 0 {
        store.hnsw_meta().delete(wtxn, ENTRY_POINT_KEY)?;
        return Ok(());
    }

    let entry_point =
        read_entry_point(store, &*wtxn)?.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
    if entry_point == *id {
        let (replacement_key, _) = store
            .hnsw_neighbors()
            .first(&*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_REMAINING_NODES_MISSING))?;
        let replacement =
            parse_entity_id(&replacement_key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
                other => other,
            })?;
        store
            .hnsw_meta()
            .put(wtxn, ENTRY_POINT_KEY, replacement.as_bytes())?;
    }

    Ok(())
}

/// Beam-search knobs, bundled so probed call sites stay within argument
/// limits.
#[derive(Clone, Copy, Debug)]
struct BeamOptions {
    ef: usize,
    lenient_neighbors: bool,
    check_existence: bool,
    /// EMB-2 MRL funnel: number of leading vector components every distance
    /// computation scores over. Equal to `config.dimensions` when the
    /// funnel is off.
    score_dims: usize,
}

/// The scoring prefix length for one vault: `fast_dims` when the MRL funnel
/// is configured, full `dimensions` otherwise.
fn score_dims_for(config: &VaultConfig) -> usize {
    config.fast_dims.map_or(config.dimensions, usize::from)
}

/// Prefix-slices one operand for a funnel distance computation. Prefix
/// cosine is exact for the prefix space — `cosine_distance` computes norms
/// per call, so no renormalization step is needed.
///
/// A vector with FEWER than `score_dims` components fails closed
/// (persisted-data corruption): healthy rows are always full-dimension and
/// both accepted query lengths are >= `score_dims`, so a short vector can
/// only be a truncated/corrupted row — and scoring it on a partial prefix
/// would let it look CLOSER than healthy rows rather than being rejected.
fn score_prefix(vector: &[f32], score_dims: usize) -> Result<&[f32]> {
    if vector.len() < score_dims {
        return Err(Error::CorruptedIndex(ERR_VECTOR_ROW_TOO_SHORT));
    }
    Ok(&vector[..score_dims])
}

fn beam_search(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    query_vector: &[f32],
    entry_point: EntityId,
    options: BeamOptions,
    dimensions: usize,
    ops: &mut u64,
) -> Result<Vec<HeapEntry>> {
    let BeamOptions {
        ef,
        lenient_neighbors,
        check_existence,
        score_dims,
    } = options;
    let ef = ef.max(1);
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    *ops += 1;
    let Some(entry_vector) =
        load_vector_into(store, txn, &entry_point, dimensions, &mut vector_buffer)?
    else {
        return Err(Error::CorruptedIndex(ERR_ENTRY_POINT_VECTOR_MISSING));
    };

    let entry = HeapEntry {
        id: entry_point,
        distance: cosine_distance(
            score_prefix(query_vector, score_dims)?,
            score_prefix(entry_vector, score_dims)?,
        ),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let graph_nodes = usize::try_from(store.hnsw_neighbors().len(txn)?).unwrap_or(0);
    // Reserve extra headroom so the visited set can absorb frontier growth
    // without immediately rehashing.
    let mut visited: HashSet<EntityId> =
        HashSet::with_capacity(visited_capacity_hint(ef, graph_nodes));

    visited.insert(entry_point);
    candidates.push(Reverse(entry));

    if !check_existence || store.entities().get(txn, entry_point.as_bytes())?.is_some() {
        results.push(entry);
    }

    while let Some(Reverse(current)) = candidates.pop() {
        let worst_distance = results.peek().map_or(f32::INFINITY, |entry| entry.distance);

        if results.len() >= ef && current.distance > worst_distance {
            break;
        }

        *ops += 1;
        let neighbors = if lenient_neighbors {
            load_neighbors_lenient(store, txn, &current.id)?
        } else {
            load_neighbors(store, txn, &current.id)?
        };
        for neighbor_id in neighbors {
            if !visited.insert(neighbor_id) {
                continue;
            }

            *ops += 1;
            if check_existence && store.entities().get(txn, neighbor_id.as_bytes())?.is_none() {
                continue;
            }

            let Some(neighbor_vector) =
                load_vector_into(store, txn, &neighbor_id, dimensions, &mut vector_buffer)?
            else {
                continue;
            };

            let distance = cosine_distance(
                score_prefix(query_vector, score_dims)?,
                score_prefix(neighbor_vector, score_dims)?,
            );
            let should_add = results.len() < ef
                || distance < results.peek().map_or(f32::INFINITY, |entry| entry.distance);

            if should_add {
                let candidate = HeapEntry {
                    id: neighbor_id,
                    distance,
                };
                candidates.push(Reverse(candidate));
                results.push(candidate);

                if results.len() > ef {
                    results.pop();
                }
            }
        }
    }

    let mut found = results.into_vec();
    found.sort_unstable();
    Ok(found)
}

fn beam_search_snapshot(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    query_id: &EntityId,
    entry_point: EntityId,
    ef: usize,
    score_dims: usize,
    dimensions: usize,
) -> Result<Vec<HeapEntry>> {
    let ef = ef.max(1);
    let query_vector = load_required_vector(store, rtxn, query_id, dimensions)?;
    let entry_vector = load_required_vector(store, rtxn, &entry_point, dimensions)?;
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    let entry = HeapEntry {
        id: entry_point,
        distance: cosine_distance(
            score_prefix(&query_vector, score_dims)?,
            score_prefix(&entry_vector, score_dims)?,
        ),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let mut visited: HashSet<EntityId> =
        HashSet::with_capacity(visited_capacity_hint(ef, neighbors_by_id.len()));

    visited.insert(entry_point);
    candidates.push(Reverse(entry));
    results.push(entry);

    while let Some(Reverse(current)) = candidates.pop() {
        let worst_distance = results.peek().map_or(f32::INFINITY, |entry| entry.distance);

        if results.len() >= ef && current.distance > worst_distance {
            break;
        }

        for neighbor_id in neighbors_by_id
            .get(&current.id)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            if !visited.insert(*neighbor_id) {
                continue;
            }

            let Some(neighbor_vector) =
                load_vector_into(store, rtxn, neighbor_id, dimensions, &mut vector_buffer)?
            else {
                continue;
            };

            let distance = cosine_distance(
                score_prefix(&query_vector, score_dims)?,
                score_prefix(neighbor_vector, score_dims)?,
            );
            let should_add = results.len() < ef
                || distance < results.peek().map_or(f32::INFINITY, |entry| entry.distance);

            if should_add {
                let candidate = HeapEntry {
                    id: *neighbor_id,
                    distance,
                };
                candidates.push(Reverse(candidate));
                results.push(candidate);

                if results.len() > ef {
                    results.pop();
                }
            }
        }
    }

    let mut found = results.into_vec();
    found.sort_unstable();
    Ok(found)
}

fn visited_capacity_hint(ef: usize, graph_nodes: usize) -> usize {
    ef.saturating_mul(2).min(graph_nodes.max(1))
}

/// Legacy refresh contract: rebuild the whole graph from the current
/// `vectors` snapshot with the historical asymmetric link discipline. Does
/// NOT set the symmetric marker — pre-migration vaults keep their legacy
/// shape until `maintain().rebuild_hnsw()` migrates them.
fn rebuild_hnsw_from_current_snapshot(
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    increment_legacy_snapshot_rebuilds(store, wtxn)?;
    let vector_ids = collect_vector_ids(store, &*wtxn)?;
    let rebuilt =
        build_hnsw_graph_from_snapshot(store, config, &*wtxn, &vector_ids, LinkDiscipline::Legacy)?;
    write_rebuilt_hnsw(store, wtxn, &rebuilt, LinkDiscipline::Legacy)
}

fn collect_vector_ids(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    let capacity = usize::try_from(store.vectors().len(txn)?).unwrap_or(0);
    let mut vector_ids = Vec::with_capacity(capacity);
    for entry in store.vectors().iter(txn)? {
        let (key, _) = entry?;
        vector_ids.push(
            parse_entity_id(&key, ERR_VECTOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_VECTOR_KEY_BYTES),
                other => other,
            })?,
        );
    }
    Ok(vector_ids)
}

fn select_best_entry_point(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    suggested: Option<EntityId>,
) -> Option<EntityId> {
    select_best_entry_point_probed(neighbors_by_id, suggested, &mut 0)
}

/// Selects the rebuild entry point, counting unit operations into `ops`.
///
/// Reachability here is DIRECTED: `m_max_0` pruning makes neighbor lists
/// asymmetric, so undirected components are not equivalent. The previous
/// implementation ran one full BFS per candidate node (`O(V·(V+E))`); this
/// version is linear-class:
///
/// 1. Fast path: a single BFS from `suggested`. Fully reachable graphs (the
///    common case after a healthy rebuild) keep the cheap early-exit and the
///    suggested entry point.
/// 2. Otherwise: condense the graph into strongly connected components
///    (iterative Tarjan, `O(V+E)`) and pick from the source SCCs
///    (condensation in-degree zero). Every maximal-reach node lives in a
///    source SCC — a non-source SCC is reached from some predecessor SCC
///    whose forward closure is strictly larger (the condensation is acyclic,
///    so the predecessor's own nodes are not in the successor's closure) —
///    therefore comparing source closures suffices. Winner: the source SCC
///    whose forward closure covers the most nodes; ties break to the lowest
///    entity id among the tied sources' member nodes, preserving the
///    previous per-candidate scan's deterministic tie-break.
///
/// `ops` increments once per node visit and once per edge scan in every
/// phase, so tests can pin the complexity class.
fn select_best_entry_point_probed(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    suggested: Option<EntityId>,
    ops: &mut u64,
) -> Option<EntityId> {
    let initial = suggested.or_else(|| neighbors_by_id.keys().copied().next())?;
    if reachable_from_entry_probed(neighbors_by_id, initial, ops).len() == neighbors_by_id.len() {
        return Some(initial);
    }

    let condensation = condense_sccs(neighbors_by_id, ops);
    best_source_scc_member(&condensation, ops)
}

/// Strongly-connected-component condensation of an in-memory rebuild graph.
struct SccCondensation {
    /// Member-node count per SCC.
    sizes: Vec<usize>,
    /// Lowest member entity id per SCC (deterministic tie-break key).
    min_ids: Vec<EntityId>,
    /// Outgoing condensation edges per SCC. May contain duplicates;
    /// consumers deduplicate via visited marks.
    adjacency: Vec<Vec<usize>>,
    /// True when the SCC has at least one incoming condensation edge,
    /// i.e. it is not a source.
    has_incoming: Vec<bool>,
}

const TARJAN_UNVISITED: usize = usize::MAX;

/// Iterative Tarjan SCC condensation, `O(V+E)`. Explicit DFS frames keep the
/// recursion depth off the thread stack (chain-shaped graphs are `O(V)`
/// deep). Neighbor ids absent from `neighbors_by_id` are skipped: rebuild
/// adjacency only references inserted nodes.
fn condense_sccs(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    ops: &mut u64,
) -> SccCondensation {
    let node_count = neighbors_by_id.len();
    let mut ids = Vec::with_capacity(node_count);
    let mut index_of = HashMap::with_capacity(node_count);
    for id in neighbors_by_id.keys() {
        index_of.insert(*id, ids.len());
        ids.push(*id);
    }

    let mut discovery = vec![TARJAN_UNVISITED; node_count];
    let mut lowlink = vec![0_usize; node_count];
    let mut on_stack = vec![false; node_count];
    let mut scc_of = vec![TARJAN_UNVISITED; node_count];
    let mut member_stack: Vec<usize> = Vec::new();
    let mut next_discovery = 0_usize;

    let mut sizes: Vec<usize> = Vec::new();
    let mut min_ids: Vec<EntityId> = Vec::new();

    // DFS frames: (node, offset of the next unexamined edge).
    let mut frames: Vec<(usize, usize)> = Vec::new();
    for root in 0..node_count {
        if discovery[root] != TARJAN_UNVISITED {
            continue;
        }
        frames.push((root, 0));
        while let Some(&mut (node, ref mut edge_pos)) = frames.last_mut() {
            if *edge_pos == 0 {
                *ops += 1;
                discovery[node] = next_discovery;
                lowlink[node] = next_discovery;
                next_discovery += 1;
                on_stack[node] = true;
                member_stack.push(node);
            }

            let neighbors = neighbors_by_id[&ids[node]].as_slice();
            let mut descend_into = None;
            while *edge_pos < neighbors.len() {
                let neighbor = &neighbors[*edge_pos];
                *edge_pos += 1;
                *ops += 1;
                let Some(&target) = index_of.get(neighbor) else {
                    continue;
                };
                if discovery[target] == TARJAN_UNVISITED {
                    descend_into = Some(target);
                    break;
                }
                if on_stack[target] {
                    lowlink[node] = lowlink[node].min(discovery[target]);
                }
            }
            if let Some(child) = descend_into {
                frames.push((child, 0));
                continue;
            }

            if lowlink[node] == discovery[node] {
                let scc = sizes.len();
                let mut size = 0_usize;
                let mut min_id = ids[node];
                loop {
                    let member = member_stack
                        .pop()
                        .expect("Tarjan member stack holds every open node until its root pops");
                    on_stack[member] = false;
                    scc_of[member] = scc;
                    size += 1;
                    if ids[member].as_bytes() < min_id.as_bytes() {
                        min_id = ids[member];
                    }
                    if member == node {
                        break;
                    }
                }
                sizes.push(size);
                min_ids.push(min_id);
            }

            frames.pop();
            if let Some(&mut (parent, _)) = frames.last_mut() {
                lowlink[parent] = lowlink[parent].min(lowlink[node]);
            }
        }
    }

    let scc_count = sizes.len();
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); scc_count];
    let mut has_incoming = vec![false; scc_count];
    for (node, id) in ids.iter().enumerate() {
        *ops += 1;
        let from = scc_of[node];
        for neighbor in &neighbors_by_id[id] {
            *ops += 1;
            let Some(&target) = index_of.get(neighbor) else {
                continue;
            };
            let to = scc_of[target];
            if from != to {
                adjacency[from].push(to);
                has_incoming[to] = true;
            }
        }
    }

    SccCondensation {
        sizes,
        min_ids,
        adjacency,
        has_incoming,
    }
}

/// Picks the entry point from the condensation: the lowest member entity id
/// among the source SCCs whose forward closure covers the most nodes.
///
/// Forward-closure node counts are computed once per SCC by a single
/// reverse-topological DP rather than a fresh per-source walk. Iterative
/// Tarjan finalizes SCCs sinks-first, so every condensation edge points to a
/// strictly smaller SCC index (see the `debug_assert` below); iterating
/// indices in increasing order therefore visits every child before its
/// parents — reverse topological order — without a separate sort.
///
/// An SCC's children have *disjoint* forward closures unless the SCC tops a
/// diamond (two child paths reconverge), so a single-child (or childless) SCC
/// reuses its child's already-computed count in `O(1)`. Only a genuine
/// diamond needs its exact closure recomputed via one bounded BFS — the
/// shared-suffix / chain shapes that broke the old per-source walk
/// (`Θ(sources · suffix)`) are diamond-free, so each condensation edge is
/// relaxed once and the whole pass stays `O(V+E)`.
fn best_source_scc_member(condensation: &SccCondensation, ops: &mut u64) -> Option<EntityId> {
    let scc_count = condensation.sizes.len();
    if scc_count == 0 {
        return None;
    }

    // Reachable-node count of each SCC's forward closure (the SCC included).
    let mut reach = vec![0_usize; scc_count];
    // Per-parent dedup stamp: the stored adjacency may repeat a target.
    let mut child_seen = vec![usize::MAX; scc_count];
    // Per-BFS visited stamp for the diamond fallback.
    let mut bfs_seen = vec![usize::MAX; scc_count];
    let mut frontier: Vec<usize> = Vec::new();

    for scc in 0..scc_count {
        *ops += 1;
        let mut unique_children = 0_usize;
        let mut single_child = usize::MAX;
        for &child in &condensation.adjacency[scc] {
            *ops += 1;
            debug_assert!(
                child < scc,
                "Tarjan finalizes sinks first, so condensation edges point to \
                 strictly smaller SCC indices already carrying a final reach count"
            );
            if child_seen[child] != scc {
                child_seen[child] = scc;
                unique_children += 1;
                single_child = child;
            }
        }

        reach[scc] = if unique_children <= 1 {
            // No siblings to overlap with: the child's closure is disjoint from
            // this SCC, so summing is exact and `O(1)`.
            condensation.sizes[scc]
                + if unique_children == 1 {
                    reach[single_child]
                } else {
                    0
                }
        } else {
            // Diamond: child closures may share descendants, so summing would
            // double count. Recompute the exact closure with one BFS that visits
            // every reachable SCC a single time.
            let mut closure_nodes = 0_usize;
            bfs_seen[scc] = scc;
            frontier.clear();
            frontier.push(scc);
            while let Some(node) = frontier.pop() {
                *ops += 1;
                closure_nodes += condensation.sizes[node];
                for &next in &condensation.adjacency[node] {
                    *ops += 1;
                    if bfs_seen[next] != scc {
                        bfs_seen[next] = scc;
                        frontier.push(next);
                    }
                }
            }
            closure_nodes
        };
    }

    // Winner: the source SCC (no incoming condensation edge) with the largest
    // forward closure; ties break to the lowest member entity id — the exact
    // selection the per-candidate reference scan makes.
    let mut best: Option<(usize, EntityId)> = None;
    for ((&closure_nodes, &has_incoming), &candidate_id) in reach
        .iter()
        .zip(&condensation.has_incoming)
        .zip(&condensation.min_ids)
    {
        *ops += 1;
        if has_incoming {
            continue;
        }

        let replace = match &best {
            None => true,
            Some((best_closure, best_id)) => {
                closure_nodes > *best_closure
                    || (closure_nodes == *best_closure
                        && candidate_id.as_bytes() < best_id.as_bytes())
            }
        };
        if replace {
            best = Some((closure_nodes, candidate_id));
        }
    }

    best.map(|(_, id)| id)
}

/// Test-facing wrapper: production code paths use
/// [`reachable_from_entry_probed`] so op counts cover the BFS fast path.
#[cfg(test)]
fn reachable_from_entry(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    entry_point: EntityId,
) -> HashSet<EntityId> {
    reachable_from_entry_probed(neighbors_by_id, entry_point, &mut 0)
}

fn reachable_from_entry_probed(
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    entry_point: EntityId,
    ops: &mut u64,
) -> HashSet<EntityId> {
    let mut visited = HashSet::with_capacity(neighbors_by_id.len().max(1));
    let mut frontier = vec![entry_point];

    while let Some(current) = frontier.pop() {
        if !visited.insert(current) {
            continue;
        }
        *ops += 1;
        if let Some(neighbors) = neighbors_by_id.get(&current) {
            for neighbor in neighbors {
                *ops += 1;
                frontier.push(*neighbor);
            }
        }
    }

    visited
}

fn read_count(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, COUNT_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_COUNT_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn hnsw_entity_count(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<usize> {
    usize::try_from(read_count(store, txn)?).map_err(|_| Error::IndexOverflow("hnsw entity count"))
}

fn read_entry_point(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Option<EntityId>> {
    let Some(raw) = store.hnsw_meta().get(txn, ENTRY_POINT_KEY)? else {
        return Ok(None);
    };

    parse_entity_id(&raw, ERR_ENTRY_POINT_BYTES)
        .map_err(|e| match e {
            Error::InvalidKey => Error::CorruptedIndex(ERR_ENTRY_POINT_BYTES),
            other => other,
        })
        .map(Some)
}

fn decode_neighbors(raw: &[u8], lenient: bool) -> Result<Vec<EntityId>> {
    let (chunks, rem) = raw.as_chunks::<ENTITY_ID_LEN>();
    if !rem.is_empty() {
        return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES));
    }

    let mut neighbors = Vec::with_capacity(chunks.len());
    for bytes in chunks {
        match EntityId::from_bytes(*bytes) {
            Ok(neighbor) => neighbors.push(neighbor),
            // Reserved sentinel keys are the only `from_bytes` failure mode possible
            // after `chunks_exact(EID_LEN)` — length is fixed by the iterator. So
            // `lenient` mode never silently swallows length corruption; only the
            // sentinel-rejection branch is skipped.
            Err(_) if lenient => continue,
            Err(_) => return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES)),
        }
    }

    Ok(neighbors)
}

fn load_neighbors(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors().get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    decode_neighbors(&raw, false)
}

fn load_neighbors_lenient(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors().get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    decode_neighbors(&raw, true)
}

fn write_neighbors(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    neighbors: &[EntityId],
) -> Result<()> {
    let mut bytes = Vec::with_capacity(neighbors.len() * ENTITY_ID_LEN);
    for neighbor in neighbors {
        bytes.extend_from_slice(neighbor.as_bytes());
    }

    store.hnsw_neighbors().put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}

fn load_vector(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    dimensions: usize,
) -> Result<Option<Vec<f32>>> {
    let Some(raw) = store.vectors().get(txn, id.as_bytes())? else {
        return Ok(None);
    };

    let mut vector = Vec::new();
    decode_vector_into(&raw, dimensions, &mut vector)?;
    Ok(Some(vector))
}

fn load_vector_into<'a>(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    dimensions: usize,
    scratch: &'a mut Vec<f32>,
) -> Result<Option<&'a [f32]>> {
    let Some(raw) = store.vectors().get(txn, id.as_bytes())? else {
        return Ok(None);
    };

    decode_vector_into(&raw, dimensions, scratch).map(Some)
}

fn load_required_vector(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    dimensions: usize,
) -> Result<Vec<f32>> {
    load_vector(store, txn, id, dimensions)?.ok_or(Error::InvariantViolation(
        "validated rebuild vector disappeared within the same read snapshot",
    ))
}

fn prune_neighbors_for_node(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    node_id: &EntityId,
    neighbors: &[EntityId],
    max_neighbors: usize,
    score_dims: usize,
    dimensions: usize,
    ops: &mut u64,
) -> Result<Vec<EntityId>> {
    let mut node_buffer = Vec::new();
    *ops += 1;
    let Some(node_vector) = load_vector_into(store, txn, node_id, dimensions, &mut node_buffer)?
    else {
        return Ok(neighbors.iter().copied().take(max_neighbors).collect());
    };
    let mut neighbor_buffer = Vec::with_capacity(node_vector.len());

    let mut seen = HashSet::with_capacity(neighbors.len());
    let mut scored = Vec::with_capacity(neighbors.len());

    for neighbor_id in neighbors {
        if *neighbor_id == *node_id || !seen.insert(*neighbor_id) {
            continue;
        }

        *ops += 1;
        let Some(neighbor_vector) =
            load_vector_into(store, txn, neighbor_id, dimensions, &mut neighbor_buffer)?
        else {
            continue;
        };

        scored.push(HeapEntry {
            id: *neighbor_id,
            distance: cosine_distance(
                score_prefix(node_vector, score_dims)?,
                score_prefix(neighbor_vector, score_dims)?,
            ),
        });
    }

    scored.sort_unstable();
    scored.truncate(max_neighbors);

    Ok(scored.into_iter().map(|entry| entry.id).collect())
}

/// Legacy-only delete-time full scan. Symmetric-marker vaults never call
/// this: their backlinks are exactly the node's own forward neighbor list.
fn collect_backlink_targets(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    ops: &mut u64,
) -> Result<Vec<EntityId>> {
    let mut targets = Vec::new();
    for entry in store.hnsw_neighbors().iter(txn)? {
        *ops += 1;
        let (key, raw) = entry?;
        let node_id = parse_entity_id(&key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
            Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
            other => other,
        })?;
        if node_id == *id {
            continue;
        }

        if !neighbor_bytes_contain(&raw, id)? {
            continue;
        }
        targets.push(node_id);
    }
    Ok(targets)
}

fn scrub_backlinks_in_place(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    targets: &[EntityId],
    ops: &mut u64,
) -> Result<()> {
    for node_id in targets {
        *ops += 1;
        let Some(raw) = store.hnsw_neighbors().get(&*wtxn, node_id.as_bytes())? else {
            continue;
        };
        let Some(scrubbed) = scrub_neighbor_bytes(&raw, id)? else {
            continue;
        };
        store
            .hnsw_neighbors()
            .put(wtxn, node_id.as_bytes(), &scrubbed)?;
        *ops += 1;
    }
    Ok(())
}

/// In-memory mirror of [`detach_reverse_link`] for the snapshot rebuilder:
/// removes `from` out of `victim`'s list, keeping the link one-way when the
/// victim would otherwise be orphaned.
fn detach_reverse_link_in_memory(
    neighbors_by_id: &mut HashMap<EntityId, Vec<EntityId>>,
    from: &EntityId,
    victim: &EntityId,
) {
    let Some(list) = neighbors_by_id.get_mut(victim) else {
        return;
    };
    if !list.contains(from) || list.len() == 1 {
        return;
    }
    list.retain(|entry| entry != from);
}

fn neighbor_bytes_contain(raw: &[u8], target: &EntityId) -> Result<bool> {
    let mut chunks = raw.chunks_exact(ENTITY_ID_LEN);
    if !chunks.remainder().is_empty() {
        return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES));
    }

    Ok(chunks.any(|chunk| chunk == target.as_bytes()))
}

fn scrub_neighbor_bytes(raw: &[u8], target: &EntityId) -> Result<Option<Vec<u8>>> {
    let mut chunks = raw.chunks_exact(ENTITY_ID_LEN);
    if !chunks.remainder().is_empty() {
        return Err(Error::CorruptedIndex(ERR_NEIGHBOR_VALUE_BYTES));
    }

    let mut changed = false;
    let mut scrubbed = Vec::with_capacity(raw.len());
    for chunk in &mut chunks {
        if chunk == target.as_bytes() {
            changed = true;
            continue;
        }
        scrubbed.extend_from_slice(chunk);
    }

    Ok(changed.then_some(scrubbed))
}

fn decode_vector_into<'a>(
    raw: &[u8],
    dimensions: usize,
    scratch: &'a mut Vec<f32>,
) -> Result<&'a [f32]> {
    crate::store::decode_vector_row_into(raw, dimensions, scratch)
        .map_err(|_| Error::CorruptedIndex(ERR_VECTOR_BYTES))
}

#[cfg(test)]
mod tests;
