use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use heed::types::Bytes;
use heed::{Database, RoTxn, RwTxn};

use crate::distance::cosine_distance;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::VECTOR_VERSION_KEY;
use crate::types::{ENTITY_ID_LEN, EntityId, ScoredEntity, VaultConfig, parse_entity_id};

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

fn read_link_discipline(store: &Store, txn: &RoTxn<'_>) -> Result<LinkDiscipline> {
    match store.hnsw_meta.get(txn, SYMMETRIC_LINKS_KEY)? {
        None => Ok(LinkDiscipline::Legacy),
        Some([SYMMETRIC_LINKS_ENABLED]) => Ok(LinkDiscipline::Symmetric),
        Some(_) => Err(Error::CorruptedIndex(ERR_SYMMETRIC_MARKER_BYTES)),
    }
}

/// Stamps the vault as maintaining the symmetric-link invariant. Called when
/// a graph is created from empty (fresh vaults) and when a full rebuild
/// rewrites every row symmetrically (the one-time migration path).
pub(crate) fn mark_symmetric_links(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    store
        .hnsw_meta
        .put(wtxn, SYMMETRIC_LINKS_KEY, &[SYMMETRIC_LINKS_ENABLED])?;
    Ok(())
}

pub(crate) fn read_refresh_fallback_rebuilds(store: &Store, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta.get(txn, REFRESH_FALLBACK_REBUILDS_KEY)? else {
        return Ok(0);
    };
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_FALLBACK_COUNTER_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

fn increment_refresh_fallback_rebuilds(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let next = read_refresh_fallback_rebuilds(store, &*wtxn)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hnsw refresh fallback counter"))?;
    store
        .hnsw_meta
        .put(wtxn, REFRESH_FALLBACK_REBUILDS_KEY, &next.to_le_bytes())?;
    Ok(())
}

pub(crate) fn read_legacy_snapshot_rebuilds(store: &Store, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta.get(txn, LEGACY_REBUILDS_KEY)? else {
        return Ok(0);
    };
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_LEGACY_REBUILDS_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

fn increment_legacy_snapshot_rebuilds(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let next = read_legacy_snapshot_rebuilds(store, &*wtxn)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hnsw legacy rebuild counter"))?;
    store
        .hnsw_meta
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
    store: &Store,
    txn: &RoTxn<'_>,
    target: &EntityId,
) -> Result<Vec<EntityId>> {
    match store.hnsw_meta.get(txn, &one_way_exception_key(target))? {
        Some(raw) => decode_exception_holders(raw),
        None => Ok(Vec::new()),
    }
}

/// Records that `holder` keeps a one-way link to `target` (orphan protection).
/// Idempotent: a holder already present is not duplicated.
fn record_one_way_exception(
    store: &Store,
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
        .hnsw_meta
        .put(wtxn, &one_way_exception_key(target), &bytes)?;
    *ops += 1;
    Ok(())
}

/// Scrubs a node being deleted out of every holder that kept a one-way link to
/// it (orphan protection), then drops the exception record. This is the half
/// of a symmetric delete that the deleted node's own forward list cannot reach
/// (the holders are, by definition, NOT in it). Bounded by the holder count.
fn purge_one_way_exceptions_for_target(
    store: &Store,
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
    store.hnsw_meta.delete(wtxn, &one_way_exception_key(id))?;
    *ops += 1;
    Ok(())
}

/// Drops every persisted one-way exception record. Used before a full rebuild,
/// which replaces the whole graph shape and so invalidates the old records;
/// the symmetric paths re-derive them from the rebuilt rows. Only the
/// `ONE_WAY_EXCEPTION_PREFIX` keyspace is touched — unrelated `hnsw_meta` rows
/// (graph/model/schema markers) are preserved.
fn clear_one_way_exceptions(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let mut stale_keys: Vec<Vec<u8>> = Vec::new();
    for entry in store.hnsw_meta.iter(wtxn)? {
        let (key, _) = entry?;
        if key.starts_with(ONE_WAY_EXCEPTION_PREFIX) {
            stale_keys.push(key.to_vec());
        }
    }
    for key in stale_keys {
        store.hnsw_meta.delete(wtxn, &key)?;
    }
    Ok(())
}

/// Re-derives the one-way exception records from a freshly rebuilt symmetric
/// graph: every link `node -> neighbor` whose neighbor row does not point back
/// is a tracked orphan-protection exception keyed by `neighbor`.
fn rebuild_one_way_exception_index(
    store: &Store,
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
            .hnsw_meta
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
    store: &Store,
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
    store: &Store,
    config: &VaultConfig,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    vector: &[f32],
    ops: &mut u64,
) -> Result<InsertOutcome> {
    let discipline = read_link_discipline(store, &*wtxn)?;
    *ops += 1;
    if store.hnsw_neighbors.get(&*wtxn, id.as_bytes())?.is_some() {
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
            || store.hnsw_neighbors.first(&*wtxn)?.is_some()
        {
            return Err(Error::CorruptedIndex(ERR_ZERO_COUNT_GRAPH_NOT_EMPTY));
        }
        store.hnsw_meta.put(wtxn, ENTRY_POINT_KEY, id.as_bytes())?;
        store.hnsw_meta.put(wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
        store.hnsw_neighbors.put(wtxn, id.as_bytes(), &[])?;
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
        },
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
    store.hnsw_meta.put(wtxn, COUNT_KEY, &count.to_le_bytes())?;

    Ok(InsertOutcome::Applied)
}

/// Legacy (pre-migration) backlink attachment: prune may drop links without
/// removing the reverse direction, leaving one-way edges. Preserved verbatim
/// for vaults that have not run the symmetry migration.
fn attach_backlinks_legacy(
    store: &Store,
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
    store: &Store,
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
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    from: &EntityId,
    victim: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let Some(raw) = store.hnsw_neighbors.get(&*wtxn, victim.as_bytes())? else {
        return Ok(());
    };
    let list = decode_neighbors(raw, false)?;
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
    store: &Store,
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
        let Some(raw) = store.hnsw_neighbors.get(&*wtxn, neighbor_id.as_bytes())? else {
            continue;
        };
        let list = decode_neighbors(raw, false)?;
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
    store.hnsw_neighbors.delete(wtxn, id.as_bytes())?;
    *ops += 1;

    if count == 1 {
        // Sole node: trivially re-anchor at the new position.
        write_neighbors(store, wtxn, id, &[])?;
        store.hnsw_meta.put(wtxn, ENTRY_POINT_KEY, id.as_bytes())?;
        return Ok(());
    }

    if entry_point == *id {
        let (replacement_key, _) = store
            .hnsw_neighbors
            .first(&*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_REMAINING_NODES_MISSING))?;
        entry_point =
            parse_entity_id(replacement_key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
                other => other,
            })?;
        store
            .hnsw_meta
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
        },
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
        let Some(raw) = store.hnsw_neighbors.get(&*wtxn, orphan.as_bytes())? else {
            continue;
        };
        if !decode_neighbors(raw, false)?.is_empty() {
            continue;
        }
        let Some(orphan_vector) = load_vector(store, &*wtxn, &orphan)? else {
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
            },
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
    store: &Store,
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
    store: &Store,
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
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    rebuilt: &RebuiltHnswGraph,
    discipline: LinkDiscipline,
) -> Result<()> {
    store.hnsw_neighbors.clear(wtxn)?;
    // Rebuild owns only the live graph shape. Preserve unrelated metadata such as
    // graph/version markers, persisted model ids, and schema/config keys.
    store.hnsw_meta.delete(wtxn, COUNT_KEY)?;
    store.hnsw_meta.delete(wtxn, ENTRY_POINT_KEY)?;
    // The old one-way exception records describe the replaced graph; drop them
    // (only the `ow1:` keyspace, never unrelated metadata) and re-derive them
    // from the rebuilt rows for symmetric graphs below.
    clear_one_way_exceptions(store, wtxn)?;

    if let Some(entry_point) = rebuilt.entry_point {
        store
            .hnsw_meta
            .put(wtxn, ENTRY_POINT_KEY, entry_point.as_bytes())?;
    }
    store
        .hnsw_meta
        .put(wtxn, COUNT_KEY, &rebuilt.count.to_le_bytes())?;

    for (id, neighbors) in &rebuilt.neighbors {
        write_neighbors(store, wtxn, id, neighbors)?;
    }

    if discipline == LinkDiscipline::Symmetric {
        rebuild_one_way_exception_index(store, wtxn, &rebuilt.neighbors)?;
    }

    Ok(())
}

pub(crate) fn read_vector_version(store: &Store, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta.get(txn, VECTOR_VERSION_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_VECTOR_VERSION_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn has_population(hnsw_meta: &Database<Bytes, Bytes>, txn: &RoTxn<'_>) -> Result<bool> {
    if let Some(raw) = hnsw_meta.get(txn, COUNT_KEY)? {
        let bytes: [u8; 8] = raw
            .try_into()
            .map_err(|_| Error::CorruptedIndex(ERR_COUNT_BYTES))?;
        if u64::from_le_bytes(bytes) > 0 {
            return Ok(true);
        }
    }

    Ok(hnsw_meta.get(txn, ENTRY_POINT_KEY)?.is_some())
}

pub(crate) fn increment_vector_version(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<u64> {
    let current = read_vector_version(store, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("vector version"))?;
    store
        .hnsw_meta
        .put(wtxn, VECTOR_VERSION_KEY, &next.to_le_bytes())?;
    Ok(next)
}
pub(crate) fn hnsw_search(
    store: &Store,
    config: &VaultConfig,
    rtxn: &RoTxn<'_>,
    query_vector: &[f32],
    limit: usize,
) -> Result<Vec<ScoredEntity>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let count = read_count(store, rtxn)?;
    let entry_point = read_entry_point(store, rtxn)?;
    if count == 0 {
        if entry_point.is_some() || store.hnsw_neighbors.first(rtxn)?.is_some() {
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
        },
        &mut 0,
    )?;

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
pub(crate) fn hnsw_deindex(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    hnsw_deindex_probed(store, wtxn, id, &mut 0)
}

/// [`hnsw_deindex`] with unit-operation accounting (`ops` increments once
/// per row read/write/delete and once per scanned row on the legacy path),
/// so tests can pin that symmetric-graph deletes never iterate the full
/// `hnsw_neighbors` DB (ONE-325 AC1).
pub(crate) fn hnsw_deindex_probed(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let own_neighbors = match store.hnsw_neighbors.get(&*wtxn, id.as_bytes())? {
        Some(raw) => decode_neighbors(raw, false)?,
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
    store.hnsw_neighbors.delete(wtxn, id.as_bytes())?;
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
        .hnsw_meta
        .put(wtxn, COUNT_KEY, &new_count.to_le_bytes())?;

    if new_count == 0 {
        store.hnsw_meta.delete(wtxn, ENTRY_POINT_KEY)?;
        return Ok(());
    }

    let entry_point =
        read_entry_point(store, &*wtxn)?.ok_or(Error::CorruptedIndex(ERR_ENTRY_POINT_MISSING))?;
    if entry_point == *id {
        let (replacement_key, _) = store
            .hnsw_neighbors
            .first(&*wtxn)?
            .ok_or(Error::CorruptedIndex(ERR_REMAINING_NODES_MISSING))?;
        let replacement =
            parse_entity_id(replacement_key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
                Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
                other => other,
            })?;
        store
            .hnsw_meta
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
}

fn beam_search(
    store: &Store,
    txn: &RoTxn<'_>,
    query_vector: &[f32],
    entry_point: EntityId,
    options: BeamOptions,
    ops: &mut u64,
) -> Result<Vec<HeapEntry>> {
    let BeamOptions {
        ef,
        lenient_neighbors,
        check_existence,
    } = options;
    let ef = ef.max(1);
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    *ops += 1;
    let Some(entry_vector) = load_vector_into(store, txn, &entry_point, &mut vector_buffer)? else {
        return Err(Error::CorruptedIndex(ERR_ENTRY_POINT_VECTOR_MISSING));
    };

    let entry = HeapEntry {
        id: entry_point,
        distance: cosine_distance(query_vector, entry_vector),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let graph_nodes = usize::try_from(store.hnsw_neighbors.len(txn)?).unwrap_or(0);
    // Reserve extra headroom so the visited set can absorb frontier growth
    // without immediately rehashing.
    let mut visited: HashSet<EntityId> =
        HashSet::with_capacity(visited_capacity_hint(ef, graph_nodes));

    visited.insert(entry_point);
    candidates.push(Reverse(entry));

    if !check_existence || store.entities.get(txn, entry_point.as_bytes())?.is_some() {
        results.push(entry);
    }

    while let Some(Reverse(current)) = candidates.pop() {
        let worst_distance = results
            .peek()
            .map(|entry| entry.distance)
            .unwrap_or(f32::INFINITY);

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
            if check_existence && store.entities.get(txn, neighbor_id.as_bytes())?.is_none() {
                continue;
            }

            let Some(neighbor_vector) =
                load_vector_into(store, txn, &neighbor_id, &mut vector_buffer)?
            else {
                continue;
            };

            let distance = cosine_distance(query_vector, neighbor_vector);
            let should_add = results.len() < ef
                || distance
                    < results
                        .peek()
                        .map(|entry| entry.distance)
                        .unwrap_or(f32::INFINITY);

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
    store: &Store,
    rtxn: &RoTxn<'_>,
    neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
    query_id: &EntityId,
    entry_point: EntityId,
    ef: usize,
) -> Result<Vec<HeapEntry>> {
    let ef = ef.max(1);
    let query_vector = load_required_vector(store, rtxn, query_id)?;
    let entry_vector = load_required_vector(store, rtxn, &entry_point)?;
    let mut vector_buffer = Vec::with_capacity(query_vector.len());

    let entry = HeapEntry {
        id: entry_point,
        distance: cosine_distance(&query_vector, &entry_vector),
    };

    let mut candidates: BinaryHeap<Reverse<HeapEntry>> = BinaryHeap::new();
    let mut results: BinaryHeap<HeapEntry> = BinaryHeap::new();
    let mut visited: HashSet<EntityId> =
        HashSet::with_capacity(visited_capacity_hint(ef, neighbors_by_id.len()));

    visited.insert(entry_point);
    candidates.push(Reverse(entry));
    results.push(entry);

    while let Some(Reverse(current)) = candidates.pop() {
        let worst_distance = results
            .peek()
            .map(|entry| entry.distance)
            .unwrap_or(f32::INFINITY);

        if results.len() >= ef && current.distance > worst_distance {
            break;
        }

        for neighbor_id in neighbors_by_id
            .get(&current.id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if !visited.insert(*neighbor_id) {
                continue;
            }

            let Some(neighbor_vector) =
                load_vector_into(store, rtxn, neighbor_id, &mut vector_buffer)?
            else {
                continue;
            };

            let distance = cosine_distance(&query_vector, neighbor_vector);
            let should_add = results.len() < ef
                || distance
                    < results
                        .peek()
                        .map(|entry| entry.distance)
                        .unwrap_or(f32::INFINITY);

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

fn collect_vector_ids(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    let capacity = usize::try_from(store.vectors.len(txn)?).unwrap_or(0);
    let mut vector_ids = Vec::with_capacity(capacity);
    for entry in store.vectors.iter(txn)? {
        let (key, _) = entry?;
        vector_ids.push(
            parse_entity_id(key, ERR_VECTOR_KEY_BYTES).map_err(|e| match e {
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

fn read_count(store: &Store, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta.get(txn, COUNT_KEY)? else {
        return Ok(0);
    };

    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_COUNT_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn hnsw_entity_count(store: &Store, txn: &RoTxn<'_>) -> Result<usize> {
    usize::try_from(read_count(store, txn)?).map_err(|_| Error::IndexOverflow("hnsw entity count"))
}

fn read_entry_point(store: &Store, txn: &RoTxn<'_>) -> Result<Option<EntityId>> {
    let Some(raw) = store.hnsw_meta.get(txn, ENTRY_POINT_KEY)? else {
        return Ok(None);
    };

    parse_entity_id(raw, ERR_ENTRY_POINT_BYTES)
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

fn load_neighbors(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors.get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    decode_neighbors(raw, false)
}

fn load_neighbors_lenient(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
    let Some(raw) = store.hnsw_neighbors.get(txn, id.as_bytes())? else {
        return Ok(Vec::new());
    };

    decode_neighbors(raw, true)
}

fn write_neighbors(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    neighbors: &[EntityId],
) -> Result<()> {
    let mut bytes = Vec::with_capacity(neighbors.len() * ENTITY_ID_LEN);
    for neighbor in neighbors {
        bytes.extend_from_slice(neighbor.as_bytes());
    }

    store.hnsw_neighbors.put(wtxn, id.as_bytes(), &bytes)?;
    Ok(())
}

fn load_vector(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<Vec<f32>>> {
    let Some(raw) = store.vectors.get(txn, id.as_bytes())? else {
        return Ok(None);
    };

    let mut vector = Vec::new();
    decode_vector_into(raw, &mut vector)?;
    Ok(Some(vector))
}

fn load_vector_into<'a>(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    scratch: &'a mut Vec<f32>,
) -> Result<Option<&'a [f32]>> {
    let Some(raw) = store.vectors.get(txn, id.as_bytes())? else {
        return Ok(None);
    };

    decode_vector_into(raw, scratch).map(Some)
}

fn load_required_vector(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<f32>> {
    load_vector(store, txn, id)?.ok_or(Error::InvariantViolation(
        "validated rebuild vector disappeared within the same read snapshot",
    ))
}

fn prune_neighbors_for_node(
    store: &Store,
    txn: &RoTxn<'_>,
    node_id: &EntityId,
    neighbors: &[EntityId],
    max_neighbors: usize,
    ops: &mut u64,
) -> Result<Vec<EntityId>> {
    let mut node_buffer = Vec::new();
    *ops += 1;
    let Some(node_vector) = load_vector_into(store, txn, node_id, &mut node_buffer)? else {
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
            load_vector_into(store, txn, neighbor_id, &mut neighbor_buffer)?
        else {
            continue;
        };

        scored.push(HeapEntry {
            id: *neighbor_id,
            distance: cosine_distance(node_vector, neighbor_vector),
        });
    }

    scored.sort_unstable();
    scored.truncate(max_neighbors);

    Ok(scored.into_iter().map(|entry| entry.id).collect())
}

/// Legacy-only delete-time full scan. Symmetric-marker vaults never call
/// this: their backlinks are exactly the node's own forward neighbor list.
fn collect_backlink_targets(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    ops: &mut u64,
) -> Result<Vec<EntityId>> {
    let mut targets = Vec::new();
    for entry in store.hnsw_neighbors.iter(txn)? {
        *ops += 1;
        let (key, raw) = entry?;
        let node_id = parse_entity_id(key, ERR_NEIGHBOR_KEY_BYTES).map_err(|e| match e {
            Error::InvalidKey => Error::CorruptedIndex(ERR_NEIGHBOR_KEY_BYTES),
            other => other,
        })?;
        if node_id == *id {
            continue;
        }

        if !neighbor_bytes_contain(raw, id)? {
            continue;
        }
        targets.push(node_id);
    }
    Ok(targets)
}

fn scrub_backlinks_in_place(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    targets: &[EntityId],
    ops: &mut u64,
) -> Result<()> {
    for node_id in targets {
        *ops += 1;
        let Some(raw) = store.hnsw_neighbors.get(&*wtxn, node_id.as_bytes())? else {
            continue;
        };
        let Some(scrubbed) = scrub_neighbor_bytes(raw, id)? else {
            continue;
        };
        store
            .hnsw_neighbors
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

fn decode_vector_into<'a>(raw: &[u8], scratch: &'a mut Vec<f32>) -> Result<&'a [f32]> {
    let (chunks, rem) = raw.as_chunks::<4>();
    if !rem.is_empty() {
        return Err(Error::CorruptedIndex(ERR_VECTOR_BYTES));
    }

    scratch.resize(chunks.len(), 0.0);
    for (slot, bytes) in scratch.iter_mut().zip(chunks) {
        *slot = f32::from_le_bytes(*bytes);
    }

    Ok(scratch.as_slice())
}

#[cfg(test)]
mod tests {
    use core::assert_matches;
    use tempfile::tempdir;

    use super::*;
    use crate::Vault;
    use crate::store::Store;
    use crate::types::{TimeRange, VaultConfig};

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.map_size = 64 * 1024 * 1024;
        config.hnsw.m_max_0 = 1;
        config.hnsw.ef_construction = 8;
        config.hnsw.ef_search = 8;
        config
    }

    fn point(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    fn vector_bytes(vector: &[f32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(vector.len() * 4);
        for value in vector {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn visited_capacity_hint_caps_by_graph_size() {
        assert_eq!(visited_capacity_hint(8, 3), 3);
        assert_eq!(visited_capacity_hint(2, 16), 4);
        assert_eq!(visited_capacity_hint(1, 0), 1);
    }

    fn put_vector_raw(
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        vector: &[f32],
    ) -> Result<()> {
        let bytes = vector_bytes(vector);
        store.vectors.put(wtxn, id.as_bytes(), &bytes)?;
        Ok(())
    }

    #[test]
    fn hnsw_deindex_scrubs_backlinks() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
        write_neighbors(&store, &mut wtxn, &b, &[a])?;
        write_neighbors(&store, &mut wtxn, &c, &[a])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

        hnsw_deindex(&store, &mut wtxn, &a)?;

        assert!(store.hnsw_neighbors.get(&wtxn, a.as_bytes())?.is_none());
        assert_eq!(load_neighbors(&store, &wtxn, &b)?, Vec::<EntityId>::new());
        assert_eq!(load_neighbors(&store, &wtxn, &c)?, Vec::<EntityId>::new());
        assert_eq!(read_count(&store, &wtxn)?, 2);
        assert_eq!(
            read_entry_point(&store, &wtxn)?.expect("replacement entry point"),
            b
        );
        Ok(())
    }

    #[test]
    fn hnsw_deindex_non_entry_preserves_entry_point() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
        write_neighbors(&store, &mut wtxn, &b, &[a, c])?;
        write_neighbors(&store, &mut wtxn, &c, &[a, b])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

        hnsw_deindex(&store, &mut wtxn, &c)?;

        assert!(store.hnsw_neighbors.get(&wtxn, c.as_bytes())?.is_none());
        assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![b]);
        assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
        assert_eq!(read_count(&store, &wtxn)?, 2);
        assert_eq!(read_entry_point(&store, &wtxn)?.expect("entry point"), a);
        Ok(())
    }

    #[test]
    fn hnsw_insert_existing_node_updates_neighbors_and_count() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        put_vector_raw(&store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &b, &[0.8, 0.6, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;

        write_neighbors(&store, &mut wtxn, &a, &[b])?;
        write_neighbors(&store, &mut wtxn, &b, &[a, c])?;
        write_neighbors(&store, &mut wtxn, &c, &[b])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, b.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

        put_vector_raw(&store, &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;
        hnsw_insert(&store, &test_config(), &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;

        assert_eq!(read_count(&store, &wtxn)?, 3);
        assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![c]);
        assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
        assert_eq!(load_neighbors(&store, &wtxn, &c)?, vec![a]);
        Ok(())
    }

    #[test]
    fn hnsw_refresh_prunes_stale_neighbors_without_new_ids() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        put_vector_raw(&store, &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;

        write_neighbors(&store, &mut wtxn, &a, &[b, c])?;
        write_neighbors(&store, &mut wtxn, &b, &[a])?;
        write_neighbors(&store, &mut wtxn, &c, &[a])?;
        store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, b.as_bytes())?;
        store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;

        hnsw_insert(&store, &test_config(), &mut wtxn, &a, &[0.0, 1.0, 0.0, 0.0])?;

        assert_eq!(load_neighbors(&store, &wtxn, &a)?, vec![c]);
        assert_eq!(load_neighbors(&store, &wtxn, &b)?, vec![a]);
        assert_eq!(load_neighbors(&store, &wtxn, &c)?, vec![a]);
        assert_eq!(
            read_entry_point(&store, &wtxn)?.expect("rebuilt entry point"),
            b
        );
        Ok(())
    }

    #[test]
    fn put_vector_refresh_preserves_search_connectivity() -> Result<()> {
        let temp_dir = tempdir()?;
        let mut config = test_config();
        config.hnsw.m_max_0 = 2;
        let vault = Vault::open(temp_dir.path(), config)?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        for id in [a, b, c] {
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        }

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[0.8, 0.2, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;
        write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
        write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, c.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
        wtxn.commit()?;

        let query = [1.0_f32, 0.0, 0.0, 0.0];
        let before = vault.search_vector(&query, 3)?;
        assert!(
            before.iter().any(|entry| entry.id == b),
            "expected B to be reachable before refresh, got {before:?}"
        );

        vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

        let after = vault.search_vector(&query, 3)?;
        assert!(
            after.iter().any(|entry| entry.id == b),
            "expected B to remain reachable after refresh, got {after:?}"
        );
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            load_neighbors(&vault.store, &rtxn, &a)?.contains(&c),
            "expected refreshed node to pick up a new outgoing link toward its new region"
        );
        Ok(())
    }

    #[test]
    fn put_vector_refresh_repairs_entry_point_reachability() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        for id in [a, b, c] {
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        }

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[0.9, 0.1, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 1.0, 0.0, 0.0])?;
        write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
        write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
        wtxn.commit()?;

        vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            read_entry_point(&vault.store, &rtxn)?.expect("reachable entry point"),
            b
        );
        assert_eq!(load_neighbors(&vault.store, &rtxn, &a)?, vec![c]);
        assert!(
            load_neighbors(&vault.store, &rtxn, &b)?.contains(&a),
            "expected the rebuilt graph to stay searchable from the refreshed entry region"
        );
        drop(rtxn);

        let results = vault.search_vector(&[1.0, 0.0, 0.0, 0.0], 3)?;
        assert!(
            results.iter().any(|entry| entry.id == b),
            "expected old-region node to remain reachable after entry-point refresh, got {results:?}"
        );
        Ok(())
    }

    #[test]
    fn put_vector_refresh_rewrites_stale_incoming_only_links() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        for id in [a, b, c] {
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
        }

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &c, &[1.0, 0.0, 0.0, 0.0])?;
        write_neighbors(&vault.store, &mut wtxn, &a, &[c])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
        write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
        wtxn.commit()?;

        vault.put_vector(&a, &[0.0, 1.0, 0.0, 0.0])?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(load_neighbors(&vault.store, &rtxn, &a)?, vec![b]);
        assert_eq!(load_neighbors(&vault.store, &rtxn, &b)?, vec![c]);
        assert_eq!(load_neighbors(&vault.store, &rtxn, &c)?, vec![b]);
        Ok(())
    }

    /// Each variant corrupts HNSW state in a different way then asserts the
    /// targeted API path propagates the expected `CorruptedIndex` message
    /// rather than silently returning bad neighbors or vectors.
    ///
    /// Search-side variants (use `vault.search_vector`):
    /// - `search/corrupted_neighbor_bytes`: neighbor row with a non-multiple
    ///   of `ENTITY_ID_LEN` payload.
    /// - `search/corrupted_vector_bytes`: vector row truncated to 3 bytes.
    /// - `search/corrupted_entry_point_bytes`: `ENTRY_POINT_KEY` rewritten
    ///   to 3 bytes instead of `ENTITY_ID_LEN`.
    /// - `search/missing_entry_point_when_count_is_nonzero`:
    ///   `ENTRY_POINT_KEY` deleted while count > 0.
    /// - `search/missing_entry_point_vector_when_count_is_nonzero`: vector
    ///   row for the entry point deleted.
    /// - `search/non_empty_graph_when_count_is_zero`: count forced to 0 while
    ///   the graph still has nodes.
    ///
    /// Insert-side variants (call `hnsw_insert` directly):
    /// - `insert/corrupted_count_bytes`: `COUNT_KEY` rewritten to 3 bytes.
    /// - `insert/non_empty_graph_when_count_is_zero`: graph already has
    ///   neighbors/entry-point but `COUNT_KEY` is missing (read as 0).
    /// - `insert/missing_entry_point_vector`: entry point row present but
    ///   its vector row is missing.
    ///
    /// Version-side variant:
    /// - `read_vector_version/corrupted_bytes`: `VECTOR_VERSION_KEY`
    ///   rewritten to 3 bytes.
    #[test]
    fn hnsw_corruption_variants_fail_closed() -> Result<()> {
        // Each variant runs in its own temp vault/store and reports the
        // observed error and the API path's expected message.
        type Variant = fn() -> Result<(Error, &'static str)>;

        fn search_corrupted_neighbor_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_neighbors
                .put(&mut wtxn, id.as_bytes(), &[1, 2, 3])?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected corrupted neighbor list");
            Ok((err, ERR_NEIGHBOR_VALUE_BYTES))
        }

        fn search_corrupted_vector_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .vectors
                .put(&mut wtxn, id.as_bytes(), &[1, 2, 3])?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected corrupted vector bytes");
            Ok((err, ERR_VECTOR_BYTES))
        }

        fn search_corrupted_entry_point_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_meta
                .put(&mut wtxn, ENTRY_POINT_KEY, &[1, 2, 3])?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected corrupted entry point bytes");
            Ok((err, ERR_ENTRY_POINT_BYTES))
        }

        fn search_missing_entry_point_when_count_is_nonzero() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.hnsw_meta.delete(&mut wtxn, ENTRY_POINT_KEY)?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected missing entry point corruption");
            Ok((err, ERR_ENTRY_POINT_MISSING))
        }

        fn search_missing_entry_point_vector_when_count_is_nonzero() -> Result<(Error, &'static str)>
        {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.vectors.delete(&mut wtxn, id.as_bytes())?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected missing entry point vector corruption");
            Ok((err, ERR_ENTRY_POINT_VECTOR_MISSING))
        }

        fn search_non_empty_graph_when_count_is_zero() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let id = EntityId::now();
            vault.put_entity(&id, 1, point(1, 1), 1, b"node")?;
            vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_meta
                .put(&mut wtxn, COUNT_KEY, &0_u64.to_le_bytes())?;
            wtxn.commit()?;

            let err = vault
                .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
                .expect_err("expected zero-count graph corruption");
            Ok((err, ERR_ZERO_COUNT_GRAPH_NOT_EMPTY))
        }

        fn insert_corrupted_count_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let store = Store::open(temp_dir.path(), &test_config())?;
            let mut wtxn = store.env.write_txn()?;
            let existing = EntityId::now();
            let new_id = EntityId::now();

            put_vector_raw(&store, &mut wtxn, &existing, &[1.0, 0.0, 0.0, 0.0])?;
            put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;
            write_neighbors(&store, &mut wtxn, &existing, &[])?;
            store
                .hnsw_meta
                .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
            store.hnsw_meta.put(&mut wtxn, COUNT_KEY, &[1, 2, 3])?;

            let err = hnsw_insert(
                &store,
                &test_config(),
                &mut wtxn,
                &new_id,
                &[0.0, 1.0, 0.0, 0.0],
            )
            .expect_err("expected corrupted count bytes");
            Ok((err, ERR_COUNT_BYTES))
        }

        fn insert_non_empty_graph_when_count_is_zero() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let store = Store::open(temp_dir.path(), &test_config())?;
            let mut wtxn = store.env.write_txn()?;
            let existing = EntityId::now();
            let new_id = EntityId::now();

            write_neighbors(&store, &mut wtxn, &existing, &[])?;
            store
                .hnsw_meta
                .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
            put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;

            let err = hnsw_insert(
                &store,
                &test_config(),
                &mut wtxn,
                &new_id,
                &[0.0, 1.0, 0.0, 0.0],
            )
            .expect_err("expected non-empty graph corruption");
            Ok((err, ERR_ZERO_COUNT_GRAPH_NOT_EMPTY))
        }

        fn insert_missing_entry_point_vector() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let store = Store::open(temp_dir.path(), &test_config())?;
            let mut wtxn = store.env.write_txn()?;
            let existing = EntityId::now();
            let new_id = EntityId::now();

            write_neighbors(&store, &mut wtxn, &existing, &[])?;
            store
                .hnsw_meta
                .put(&mut wtxn, ENTRY_POINT_KEY, existing.as_bytes())?;
            store
                .hnsw_meta
                .put(&mut wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
            put_vector_raw(&store, &mut wtxn, &new_id, &[0.0, 1.0, 0.0, 0.0])?;

            let err = hnsw_insert(
                &store,
                &test_config(),
                &mut wtxn,
                &new_id,
                &[0.0, 1.0, 0.0, 0.0],
            )
            .expect_err("expected missing entry point vector corruption");
            Ok((err, ERR_ENTRY_POINT_VECTOR_MISSING))
        }

        fn read_vector_version_corrupted_bytes() -> Result<(Error, &'static str)> {
            let temp_dir = tempdir()?;
            let store = Store::open(temp_dir.path(), &test_config())?;
            let mut wtxn = store.env.write_txn()?;
            store
                .hnsw_meta
                .put(&mut wtxn, VECTOR_VERSION_KEY, &[1, 2, 3])?;

            let err =
                read_vector_version(&store, &wtxn).expect_err("expected corrupted version bytes");
            Ok((err, ERR_VECTOR_VERSION_BYTES))
        }

        let variants: Vec<(&str, Variant)> = vec![
            (
                "search/corrupted_neighbor_bytes",
                search_corrupted_neighbor_bytes,
            ),
            (
                "search/corrupted_vector_bytes",
                search_corrupted_vector_bytes,
            ),
            (
                "search/corrupted_entry_point_bytes",
                search_corrupted_entry_point_bytes,
            ),
            (
                "search/missing_entry_point_when_count_is_nonzero",
                search_missing_entry_point_when_count_is_nonzero,
            ),
            (
                "search/missing_entry_point_vector_when_count_is_nonzero",
                search_missing_entry_point_vector_when_count_is_nonzero,
            ),
            (
                "search/non_empty_graph_when_count_is_zero",
                search_non_empty_graph_when_count_is_zero,
            ),
            ("insert/corrupted_count_bytes", insert_corrupted_count_bytes),
            (
                "insert/non_empty_graph_when_count_is_zero",
                insert_non_empty_graph_when_count_is_zero,
            ),
            (
                "insert/missing_entry_point_vector",
                insert_missing_entry_point_vector,
            ),
            (
                "read_vector_version/corrupted_bytes",
                read_vector_version_corrupted_bytes,
            ),
        ];

        for (case_name, variant) in variants {
            let (err, expected_msg) = variant()?;
            assert!(
                matches!(&err, Error::CorruptedIndex(message) if *message == expected_msg),
                "case {case_name}: expected CorruptedIndex({expected_msg:?}), got {err:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn hnsw_insert_rejects_corrupted_neighbor_lists() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();

        vault.put_entity(&a, 1, point(1, 1), 1, b"a")?;
        vault.put_entity(&b, 1, point(1, 1), 1, b"b")?;
        vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_neighbors
            .put(&mut wtxn, a.as_bytes(), &[0; ENTITY_ID_LEN])?;
        wtxn.commit()?;

        let err = vault
            .put_vector(&b, &[0.9, 0.1, 0.0, 0.0])
            .expect_err("expected corrupted write-side neighbors to fail");
        assert_matches!(err, Error::CorruptedIndex(message) if message == ERR_NEIGHBOR_VALUE_BYTES);
        Ok(())
    }

    #[test]
    fn beam_search_strict_rejects_corrupted_neighbor_rows() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let a = EntityId::now();
        let b = EntityId::now();

        let mut wtxn = store.env.write_txn()?;
        store
            .entities
            .put(&mut wtxn, a.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0])?;
        store
            .entities
            .put(&mut wtxn, b.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0])?;
        store.vectors.put(
            &mut wtxn,
            a.as_bytes(),
            &vector_bytes(&[1.0, 0.0, 0.0, 0.0]),
        )?;
        store.vectors.put(
            &mut wtxn,
            b.as_bytes(),
            &vector_bytes(&[0.9, 0.1, 0.0, 0.0]),
        )?;
        store
            .hnsw_neighbors
            .put(&mut wtxn, a.as_bytes(), b.as_bytes())?;
        store
            .hnsw_neighbors
            .put(&mut wtxn, b.as_bytes(), &[0; ENTITY_ID_LEN])?;
        wtxn.commit()?;

        let rtxn = store.env.read_txn()?;
        let err = beam_search(
            &store,
            &rtxn,
            &[1.0, 0.0, 0.0, 0.0],
            a,
            BeamOptions {
                ef: 2,
                lenient_neighbors: false,
                check_existence: false,
            },
            &mut 0,
        )
        .expect_err("strict beam search should reject corrupted neighbors");
        assert_matches!(err, Error::CorruptedIndex(message) if message == ERR_NEIGHBOR_VALUE_BYTES);
        Ok(())
    }

    // Original 9 corruption tests folded into `hnsw_corruption_variants_fail_closed` above.

    #[test]
    fn select_best_entry_point_prefers_full_reachability() {
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();
        let neighbors = HashMap::from([(a, vec![c]), (b, vec![a]), (c, vec![a])]);

        assert_eq!(select_best_entry_point(&neighbors, Some(a)), Some(b));
        assert_eq!(reachable_from_entry(&neighbors, b).len(), neighbors.len());
    }

    #[test]
    fn select_best_entry_point_tie_breaks_by_entity_id() {
        let low = EntityId::from_bytes([0x10; ENTITY_ID_LEN]).expect("test id should be valid");
        let mid = EntityId::from_bytes([0x20; ENTITY_ID_LEN]).expect("test id should be valid");
        let high = EntityId::from_bytes([0x30; ENTITY_ID_LEN]).expect("test id should be valid");
        let neighbors = HashMap::from([
            (high, Vec::<EntityId>::new()),
            (mid, Vec::<EntityId>::new()),
            (low, Vec::<EntityId>::new()),
        ]);

        assert_eq!(reachable_from_entry(&neighbors, low).len(), 1);
        assert_eq!(reachable_from_entry(&neighbors, mid).len(), 1);
        assert_eq!(reachable_from_entry(&neighbors, high).len(), 1);
        assert!(reachable_from_entry(&neighbors, low).len() < neighbors.len());
        assert_eq!(select_best_entry_point(&neighbors, Some(high)), Some(low));
    }

    // ─── ONE-325 / ONE-324: symmetric links + localized delete/refresh ───

    /// Builds a distinct, lexicographically ordered test id: `value` (>= 1,
    /// big-endian) in the first 8 bytes, zero padding after. Ordering by
    /// `as_bytes()` equals numeric ordering of `value`.
    fn id_from_u64(value: u64) -> EntityId {
        assert!(value >= 1, "zero would collide with the reserved zero id");
        let mut bytes = [0_u8; ENTITY_ID_LEN];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        EntityId::from_bytes(bytes).expect("nonzero counter ids avoid reserved sentinels")
    }

    /// SplitMix64 — deterministic test PRNG, no external dependency.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn pseudo_vector(state: &mut u64, dim: usize) -> Vec<f32> {
        (0..dim)
            .map(|_| ((splitmix64(state) >> 40) as f32 / (1 << 24) as f32) * 2.0 - 1.0)
            .collect()
    }

    fn small_graph_config(dim: usize, m_max_0: usize, ef: usize) -> VaultConfig {
        let mut config = VaultConfig::device();
        config.dimensions = dim;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.map_size = 64 * 1024 * 1024;
        config.hnsw.m_max_0 = m_max_0;
        config.hnsw.ef_construction = ef;
        config.hnsw.ef_search = ef;
        config
    }

    /// Builds a vault with `n` deterministic vectors through the public API
    /// (so the symmetric-link path is exercised end to end). Returns the ids
    /// in insertion order.
    fn build_symmetric_vault(
        vault: &crate::Vault,
        n: u64,
        dim: usize,
        seed: u64,
    ) -> Result<Vec<EntityId>> {
        let mut state = seed;
        let mut ids = Vec::with_capacity(n as usize);
        let mut batch = vault.batch();
        for value in 1..=n {
            let id = id_from_u64(value);
            batch = batch.vector(&id, &pseudo_vector(&mut state, dim));
            ids.push(id);
        }
        batch.commit()?;
        Ok(ids)
    }

    /// Asserts the symmetric-link invariant over the entire neighbors DB:
    /// every stored link has its reverse, except the orphan-protection case
    /// where a node's single remaining link may be one-way. Every referenced
    /// neighbor must have a row (no dangling ids).
    fn assert_symmetric_links(store: &Store, txn: &RoTxn<'_>) -> Result<()> {
        for entry in store.hnsw_neighbors.iter(txn)? {
            let (key, raw) = entry?;
            let node = parse_entity_id(key, ERR_NEIGHBOR_KEY_BYTES)?;
            let list = decode_neighbors(raw, false)?;
            for neighbor in &list {
                let back_raw = store.hnsw_neighbors.get(txn, neighbor.as_bytes())?;
                let back_raw = back_raw.unwrap_or_else(|| {
                    panic!("dangling link {node:?} -> {neighbor:?}: neighbor row missing")
                });
                let back = decode_neighbors(back_raw, false)?;
                if back.contains(&node) {
                    continue;
                }
                // A one-way link is legitimate ONLY when the orphan-protection
                // exception is tracked: `node` must be recorded as a holder
                // under target `neighbor`. An UNTRACKED one-way link is exactly
                // the stale-delete hazard ONE-325 forbids — deleting `neighbor`
                // derives its backlinks from its own forward list, never sees
                // `node`, and would strand the deleted id in `node`'s row. The
                // pre-fix `|| list.len() == 1` clause blessed precisely that
                // hole; require the exception record instead.
                let holders = read_one_way_exception_holders(store, txn, neighbor)?;
                assert!(
                    holders.contains(&node),
                    "untracked one-way link {node:?} -> {neighbor:?} (own degree {}): \
                     no exception record under {neighbor:?}; a delete of {neighbor:?} \
                     would orphan this backlink",
                    list.len()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn fresh_vault_sets_symmetric_marker_and_keeps_links_symmetric() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), small_graph_config(8, 2, 16))?;
        build_symmetric_vault(&vault, 24, 8, 7)?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault.store.hnsw_meta.get(&rtxn, SYMMETRIC_LINKS_KEY)?,
            Some([SYMMETRIC_LINKS_ENABLED].as_slice()),
            "fresh graphs must carry the symmetric-links marker"
        );
        assert_symmetric_links(&vault.store, &rtxn)?;
        assert_eq!(read_count(&vault.store, &rtxn)?, 24);
        Ok(())
    }

    /// ONE-325 regression: orphan protection keeps a victim's last link
    /// (`victim -> from`) one-way, but the symmetric delete of `from` derives
    /// its backlinks from `from`'s OWN forward list — which never contains the
    /// victim. The tracked exception record is what lets the delete still
    /// scrub `from` out of the victim's row; without it the deleted id lingers
    /// there forever, violating the active-index purge contract while queries
    /// silently tolerate the dangling id.
    #[test]
    fn delete_purges_orphan_protected_one_way_backlink() -> Result<()> {
        // m_max_0 = 1 forces every prune cascade down to the single-link case
        // that trips orphan protection.
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), small_graph_config(4, 1, 8))?;
        let from = id_from_u64(1); // deletion target
        let victim = id_from_u64(2); // keeps a one-way link `victim -> from`
        let near = id_from_u64(3); // closer to `from`, claims its single slot

        // Entity records back the vectors so the search existence check resolves
        // live nodes (graph shape is driven entirely by the vector inserts).
        for id in [from, victim, near] {
            vault.put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
        }

        vault.put_vector(&from, &[1.0, 0.0, 0.0, 0.0])?;
        vault.put_vector(&victim, &[0.8, 0.6, 0.0, 0.0])?;
        // `near` is closer to `from` than `victim` is, so inserting it prunes
        // `victim` out of `from`'s one neighbor slot; orphan protection then
        // keeps the reverse `victim -> from` one-way.
        vault.put_vector(&near, &[0.99, 0.14, 0.0, 0.0])?;

        // Pre-delete: the one-way link exists and is TRACKED.
        {
            let rtxn = vault.store.env.read_txn()?;
            assert_eq!(load_neighbors(&vault.store, &rtxn, &victim)?, vec![from]);
            assert!(
                !load_neighbors(&vault.store, &rtxn, &from)?.contains(&victim),
                "scenario invalid: `from` still points back at `victim`"
            );
            assert_eq!(
                read_one_way_exception_holders(&vault.store, &rtxn, &from)?,
                vec![victim],
                "orphan-protected one-way link must be recorded as an exception"
            );
            // The strengthened invariant accepts the link *because* it is tracked.
            assert_symmetric_links(&vault.store, &rtxn)?;
        }

        let mut wtxn = vault.store.env.write_txn()?;
        hnsw_deindex(&vault.store, &mut wtxn, &from)?;
        wtxn.commit()?;

        let rtxn = vault.store.env.read_txn()?;
        // 1. The victim's row no longer carries the deleted id.
        assert!(
            !load_neighbors(&vault.store, &rtxn, &victim)?.contains(&from),
            "deleted id left stranded in the orphan-protected victim's row"
        );
        // 2. No surviving row references the deleted node anywhere.
        for entry in vault.store.hnsw_neighbors.iter(&rtxn)? {
            let (k, raw) = entry?;
            assert!(
                !neighbor_bytes_contain(raw, &from)?,
                "stale backlink to deleted node left in row {k:?}"
            );
        }
        // 3. The exception record is cleared.
        assert!(
            read_one_way_exception_holders(&vault.store, &rtxn, &from)?.is_empty(),
            "exception record must be cleared once its target is deleted"
        );
        // 4. The graph still upholds the exception-checked invariant; count drops.
        assert_symmetric_links(&vault.store, &rtxn)?;
        assert_eq!(read_count(&vault.store, &rtxn)?, 2);
        // 5. A query at the deleted node's position never returns it and the
        //    search over the victim's region still resolves to a live node.
        let hits = hnsw_search(&vault.store, &vault.config, &rtxn, &[1.0, 0.0, 0.0, 0.0], 5)?;
        assert!(
            hits.iter().all(|hit| hit.id != from),
            "search must not return the deleted node"
        );
        assert!(!hits.is_empty(), "search must still reach a live node");
        Ok(())
    }

    #[test]
    fn symmetric_marker_corruption_fails_closed() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), small_graph_config(4, 2, 8))?;
        let a = id_from_u64(1);
        let b = id_from_u64(2);
        vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;
        vault.put_vector(&b, &[0.0, 1.0, 0.0, 0.0])?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, SYMMETRIC_LINKS_KEY, &[9])?;
        wtxn.commit()?;

        let insert_err = vault
            .put_vector(&id_from_u64(3), &[0.5, 0.5, 0.0, 0.0])
            .expect_err("insert must reject a malformed symmetric marker");
        assert_matches!(insert_err, Error::CorruptedIndex(message) if message == ERR_SYMMETRIC_MARKER_BYTES);

        let mut wtxn = vault.store.env.write_txn()?;
        let deindex_err = hnsw_deindex(&vault.store, &mut wtxn, &a)
            .expect_err("deindex must reject a malformed symmetric marker");
        assert_matches!(deindex_err, Error::CorruptedIndex(message) if message == ERR_SYMMETRIC_MARKER_BYTES);
        Ok(())
    }

    #[test]
    fn refresh_fallback_counter_corruption_fails_closed() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = Store::open(temp_dir.path(), &test_config())?;
        let mut wtxn = store.env.write_txn()?;
        store
            .hnsw_meta
            .put(&mut wtxn, REFRESH_FALLBACK_REBUILDS_KEY, &[1, 2, 3])?;

        let err = read_refresh_fallback_rebuilds(&store, &wtxn)
            .expect_err("expected corrupted fallback counter bytes");
        assert_matches!(err, Error::CorruptedIndex(message) if message == ERR_FALLBACK_COUNTER_BYTES);

        store
            .hnsw_meta
            .put(&mut wtxn, LEGACY_REBUILDS_KEY, &[4, 5])?;
        let err = read_legacy_snapshot_rebuilds(&store, &wtxn)
            .expect_err("expected corrupted legacy rebuild counter bytes");
        assert_matches!(err, Error::CorruptedIndex(message) if message == ERR_LEGACY_REBUILDS_BYTES);
        Ok(())
    }

    /// ONE-325 AC1: on a symmetric graph, deletes scrub backlinks through the
    /// node's own neighbor list and never iterate the full `hnsw_neighbors`
    /// DB. The fixture (256 nodes) is far larger than any node's
    /// neighborhood (m_max_0 = 4); a full-scan implementation costs ≥ 256
    /// probed ops and fails the literal bound. Removing the marker from the
    /// very same vault demonstrates the bound bites: the legacy scan path
    /// exceeds the node count.
    #[test]
    fn hnsw_deindex_symmetric_op_count_is_local() -> Result<()> {
        for n in [128_u64, 256] {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), small_graph_config(8, 4, 16))?;
            let ids = build_symmetric_vault(&vault, n, 8, 11)?;

            let victim = ids[(n / 2) as usize];
            let mut wtxn = vault.store.env.write_txn()?;
            let mut ops = 0_u64;
            hnsw_deindex_probed(&vault.store, &mut wtxn, &victim, &mut ops)?;
            wtxn.commit()?;

            // Measured: 10 ops at n=128, 12 ops at n=256 (deterministic
            // fixture). A full-scan implementation costs ≥ n - 1.
            eprintln!("symmetric deindex n={n}: {ops} probed ops");
            assert!(
                ops <= 32,
                "symmetric deindex on n={n} should be neighborhood-local, took {ops} ops"
            );

            let rtxn = vault.store.env.read_txn()?;
            assert_eq!(read_count(&vault.store, &rtxn)?, n - 1);
            assert!(
                vault
                    .store
                    .hnsw_neighbors
                    .get(&rtxn, victim.as_bytes())?
                    .is_none()
            );
            // No surviving row may still reference the deleted node.
            for entry in vault.store.hnsw_neighbors.iter(&rtxn)? {
                let (key, raw) = entry?;
                assert!(
                    !neighbor_bytes_contain(raw, &victim)?,
                    "stale backlink to deleted node left in row {key:?}"
                );
            }
            drop(rtxn);

            // Contrast: the same vault downgraded to legacy (marker removed)
            // pays a full scan — the op count the symmetric path must beat.
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .hnsw_meta
                .delete(&mut wtxn, SYMMETRIC_LINKS_KEY)?;
            let mut legacy_ops = 0_u64;
            let second_victim = ids[(n / 2 + 1) as usize];
            hnsw_deindex_probed(&vault.store, &mut wtxn, &second_victim, &mut legacy_ops)?;
            wtxn.commit()?;
            assert!(
                legacy_ops >= n - 1,
                "legacy deindex must visit every row (n={n}), took {legacy_ops} ops"
            );
        }
        Ok(())
    }

    /// ONE-324 AC5: refreshing an existing node is a localized update — no
    /// full iteration over `vectors` or `hnsw_neighbors`. A snapshot-rebuild
    /// implementation costs ≥ n beam searches (thousands of probed ops); the
    /// literal bound pins the localized class across two fixture sizes.
    #[test]
    fn hnsw_refresh_symmetric_op_count_is_local() -> Result<()> {
        for n in [128_u64, 256] {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), small_graph_config(8, 4, 16))?;
            let ids = build_symmetric_vault(&vault, n, 8, 13)?;

            let target = ids[(n / 2) as usize];
            let mut state = 0xDEAD_BEEF_u64 ^ n;
            let new_vector = pseudo_vector(&mut state, 8);

            let mut wtxn = vault.store.env.write_txn()?;
            let mut ops = 0_u64;
            hnsw_insert_probed(
                &vault.store,
                &vault.config,
                &mut wtxn,
                &target,
                &new_vector,
                &mut ops,
            )?;
            wtxn.commit()?;

            // Measured: 78 ops at n=128, 100 ops at n=256 (deterministic
            // fixture). A snapshot rebuild costs ≥ n row reads before it
            // even starts searching.
            eprintln!("symmetric refresh n={n}: {ops} probed ops");
            assert!(
                ops <= 300,
                "symmetric refresh on n={n} should be neighborhood-local, took {ops} ops"
            );

            let rtxn = vault.store.env.read_txn()?;
            assert_eq!(read_count(&vault.store, &rtxn)?, n);
            assert!(
                !load_neighbors(&vault.store, &rtxn, &target)?.is_empty(),
                "refreshed node must be re-linked"
            );
            assert_symmetric_links(&vault.store, &rtxn)?;
            assert_eq!(
                read_refresh_fallback_rebuilds(&vault.store, &rtxn)?,
                0,
                "localized refresh must not fall back to a rebuild"
            );
            assert_eq!(
                read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
                0,
                "symmetric refresh must never run a legacy snapshot rebuild"
            );
        }
        Ok(())
    }

    /// ONE-324 AC7: a refresh that empties an old neighbor's list re-links
    /// that neighbor (repair pass) instead of leaving it dangling.
    #[test]
    fn symmetric_refresh_repairs_orphaned_old_neighbors() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), small_graph_config(4, 1, 8))?;
        let a = id_from_u64(1);
        let b = id_from_u64(2);
        let c = id_from_u64(3);

        vault.put_vector(&a, &[1.0, 0.0, 0.0, 0.0])?;
        vault.put_vector(&b, &[0.9, 0.1, 0.0, 0.0])?;
        vault.put_vector(&c, &[0.89, 0.11, 0.0, 0.0])?;

        {
            // Sanity: with m_max_0 = 1 the API-built graph concentrates links
            // around the closest pairs; C holds B's only strong link.
            let rtxn = vault.store.env.read_txn()?;
            assert_eq!(load_neighbors(&vault.store, &rtxn, &b)?, vec![c]);
        }

        // Move B to the far side of the sphere: C's list would empty.
        vault.put_vector(&b, &[0.0, 0.0, 1.0, 0.0])?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(read_count(&vault.store, &rtxn)?, 3);
        for id in [a, b, c] {
            assert!(
                !load_neighbors(&vault.store, &rtxn, &id)?.is_empty(),
                "node {id:?} left orphaned after refresh"
            );
        }
        // Every referenced neighbor still has a row (nothing dangles).
        for entry in vault.store.hnsw_neighbors.iter(&rtxn)? {
            let (_, raw) = entry?;
            for neighbor in decode_neighbors(raw, false)? {
                assert!(
                    vault
                        .store
                        .hnsw_neighbors
                        .get(&rtxn, neighbor.as_bytes())?
                        .is_some()
                );
            }
        }
        Ok(())
    }

    /// ONE-324 AC10 machinery: the fallback rebuild is symmetric, keeps the
    /// marker, and bumps the persistent measurement counter.
    #[test]
    fn symmetric_fallback_rebuild_is_measured_and_symmetric() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), small_graph_config(8, 2, 16))?;
        build_symmetric_vault(&vault, 12, 8, 17)?;

        let mut wtxn = vault.store.env.write_txn()?;
        hnsw_symmetric_fallback_rebuild(&vault.store, &vault.config, &mut wtxn)?;
        wtxn.commit()?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(read_refresh_fallback_rebuilds(&vault.store, &rtxn)?, 1);
        assert_eq!(
            vault.store.hnsw_meta.get(&rtxn, SYMMETRIC_LINKS_KEY)?,
            Some([SYMMETRIC_LINKS_ENABLED].as_slice())
        );
        assert_eq!(read_count(&vault.store, &rtxn)?, 12);
        assert_symmetric_links(&vault.store, &rtxn)?;
        Ok(())
    }

    /// ONE-324 AC11: batched vector refreshes on a legacy (unmigrated) graph
    /// coalesce into exactly one snapshot rebuild per transaction; symmetric
    /// graphs never rebuild at all.
    #[test]
    fn batched_vector_refreshes_coalesce_rebuilds() -> Result<()> {
        // Legacy vault: hand-built asymmetric graph without the marker.
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = id_from_u64(1);
        let b = id_from_u64(2);
        let c = id_from_u64(3);

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[0.0, 1.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 0.0, 1.0, 0.0])?;
        write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a, c])?;
        write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
        wtxn.commit()?;

        vault
            .batch()
            .vector(&a, &[0.5, 0.5, 0.0, 0.0])
            .vector(&b, &[0.0, 0.5, 0.5, 0.0])
            .vector(&c, &[0.5, 0.0, 0.5, 0.0])
            .vector(&id_from_u64(4), &[0.5, 0.0, 0.0, 0.5])
            .commit()?;
        {
            let rtxn = vault.store.env.read_txn()?;
            assert_eq!(
                read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
                1,
                "a batch of legacy refreshes must trigger exactly one snapshot rebuild"
            );
            assert_eq!(read_count(&vault.store, &rtxn)?, 4);
            assert!(
                vault
                    .store
                    .hnsw_meta
                    .get(&rtxn, SYMMETRIC_LINKS_KEY)?
                    .is_none(),
                "legacy snapshot rebuild must not stamp the symmetric marker"
            );
        }

        // Symmetric vault: batched refreshes stay localized — zero rebuilds.
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), small_graph_config(4, 2, 8))?;
        build_symmetric_vault(&vault, 8, 4, 19)?;
        vault
            .batch()
            .vector(&id_from_u64(2), &[0.7, 0.1, 0.1, 0.1])
            .vector(&id_from_u64(5), &[0.1, 0.7, 0.1, 0.1])
            .vector(&id_from_u64(7), &[0.1, 0.1, 0.7, 0.1])
            .commit()?;
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
            0,
            "symmetric refreshes must not trigger snapshot rebuilds"
        );
        Ok(())
    }

    /// ONE-325 AC3: `maintain().rebuild_hnsw()` is the one-time migration —
    /// it rewrites a legacy asymmetric graph symmetrically and stamps the
    /// marker, after which refreshes take the localized path.
    #[test]
    fn maintain_rebuild_migrates_legacy_vault_to_symmetric() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = id_from_u64(1);
        let b = id_from_u64(2);
        let c = id_from_u64(3);

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[0.0, 1.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &c, &[0.0, 0.9, 0.1, 0.0])?;
        // Asymmetric on purpose: b -> a has no reverse link.
        write_neighbors(&vault.store, &mut wtxn, &a, &[c])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
        write_neighbors(&vault.store, &mut wtxn, &c, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &3_u64.to_le_bytes())?;
        wtxn.commit()?;

        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(
                vault
                    .store
                    .hnsw_meta
                    .get(&rtxn, SYMMETRIC_LINKS_KEY)?
                    .is_none()
            );
        }

        vault.maintain().rebuild_hnsw().run()?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault.store.hnsw_meta.get(&rtxn, SYMMETRIC_LINKS_KEY)?,
            Some([SYMMETRIC_LINKS_ENABLED].as_slice()),
            "maintenance rebuild must stamp the symmetric marker"
        );
        assert_eq!(read_count(&vault.store, &rtxn)?, 3);
        assert_symmetric_links(&vault.store, &rtxn)?;
        drop(rtxn);

        // Post-migration refreshes are localized: no snapshot rebuild runs.
        vault.put_vector(&b, &[0.0, 0.0, 1.0, 0.0])?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
            0,
            "post-migration refresh must stay localized"
        );
        assert_symmetric_links(&vault.store, &rtxn)?;
        Ok(())
    }

    /// Legacy vaults keep legacy semantics until migrated: a refresh on an
    /// unmarked graph runs the historical snapshot rebuild and does NOT
    /// stamp the marker.
    #[test]
    fn legacy_refresh_keeps_marker_unset() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = id_from_u64(1);
        let b = id_from_u64(2);

        let mut wtxn = vault.store.env.write_txn()?;
        put_vector_raw(&vault.store, &mut wtxn, &a, &[1.0, 0.0, 0.0, 0.0])?;
        put_vector_raw(&vault.store, &mut wtxn, &b, &[0.0, 1.0, 0.0, 0.0])?;
        write_neighbors(&vault.store, &mut wtxn, &a, &[b])?;
        write_neighbors(&vault.store, &mut wtxn, &b, &[a])?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, ENTRY_POINT_KEY, a.as_bytes())?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &2_u64.to_le_bytes())?;
        wtxn.commit()?;

        vault.put_vector(&a, &[0.0, 0.0, 1.0, 0.0])?;

        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            read_legacy_snapshot_rebuilds(&vault.store, &rtxn)?,
            1,
            "legacy refresh must run the snapshot rebuild"
        );
        assert!(
            vault
                .store
                .hnsw_meta
                .get(&rtxn, SYMMETRIC_LINKS_KEY)?
                .is_none(),
            "legacy rebuild must not stamp the symmetric marker"
        );
        Ok(())
    }

    /// The pre-SCC selector — one full directed BFS per candidate node,
    /// `O(V·(V+E))` — kept verbatim as the exhaustive reference that the
    /// linear implementation must match: maximal directed reach, ties broken
    /// by lowest entity id.
    fn reference_select_best_entry_point(
        neighbors_by_id: &HashMap<EntityId, Vec<EntityId>>,
        suggested: Option<EntityId>,
    ) -> Option<EntityId> {
        let mut best = suggested.or_else(|| neighbors_by_id.keys().copied().next())?;
        let mut best_reach = reachable_from_entry(neighbors_by_id, best).len();
        if best_reach == neighbors_by_id.len() {
            return Some(best);
        }

        for candidate in neighbors_by_id.keys().copied() {
            if candidate == best {
                continue;
            }
            let reach = reachable_from_entry(neighbors_by_id, candidate).len();
            if reach > best_reach || (reach == best_reach && candidate.as_bytes() < best.as_bytes())
            {
                best = candidate;
                best_reach = reach;
                if best_reach == neighbors_by_id.len() {
                    break;
                }
            }
        }

        Some(best)
    }

    /// Directed reach decides the entry point, not SCC size and not weak
    /// (undirected) components: a 6-node chain's head (forward closure 6)
    /// beats a 5-node cycle (the largest SCC, closure 5). The chain head is
    /// deliberately NOT the lowest id of its own component, so a
    /// "lowest id in the biggest component" implementation also fails here.
    #[test]
    fn select_best_entry_point_prefers_long_chain_over_larger_scc() {
        let cycle: Vec<EntityId> = (1..=5_u64).map(id_from_u64).collect();
        let chain_head = id_from_u64(60);
        let chain_rest: Vec<EntityId> = (10..=14_u64).map(id_from_u64).collect();

        let mut neighbors = HashMap::new();
        for (i, id) in cycle.iter().enumerate() {
            neighbors.insert(*id, vec![cycle[(i + 1) % cycle.len()]]);
        }
        neighbors.insert(chain_head, vec![chain_rest[0]]);
        for [left, right] in chain_rest.array_windows::<2>() {
            neighbors.insert(*left, vec![*right]);
        }
        neighbors.insert(
            *chain_rest.last().expect("test chain has a tail"),
            Vec::new(),
        );

        assert_eq!(
            select_best_entry_point(&neighbors, Some(cycle[0])),
            Some(chain_head)
        );
    }

    /// On closure ties the winner is the lowest entity id over ALL member
    /// nodes of the tied source SCCs — not the suggested node and not an
    /// SCC-root artifact. Two disconnected 2-cycles tie at closure 2; the
    /// 0x10 member of the {0x10, 0x40} cycle must win.
    #[test]
    fn select_best_entry_point_tie_breaks_by_lowest_member_id_across_sccs() {
        let m1 = EntityId::from_bytes([0x10; ENTITY_ID_LEN]).expect("test id should be valid");
        let m2 = EntityId::from_bytes([0x40; ENTITY_ID_LEN]).expect("test id should be valid");
        let n1 = EntityId::from_bytes([0x20; ENTITY_ID_LEN]).expect("test id should be valid");
        let n2 = EntityId::from_bytes([0x30; ENTITY_ID_LEN]).expect("test id should be valid");
        let neighbors = HashMap::from([
            (m1, vec![m2]),
            (m2, vec![m1]),
            (n1, vec![n2]),
            (n2, vec![n1]),
        ]);

        assert_eq!(select_best_entry_point(&neighbors, Some(n1)), Some(m1));
    }

    /// AC: on randomized disconnected fixtures the SCC-based entry reaches at
    /// least as many nodes as the per-candidate-BFS reference's choice. The
    /// fixtures are disconnected (>= 2 disjoint components), so no node is
    /// fully reaching, the reference is deterministic (max reach, lowest-id
    /// tie-break), and the result must match it exactly.
    #[test]
    fn select_best_entry_point_matches_exhaustive_reference_on_disconnected_fixtures() {
        for seed in 0..60_u64 {
            let mut state = seed;
            let component_count = 2 + (splitmix64(&mut state) % 4) as usize;
            let mut neighbors = HashMap::new();
            let mut all_ids = Vec::new();
            let mut next_id = 1_u64;

            for _ in 0..component_count {
                let size = 2 + (splitmix64(&mut state) % 9) as usize;
                let ids: Vec<EntityId> = (0..size)
                    .map(|_| {
                        let id = id_from_u64(next_id);
                        next_id += 1;
                        id
                    })
                    .collect();
                for (i, id) in ids.iter().enumerate() {
                    let out_degree = (splitmix64(&mut state) % 4) as usize;
                    let mut outs: Vec<EntityId> = Vec::new();
                    for _ in 0..out_degree {
                        let target = (splitmix64(&mut state) % size as u64) as usize;
                        if target != i && !outs.contains(&ids[target]) {
                            outs.push(ids[target]);
                        }
                    }
                    neighbors.insert(*id, outs);
                }
                all_ids.extend(ids);
            }

            let suggested = all_ids[(splitmix64(&mut state) as usize) % all_ids.len()];
            let expected = reference_select_best_entry_point(&neighbors, Some(suggested))
                .expect("non-empty fixture");
            let actual =
                select_best_entry_point(&neighbors, Some(suggested)).expect("non-empty fixture");

            let expected_reach = reachable_from_entry(&neighbors, expected).len();
            let actual_reach = reachable_from_entry(&neighbors, actual).len();
            assert!(
                actual_reach >= expected_reach,
                "seed {seed}: SCC entry reaches {actual_reach} < reference {expected_reach}"
            );
            assert!(
                expected_reach < neighbors.len(),
                "seed {seed}: disconnected fixture must not be fully reachable"
            );
            assert_eq!(
                actual, expected,
                "seed {seed}: deterministic (max reach, lowest id) winner must match"
            );
        }
    }

    /// AC: complexity stays `O(V+E)`-class on a multi-component fixture —
    /// verified by op-count probe. 10 disjoint 100-node chains: V = 1000,
    /// E = 990. The SCC path touches each node and edge a small constant
    /// number of times (measured ~3.6·(V+E)); budget 8·(V+E). A
    /// per-candidate full-BFS selector pays Σ reach(v) =
    /// 10 · (100·101/2) ≈ 50,500 node visits alone and cannot fit the
    /// budget.
    #[test]
    fn select_best_entry_point_op_count_is_linear_on_multi_component_fixture() {
        const CHAINS: usize = 10;
        const CHAIN_LEN: usize = 100;

        let mut neighbors = HashMap::new();
        let mut heads = Vec::new();
        let mut next_id = 1_u64;
        for _ in 0..CHAINS {
            let ids: Vec<EntityId> = (0..CHAIN_LEN)
                .map(|_| {
                    let id = id_from_u64(next_id);
                    next_id += 1;
                    id
                })
                .collect();
            heads.push(ids[0]);
            for [left, right] in ids.array_windows::<2>() {
                neighbors.insert(*left, vec![*right]);
            }
            neighbors.insert(*ids.last().expect("test chain has a tail"), Vec::new());
        }

        let v = CHAINS * CHAIN_LEN;
        let e = CHAINS * (CHAIN_LEN - 1);
        let mut ops = 0_u64;
        // Suggested is NOT the winning head: every chain head reaches
        // CHAIN_LEN nodes, ties break to the lowest id (heads[0]).
        let entry = select_best_entry_point_probed(&neighbors, Some(heads[3]), &mut ops)
            .expect("non-empty fixture");

        assert_eq!(entry, heads[0]);
        let budget = 8 * (v + e) as u64;
        assert!(
            ops <= budget,
            "ops {ops} exceeded linear budget {budget} (V={v}, E={e})"
        );
    }

    /// AC: complexity stays `O(V+E)`-class even when many source SCCs feed a
    /// SHARED reachable suffix — the shape a per-source closure walk degrades
    /// to `Θ(sources · suffix)` on. K single-node sources all point at the head
    /// of one shared K-node chain: V = 2K, E = 2K-1, and every source's forward
    /// closure is the same K+1 nodes. The reverse-topological DP computes the
    /// chain's reach once and reuses it for every source, relaxing each
    /// condensation edge a single time, so ops stay linear. The previous
    /// per-source closure walk re-traversed the whole shared chain once per
    /// source: with K=100 it spends ~2·K² ≈ 20k closure ops and blows this
    /// budget (8·(V+E) = 3192) — pre-fix the assert below fails; post-fix it
    /// passes well under budget.
    #[test]
    fn select_best_entry_point_op_count_is_linear_on_shared_suffix_fixture() {
        const K: usize = 100;
        let sources: Vec<EntityId> = (1..=K as u64).map(id_from_u64).collect();
        let chain: Vec<EntityId> = ((K as u64 + 1)..=(2 * K as u64)).map(id_from_u64).collect();

        let mut neighbors = HashMap::new();
        for source in &sources {
            neighbors.insert(*source, vec![chain[0]]);
        }
        for [left, right] in chain.array_windows::<2>() {
            neighbors.insert(*left, vec![*right]);
        }
        neighbors.insert(*chain.last().expect("test chain has a tail"), Vec::new());

        let v = 2 * K; // K sources + K chain nodes
        let e = K + (K - 1); // source->head edges + chain edges
        let mut ops = 0_u64;
        // Suggested is NOT the winner: every source reaches K+1 nodes (itself
        // plus the shared chain), so they tie and the lowest id (sources[0])
        // wins. The suggested source reaches only K+1 < 2K nodes, so the cheap
        // fully-reachable early-exit does not fire and the SCC path runs.
        let entry = select_best_entry_point_probed(&neighbors, Some(sources[3]), &mut ops)
            .expect("non-empty fixture");

        assert_eq!(entry, sources[0]);
        let budget = 8 * (v + e) as u64;
        assert!(
            ops <= budget,
            "ops {ops} exceeded linear budget {budget} (V={v}, E={e})"
        );
    }

    /// AC: fully reachable graphs keep the cheap early-exit — a single BFS,
    /// no SCC pass (which alone would at least double the op count), and the
    /// suggested entry point is kept verbatim even though it is not the
    /// lowest id.
    #[test]
    fn select_best_entry_point_keeps_suggested_on_fully_reachable_graph_with_single_bfs() {
        const N: usize = 200;
        let ids: Vec<EntityId> = (1..=N as u64).map(id_from_u64).collect();
        let mut neighbors = HashMap::new();
        for (i, id) in ids.iter().enumerate() {
            neighbors.insert(*id, vec![ids[(i + 1) % N]]);
        }
        let suggested = ids[N / 2];

        let mut ops = 0_u64;
        let entry = select_best_entry_point_probed(&neighbors, Some(suggested), &mut ops)
            .expect("non-empty fixture");

        assert_eq!(entry, suggested);
        // Single BFS budget: one op per node + one per edge, nothing else.
        let single_bfs_budget = (N + N) as u64;
        assert!(
            ops <= single_bfs_budget,
            "expected single-BFS early-exit, got {ops} ops > {single_bfs_budget}"
        );
    }
}
