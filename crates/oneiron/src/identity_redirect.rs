//! ARCH-0055 redirect projection: the rebuildable `shell id -> head set`
//! table and the read-time canonicalization it serves (ONE-1744 / MS-02).
//!
//! CID-7 / ARCH-0035 posture: this table is a PROJECTOR OUTPUT, never a
//! source of truth. Its every row is derivable from engine-authored
//! append-only truth — the canonical `merged_into` / `split_into` shell
//! edges for every edge-ful op, plus the type-76 identity-topology event
//! ledger for the one arm the edges structurally cannot express (a
//! zero-head split leaves no edge to point at). Dropping the whole table
//! and rebuilding it from that truth is byte-identical, which is what makes
//! it droppable: [`Vault::drop_redirect_projection`] and
//! [`Vault::rebuild_redirect_projection_from_edges`] are the CID-7 doors.
//!
//! Resolution vocabulary (r1/r2, Senzing 0/1/N stable-id semantics):
//!
//! | subject | [`Vault::resolve_entity`] |
//! |---|---|
//! | live entity | `[id]` — identity |
//! | merged shell | `[survivor]` — one canonical head |
//! | split shell | the exact head set — N heads, N ids |
//! | zero-head split shell | `[]` — a deliberate retire-without-successor |
//!
//! Chains resolve transitively (a shell whose head is itself a shell keeps
//! walking) under a path-cycle guard and a depth bound, so a forged or
//! corrupted edge cycle surfaces as a typed error and never a hang.
//!
//! r6 read-time canonicalization, never rewriting: claim subjects and edges
//! stay bound to the ids they were written against, forever — that is the
//! provenance truth an unmerge has to unwind. NOTHING in this module writes
//! a claim or moves an edge; resolution happens at read time, at the
//! caller's discretion.

use std::collections::{BTreeMap, BTreeSet};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::edge::{EdgeKind, parse_strict_edge_record_key};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::identity_topology::{
    IdentityTopologyAction, IdentityTopologyOp, fold_identity_topology_log,
    identity_topology_shell_peers_for_store_in_txn, note_zero_head_split_in_txn,
    shell_edge_sources_for_store_in_txn, zero_head_split_shells_for_store_in_txn,
};
use crate::store::Store;
use crate::vault::{MAX_EDGE_QUERY_RESULTS, Vault, edge_kind_prefix};

/// `vault_meta` key prefix of the redirect projection. The full key is this
/// prefix followed by the 16-byte shell id; the value is a
/// [`REDIRECT_ROW_VERSION`]-tagged head list. Absence of a row means "live"
/// — the identity resolution — so the table stores only shells and a
/// dropped table degrades to universal identity, never to a wrong head.
///
/// This const lives with the projection rather than in `store.rs` for the
/// same reason `identity_topology::IDENTITY_TOPOLOGY_SEQ_KEY` does: the
/// family that owns the keyspace owns its key shape, and `vault_meta`
/// readers already ignore unknown prefixes.
pub(crate) const REDIRECT_TABLE_META_PREFIX: &[u8] = b"redirect:v1:";

/// Only accepted row-version byte. A row is `[version][head_id(16)]*`, so
/// the zero-head split is exactly the one-byte row — distinguishable from
/// an absent row (live entity) by presence alone.
const REDIRECT_ROW_VERSION: u8 = 1;

/// ARCH-0038 carrier-class handle for the redirect table (MS-07 / ONE-1749
/// adds it to the erase machinery's carrier list). Named here so the erase
/// ticket registers the class without re-plumbing the storage.
pub const REDIRECT_CARRIER_CLASS: &str = "redirect_table";

/// Maximum shell hops one resolution may walk. The path-cycle guard already
/// makes a cycle a typed error; this bound additionally keeps a pathological
/// (forged, or corruption-induced) chain from consuming unbounded stack.
const MAX_REDIRECT_CHAIN_DEPTH: usize = 64;

/// Encodes a head set as a redirect row. The heads are written in the
/// caller's order, which every derivation normalizes to ascending id order,
/// so the same topology always encodes to the same bytes.
fn encode_redirect_row(heads: &[EntityId]) -> Vec<u8> {
    let mut row = Vec::with_capacity(1 + heads.len() * ENTITY_ID_LEN);
    row.push(REDIRECT_ROW_VERSION);
    for head in heads {
        row.extend_from_slice(head.as_bytes());
    }
    row
}

/// Decodes a redirect row back into its head set, fail-closed on any shape
/// the encoder cannot produce.
fn decode_redirect_row(row: &[u8]) -> Result<Vec<EntityId>> {
    let [version, heads @ ..] = row else {
        return Err(Error::CorruptedIndex("identity redirect row"));
    };
    if *version != REDIRECT_ROW_VERSION || heads.len() % ENTITY_ID_LEN != 0 {
        return Err(Error::CorruptedIndex("identity redirect row"));
    }
    heads
        .chunks_exact(ENTITY_ID_LEN)
        .map(|chunk| {
            let bytes: [u8; ENTITY_ID_LEN] = chunk
                .try_into()
                .map_err(|_| Error::CorruptedIndex("identity redirect row"))?;
            EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("identity redirect row"))
        })
        .collect()
}

/// The `vault_meta` key of one shell's redirect row.
fn redirect_key(shell: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(REDIRECT_TABLE_META_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(REDIRECT_TABLE_META_PREFIX);
    key.extend_from_slice(shell.as_bytes());
    key
}

/// The redirect row `entity` MUST have, derived from engine-authored truth
/// alone: the canonical shell edges first (D11 — they are the structural
/// truth for every op that leaves one), and the type-76 ledger only for the
/// zero-head split, the single arm no edge can witness. `Ok(None)` means
/// "live" — no row.
///
/// `zero_head_shells` is the ledger-derived set, passed in so a batch
/// derivation folds the (rare, quota-bounded) event family once rather than
/// once per entity.
fn derive_redirect_row_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    entity: &EntityId,
    zero_head_shells: &BTreeSet<EntityId>,
) -> Result<Option<Vec<EntityId>>> {
    let merged =
        identity_topology_shell_peers_for_store_in_txn(store, rtxn, entity, EdgeKind::MergedInto)?;
    let split =
        identity_topology_shell_peers_for_store_in_txn(store, rtxn, entity, EdgeKind::SplitInto)?;
    // The same shape assertion `entity_lifecycle_state_in_txn` makes: an
    // entity is at most one kind of shell, and a merge has exactly one
    // survivor.
    match (merged.len(), split.is_empty()) {
        (0, true) => {}
        (1, true) => return Ok(Some(merged)),
        (0, false) => {
            let mut heads = split;
            heads.sort_unstable();
            heads.dedup();
            return Ok(Some(heads));
        }
        _ => return Err(Error::CorruptedIndex("identity redirect shell")),
    }
    // No shell edge. Only the ledger can say whether this is a live entity
    // or a zero-head split's terminal shell.
    if zero_head_shells.contains(entity) {
        return Ok(Some(Vec::new()));
    }
    Ok(None)
}

/// Writes or clears the redirect rows of exactly `touched`, inside the
/// caller's write txn — the incremental maintenance half of the projection.
///
/// Every row is recomputed by [`derive_redirect_row_in_txn`], the same
/// function [`Vault::rebuild_redirect_projection_from_edges`] uses, so
/// incremental maintenance and a full rebuild are byte-identical by
/// construction rather than by two implementations agreeing.
///
/// MUST run AFTER the caller's edge writes land in `wtxn`: the derivation
/// reads the shell edges, so running it first would project the pre-op
/// topology.
pub(crate) fn maintain_redirect_projection_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    touched: &BTreeSet<EntityId>,
    zero_head_shells: &BTreeSet<EntityId>,
) -> Result<()> {
    if touched.is_empty() {
        return Ok(());
    }
    if !zero_head_shells.is_empty() {
        note_zero_head_split_in_txn(store, wtxn)?;
    }
    let mut rows = BTreeMap::new();
    for entity in touched {
        rows.insert(
            *entity,
            derive_redirect_row_in_txn(store, &*wtxn, entity, zero_head_shells)?,
        );
    }
    for (entity, heads) in rows {
        let key = redirect_key(&entity);
        match heads {
            Some(heads) => store
                .vault_meta
                .put(wtxn, &key, &encode_redirect_row(&heads))?,
            None => {
                store.vault_meta.delete(wtxn, &key)?;
            }
        }
    }
    Ok(())
}

/// Reads one shell's row: `Ok(None)` when the entity is live (or the
/// projection has been dropped), `Ok(Some(heads))` for a shell.
fn redirect_row_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    shell: &EntityId,
) -> Result<Option<Vec<EntityId>>> {
    let Some(row) = store.vault_meta.get(rtxn, &redirect_key(shell))? else {
        return Ok(None);
    };
    decode_redirect_row(row.as_ref()).map(Some)
}

/// Walks `id` through the projection into its head set, accumulating into
/// `heads`.
///
/// TWO INDEPENDENT guards, because neither implies the other and this walk
/// recurses over data an attacker or a corrupt page can shape:
/// - `path` is the ancestor set of the CURRENT walk; re-entering it is a
///   cycle, which no door can build (the apply door refuses to shell a
///   shell) and so is corruption. This catches cycles precisely.
/// - `depth` is the recursion depth. It is NOT derivable from `path.len()`:
///   on a cycle the path set stops growing while the stack keeps growing, so
///   a `path.len()` bound is no backstop at all — losing the cycle check
///   would overflow the stack rather than error. Depth stands alone and
///   bounds a legitimately-deep (or adversarially-deep) acyclic chain.
fn resolve_into_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    depth: usize,
    path: &mut BTreeSet<EntityId>,
    heads: &mut BTreeSet<EntityId>,
) -> Result<()> {
    if depth >= MAX_REDIRECT_CHAIN_DEPTH {
        return Err(Error::CorruptedIndex("identity redirect chain depth"));
    }
    let Some(row) = redirect_row_in_txn(store, rtxn, id)? else {
        // Live: resolves to itself.
        heads.insert(*id);
        return Ok(());
    };
    if !path.insert(*id) {
        return Err(Error::CorruptedIndex("identity redirect cycle"));
    }
    for head in &row {
        resolve_into_in_txn(store, rtxn, head, depth + 1, path, heads)?;
    }
    path.remove(id);
    Ok(())
}

/// The two canonical shell edge kinds — the edge-scan witness of "which
/// shells point HERE".
///
/// A zero-head split writes neither, which is exactly right for an INBOUND
/// walk: it resolves to the EMPTY head set, so it can never point at an
/// erased head. The one arm the edges structurally cannot witness is also
/// the one arm an inbound walk has nothing to ask them about.
const SHELL_EDGE_KINDS: [EdgeKind; 2] = [EdgeKind::MergedInto, EdgeKind::SplitInto];

/// The materialized table inverted: `head -> the shells whose row names it`.
///
/// One pass over the projection, so a walk that expands many heads pays for
/// the (shell-only, therefore small) table exactly once.
fn table_inbound_shells_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, BTreeSet<EntityId>>> {
    let mut inbound: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
    for entry in store
        .vault_meta
        .prefix_iter(rtxn, REDIRECT_TABLE_META_PREFIX)?
    {
        let (key, value) = entry?;
        let shell_bytes: [u8; ENTITY_ID_LEN] = key
            .get(REDIRECT_TABLE_META_PREFIX.len()..)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::CorruptedIndex("identity redirect row"))?;
        let shell = EntityId::from_bytes(shell_bytes)
            .map_err(|_| Error::CorruptedIndex("identity redirect row"))?;
        for head in decode_redirect_row(value.as_ref())? {
            inbound.entry(head).or_default().insert(shell);
        }
    }
    Ok(inbound)
}

/// The append-only type-76 ledger inverted: `head -> the shells the fold
/// still binds to it`.
///
/// The one witness that SURVIVES a HardErase of `head`. The erase purges the
/// head's incident edges in the same transaction that empties its shells, and
/// a rebuild re-derives every row from exactly those edges — so after
/// erase + drop + rebuild the edge scan and the table inversion have BOTH
/// gone silent about precisely the shells ARCH-0055 §9 makes the census
/// responsible for. The stored events name the head themselves and an erase
/// tears none of them (only the deciding actor's stamp), so they still
/// answer.
///
/// Read through the ORDINARY fold rather than off the raw rows: a parked,
/// undone or fold-rejected op leaves its event on the ledger while shelling
/// nothing, and counting its source would report a leak that never was. The
/// fold runs over the RAW event family rather than the effective projection
/// because that projection drops an op whose participant row is missing —
/// which is exactly what erasing the head makes true.
fn ledger_inbound_shells_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, BTreeSet<EntityId>>> {
    let events = vault.identity_topology_events_in_txn(rtxn)?;
    let fold = fold_identity_topology_log(&events);
    let mut applied: BTreeMap<EntityId, &IdentityTopologyOp> = BTreeMap::new();
    for event in &events {
        if let IdentityTopologyAction::Apply(op) = &event.action {
            applied.insert(event.event_id, op);
        }
    }
    let mut inbound: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
    for (shell, event_id) in &fold.current_event {
        let Some(&op) = applied.get(event_id) else {
            continue;
        };
        match op {
            IdentityTopologyOp::Merge(merge) => {
                inbound.entry(merge.survivor).or_default().insert(*shell);
            }
            IdentityTopologyOp::Split(split) => {
                for head in &split.heads {
                    inbound.entry(*head).or_default().insert(*shell);
                }
            }
            // Neither shells an entity, so neither can be the current
            // topology writer the fold names here.
            IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => {}
        }
    }
    Ok(inbound)
}

/// Shells that point DIRECTLY at `head`, read through the CID-7 witnesses
/// and UNIONED.
///
/// - The canonical `merged_into` / `split_into` edges are engine-authored
///   truth, and the only witness left once the table has been dropped —
///   `edges_in` is keyed `[target | kind | source]`, so a reversed row for
///   `head` names the shell in its source slot.
/// - The materialized table additionally covers a row whose edge is already
///   gone, which is the shape a projector output can hold and the edges
///   cannot.
/// - `ledger_inbound` covers the shape NEITHER can hold: an erase that took
///   the edge AND the row with it. It is empty for every caller that reads
///   before a purge, where the two structural witnesses are already exact.
///
/// Either structural witness alone answers the ordinary case; the union is
/// what makes an ERASE walk fail-closed, because a shell missed here keeps a
/// readable payload of precisely what the erasure hid.
fn direct_inbound_shells_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    head: &EntityId,
    table_inbound: &BTreeMap<EntityId, BTreeSet<EntityId>>,
    ledger_inbound: &BTreeMap<EntityId, BTreeSet<EntityId>>,
    shells: &mut BTreeSet<EntityId>,
) -> Result<()> {
    for kind in SHELL_EDGE_KINDS {
        let prefix = edge_kind_prefix(head, kind);
        for (scanned, entry) in store.edges_in.prefix_iter(rtxn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("identity redirect inbound shells"));
            }
            let (key, _) = entry?;
            shells.insert(parse_strict_edge_record_key(&key)?.2);
        }
    }
    for witness in [table_inbound, ledger_inbound] {
        if let Some(witnessed) = witness.get(head) {
            shells.extend(witnessed.iter().copied());
        }
    }
    Ok(())
}

/// Every shell that resolves — directly or through a chain — to one of
/// `heads`. The inverse of [`resolve_into_in_txn`], and the walk ARCH-0055 §9
/// means by "HardErase walks redirects".
///
/// Bounded by [`MAX_REDIRECT_CHAIN_DEPTH`], the same law the forward
/// resolution carries, and cycle-safe for a stronger reason than a path
/// guard: a shell is expanded at most ONCE, so a forged cycle costs one
/// frontier step and terminates rather than erroring — an erase walk must
/// not be stoppable by planting a cycle in the data it is about to erase.
///
/// `heads` themselves are never returned; the answer is the shells around
/// them.
pub(crate) fn inbound_redirect_shells_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    heads: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    inbound_redirect_shells_with_ledger_in_txn(store, rtxn, heads, &BTreeMap::new())
}

/// [`inbound_redirect_shells_in_txn`] with the ledger witness of
/// [`ledger_inbound_shells_in_txn`] unioned into every frontier step.
///
/// Separate door rather than a widened one: the erase walk reads BEFORE the
/// purge, where the structural witnesses are exact and the ledger adds
/// nothing, so it keeps paying for neither the fold nor a cascade set derived
/// from anything but the edges it is about to tear.
fn inbound_redirect_shells_with_ledger_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    heads: &BTreeSet<EntityId>,
    ledger_inbound: &BTreeMap<EntityId, BTreeSet<EntityId>>,
) -> Result<BTreeSet<EntityId>> {
    let table_inbound = table_inbound_shells_in_txn(store, rtxn)?;
    let mut reached = heads.clone();
    let mut shells = BTreeSet::new();
    let mut frontier: Vec<EntityId> = heads.iter().copied().collect();
    for _ in 0..MAX_REDIRECT_CHAIN_DEPTH {
        if frontier.is_empty() {
            break;
        }
        let mut found = BTreeSet::new();
        for head in &frontier {
            direct_inbound_shells_in_txn(
                store,
                rtxn,
                head,
                &table_inbound,
                ledger_inbound,
                &mut found,
            )?;
        }
        frontier = Vec::new();
        for shell in found {
            if reached.insert(shell) {
                shells.insert(shell);
                frontier.push(shell);
            }
        }
    }
    Ok(shells)
}

/// Bytes of `id` still readable as content: the entity body past the fixed
/// metadata header. An absent row and a SoftErased 25 B shell both read
/// zero, which is the point — ARCH-0055 §9 asks whether anything is left to
/// read, not by which door it went.
fn readable_payload_bytes_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<usize> {
    Ok(store.entities.get(rtxn, id.as_bytes())?.map_or(0, |raw| {
        raw.len().saturating_sub(ENTITY_METADATA_HEADER_LEN)
    }))
}

impl Vault {
    /// ARCH-0055 §9 / ARCH-0038 census: how many entities a completed
    /// HardErase should have left unreadable are still holding readable
    /// payload bytes.
    ///
    /// The subjects are the hard-erased ids themselves (the permanent `dt:`
    /// markers, which outlive every row the erasure tore) plus every redirect
    /// shell that resolves to one of them — the exact set r6 rules on:
    /// "erasing a canonical head erases its redirect shells' payloads too —
    /// leaving a shell readable would leak what erasure hid".
    ///
    /// ZERO is the invariant. A non-zero answer names a leak, and names it
    /// after a projection rebuild just as well as before one, since neither
    /// the marker set nor the erased payload is a projector output: a rebuild
    /// that resurrected content would raise this count rather than hide in a
    /// table that agrees with itself.
    ///
    /// Which is why the shell half reads the type-76 ledger too, unioned into
    /// the ordinary shell walk: the completed erase this census judges has
    /// already taken both STRUCTURAL witnesses of its own cascade with it —
    /// the head's incident shell edges, and the projection rows only those
    /// edges could rebuild. A census that asked them alone would police the
    /// erased heads and be blind to their shells, reporting zero on exactly
    /// the leak §9 names.
    pub fn count_dangling_redirect_payloads(&self) -> Result<usize> {
        let rtxn = self.store.env.read_txn()?;
        let mut erased = BTreeSet::new();
        for row in self
            .store
            .sync_state
            .prefix_iter(&rtxn, crate::deletion::LOCAL_HARD_DELETE_PREFIX)?
        {
            let (key, _) = row?;
            if let Some(hex) = key.strip_prefix(crate::deletion::LOCAL_HARD_DELETE_PREFIX)
                && let Ok(id) = EntityId::from_hex(hex)
            {
                erased.insert(id);
            }
        }
        if erased.is_empty() {
            return Ok(0);
        }
        let ledger_inbound = ledger_inbound_shells_in_txn(self, &rtxn)?;
        let shells = inbound_redirect_shells_with_ledger_in_txn(
            &self.store,
            &rtxn,
            &erased,
            &ledger_inbound,
        )?;
        let mut dangling = 0;
        for id in shells.iter().chain(&erased) {
            if readable_payload_bytes_in_txn(&self.store, &rtxn, id)? > 0 {
                dangling += 1;
            }
        }
        Ok(dangling)
    }

    /// Canonical read-time resolution of an entity id through the redirect
    /// projection (r6): a live id resolves to itself, a merged shell to its
    /// surviving head, a split shell to its exact head set, and a zero-head
    /// split shell to the empty set. Chains resolve transitively.
    ///
    /// This is a READ. It never rewrites a claim subject, an edge, or the
    /// ledger — the stored id stays the id the writer stated, and callers
    /// canonicalize when they read, which is what keeps an unmerge
    /// possible.
    ///
    /// Returns [`Error::CorruptedIndex`] when the projection graph contains
    /// a cycle or an implausibly deep chain, rather than looping.
    pub fn resolve_entity(&self, id: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.resolve_entity_in_txn(&rtxn, id)
    }

    /// Transaction-composable [`Vault::resolve_entity`].
    pub(crate) fn resolve_entity_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut heads = BTreeSet::new();
        let mut path = BTreeSet::new();
        resolve_into_in_txn(&self.store, rtxn, id, 0, &mut path, &mut heads)?;
        Ok(heads.into_iter().collect())
    }

    /// CID-7 door: drops the whole materialized redirect projection. Every
    /// id resolves to itself until
    /// [`Vault::rebuild_redirect_projection_from_edges`] runs — the table is
    /// a cache, so losing it degrades resolution to the pre-topology answer
    /// and never to a wrong head.
    pub fn drop_redirect_projection(&self) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let stale: Vec<Vec<u8>> = self
                .store
                .vault_meta
                .prefix_iter(&*wtxn, REDIRECT_TABLE_META_PREFIX)?
                .map(|row| row.map(|(key, _)| key.to_vec()))
                .collect::<Result<_>>()?;
            for key in stale {
                self.store.vault_meta.delete(wtxn, &key)?;
            }
            Ok(())
        })
    }

    /// CID-7 door: rebuilds the redirect projection from engine-authored
    /// truth — the canonical `merged_into` / `split_into` edges for every
    /// edge-ful op, plus the type-76 ledger for the zero-head split arm the
    /// edges cannot witness. Byte-identical to whatever incremental
    /// maintenance produced, because both derive each row with the same
    /// function.
    ///
    /// The candidate set is every entity the event family names as a shell
    /// source; a candidate that is not (or is no longer) a shell simply
    /// loses its row, so a rebuild also repairs a stale table.
    pub fn rebuild_redirect_projection_from_edges(&self) -> Result<()> {
        self.drop_redirect_projection()?;
        self.with_write_txn(|wtxn| {
            let candidates = shell_edge_sources_for_store_in_txn(&self.store, &*wtxn)?;
            // A rebuild is an explicit maintenance door, so it pays the
            // UNGATED fold: it must find zero-head shells even on a vault
            // whose marker was never set (e.g. rebuilt from replicated
            // history).
            let zero_head_shells = zero_head_split_shells_for_store_in_txn(&self.store, &*wtxn)?;
            maintain_redirect_projection_in_txn(&self.store, wtxn, &candidates, &zero_head_shells)
        })
    }
}

#[cfg(test)]
mod tests;
