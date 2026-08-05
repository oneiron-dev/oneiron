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

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::identity_topology::{
    identity_topology_shell_peers_for_store_in_txn, shell_edge_sources_for_store_in_txn,
    zero_head_split_shells_for_store_in_txn,
};
use crate::store::Store;
use crate::vault::Vault;

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
    let merged = identity_topology_shell_peers_for_store_in_txn(
        store,
        rtxn,
        entity,
        crate::edge::EdgeKind::MergedInto,
    )?;
    let split = identity_topology_shell_peers_for_store_in_txn(
        store,
        rtxn,
        entity,
        crate::edge::EdgeKind::SplitInto,
    )?;
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
) -> Result<()> {
    if touched.is_empty() {
        return Ok(());
    }
    let zero_head_shells = zero_head_split_shells_for_store_in_txn(store, &*wtxn)?;
    let mut rows = BTreeMap::new();
    for entity in touched {
        rows.insert(
            *entity,
            derive_redirect_row_in_txn(store, &*wtxn, entity, &zero_head_shells)?,
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

impl Vault {
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
            maintain_redirect_projection_in_txn(&self.store, wtxn, &candidates)
        })
    }
}

#[cfg(test)]
mod tests;
