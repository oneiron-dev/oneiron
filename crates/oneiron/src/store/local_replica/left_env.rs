//! Local purge of a left shared vault's dedicated environment (OF-158).
//!
//! The leave ends the shared lane for good and discards its outbox; this door
//! then empties the environment by raw walks over every database, not by the
//! delete tear or demotion. Every canonical row goes with its projections,
//! documents, windows and residence rows, of any kind and in any state. Kept
//! are the authority log and MACHINE rows, a held record, and the side rows
//! the host still talks to its home with and reopens this environment by.
//! Nothing else is written: no tombstone, deletion marker, audit row, Loro op,
//! outbox row, receipt or release row.

use std::collections::HashSet;

use heed::{RoTxn, RwTxn};

use super::KeepReason;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::overlay_db::OverlayDb;
use crate::ports::EntityStoreStaging;
use crate::registry;
use crate::side_table::{self, SideDb, SideTableDecl};
use crate::store::Store;

/// Entity kinds a leave keeps whole. Every other row goes, whatever its kind:
/// WORLD, PERSON, AGENT_DEF, grants, policy manifests, bound actors, pending
/// and uncarried rows with the rest.
const LEAVE_KEPT_KINDS: &[u8] = &[
    registry::ENTITY_TYPE_AUTHORITY_LOG,
    registry::ENTITY_TYPE_MACHINE,
];

/// Declared side families a leave keeps whole. Every other declared family
/// goes, but for the rows whose key names a kept entity.
static LEAVE_KEPT_FAMILIES: &[&SideTableDecl] = &[
    // The leave's receipt, then what the host talks to its home with: install
    // identity, authority state, control keys, slips and key custody.
    &side_table::SYNC_SHARED_LEAVE_RECEIPT,
    &side_table::AUTH_CONTROL_KEY,
    &side_table::AUTH_REVOKED_TOKEN_JTI,
    &side_table::AUTHORITY_CACHE_GENERATION,
    &side_table::AUTHLOG_FIRST_SEEN_SIDECAR,
    &side_table::AUTHLOG_INGEST_CHECK,
    &side_table::AUTHLOG_INGEST_COUNT,
    &side_table::AUTHLOG_OBSERVATION_POLICY,
    &side_table::AUTHLOG_SEQ_HWM,
    &side_table::AUTHLOG_SEQ_OBSERVATION,
    &side_table::AUTHORITY_HOST_ROOT_SLIP_CACHE,
    &side_table::AUTHORITY_MESH_MACHINE,
    &side_table::AUTHORITY_OWNER_PROJECT_SLIP_CACHE,
    &side_table::AUTHORITY_PAIRING_WRITE_FACET,
    &side_table::AUTHORITY_PAIRING_PENDING,
    &side_table::AUTHORITY_SLIP_PROOF_CLOCK,
    &side_table::AUTHORITY_SLIP_PROOF_NOT_BEFORE,
    &side_table::AUTHORITY_SLIP_REPLAY_NONCE,
    &side_table::AUTHORITY_CHECKPOINT_HEAD,
    &side_table::AUTHORITY_CHECKPOINT_ROW,
    &side_table::AUTHORITY_HANDOFF_ALARM,
    &side_table::AUTHORITY_CHECKPOINT_ATTESTATION,
    &side_table::AUTHORITY_CHECKPOINT_ATTESTED_HEAD,
    &side_table::AUTHORITY_CHECKPOINT_KEY_BINDING,
    &side_table::PEER_AUTHORITY_ENTRY,
    &side_table::IDENTITY_CLIENT_ID,
    &side_table::IDENTITY_DEVICE_PK,
    &side_table::IDENTITY_MACHINE_ID,
    &side_table::IDENTITY_PINNED_ROOT,
    &side_table::MANAGED_ACCOUNT_KEY_LEASE,
    &side_table::MANAGED_CANARY_MARKER,
    &side_table::MANAGED_DEK_MAC,
    &side_table::MANAGED_LEASE_SCOPE,
    &side_table::MANAGED_LEDGER_REV,
    &side_table::VAULT_IDENTITY_LOCAL,
    &side_table::VAULT_KEY_STATE,
    &side_table::VAULT_KEY_WRAP,
    &side_table::VAULT_KEY_ESCROW_SPOOLED,
    &side_table::RECOVERY_KIT,
    // Monotonic counters and floors, so no sequence or id is ever reused.
    &side_table::SYNC_M_U_SEQ_W,
    &side_table::SYNC_M_U_SEQ_E,
    &side_table::SYNC_RESIDENCE_SEALED_NEXT,
    &side_table::SYNC_RESIDENCE_SEALED_TAKEN,
    &side_table::SHORT_ID_COUNTER,
    &side_table::PORTS_ID_FLOOR,
    &side_table::PORTS_CLOCK_FLOOR,
    // Fences and masks already written; none is added.
    &side_table::DELETION_ROW_FENCE,
    &side_table::DELETION_HARD_DELETE_MARKER,
    &side_table::DELETION_IDENTITY_SOFT_DELETE_MARKER,
    &side_table::SYNC_HISTORY_FREE_WINDOW,
    &side_table::PROVENANCE_WITHHELD_SECRET,
    // Legal holds: definitions, targets, logs, use limits, pending erases.
    &side_table::LEGAL_HOLD_ROW,
    &side_table::LEGAL_HOLD_TARGET,
    &side_table::LEGAL_HOLD_EVENT,
    &side_table::LEGAL_HOLD_ERASE_LINK,
    &side_table::LEGAL_HOLD_USE_LIMIT,
    &side_table::LEGAL_HOLD_PENDING_ERASE,
    &side_table::LEGAL_HOLD_HOST_ROW,
    &side_table::LEGAL_HOLD_HOST_TARGET,
    &side_table::LEGAL_HOLD_HOST_EVENT,
    &side_table::LEGAL_HOLD_HOST_ERASE_LINK,
    // The body collector's queue, and the device's residence choice.
    &side_table::PROVENANCE_BODY_RELEASED,
    &side_table::SYNC_RESIDENCE_DEVICE_MODE,
    // Format pins and what a reopen reads: the store's open gates, the
    // vault's open (the LFS chunk seed and the pack map head refuse when
    // missing) and its done-markers.
    &side_table::STORAGE_SCHEMA_VERSION,
    &side_table::STORAGE_ABI_VERSION,
    &side_table::TEXT_ANALYZER_MANIFEST,
    &side_table::TEXT_BM25_FIELD_SCHEMA_HASH,
    &side_table::TEXT_INDEX_SCHEMA_VERSION,
    &side_table::SHORT_ID_GRAMMAR_VERSION,
    &side_table::STRUCTURAL_KIND_REGISTRY,
    &side_table::PACK_BYTE_MAP_LOCAL_HEAD,
    &side_table::ORIGIN_LFS_CDC_SEED,
    &side_table::GATE_DECISION_CUSTODY_ROOT,
    &side_table::VAULT_ARCHIVED_BY_RESTORE,
    &side_table::RETRIEVAL_TRACE_KEY_LOCAL,
    &side_table::RECEIPT_FAMILY_INDEX_VERSION,
    &side_table::GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE,
    &side_table::DELETION_ROW_FENCE_BACKFILLED,
    &side_table::TASK_CONSULT_PARTY_BACKFILLED,
    &side_table::ORIGIN_CAS_BACKFILL,
    &side_table::SCOPE_STAMP_SWEEP_DONE,
    &side_table::SCOPE_POLICY_SWEEP_DONE,
];

/// The gate-decision ledger and every family beside it: partitions, custody,
/// retention, claim and grant indexes. Kept whole while
/// [`keeps_gate_ledger`] holds.
static GATE_LEDGER_FAMILIES: &[&SideTableDecl] = &[
    &side_table::GATE_DECISION_LEDGER,
    &side_table::GATE_DECISION_CLAIM_CONTEXT,
    &side_table::GATE_DECISION_CUSTODY_ROOT,
    &side_table::GATE_DECISION_GRANT_REF_INDEX,
    &side_table::GATE_DECISION_PARTITION_ERASE_PENDING,
    &side_table::GATE_DECISION_PARTITION_RETAIN_UNTIL,
    &side_table::GATE_DECISION_PARTITION_RETIRE_PENDING,
    &side_table::GATE_DECISION_RETENTION_CONTEXT,
    &side_table::GATE_DECISION_CLAIM_INDEX,
    &side_table::GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE,
    &side_table::GATE_DECISION_CLAIM_REF_INDEX,
    &side_table::GATE_DECISION_CLAIM_REFS,
    &side_table::GATE_DECISION_UNAPPLIED_PREFLIGHT,
];

/// Whether the gate-decision families stay whole: while any legal hold
/// stands here. A hold may name a decision partition, and a ledger row's key
/// carries its decision id, not the claim the partition is.
fn keeps_gate_ledger(store: &Store, txn: &RoTxn<'_>) -> Result<bool> {
    crate::store::legal_hold::any_standing_in_txn(store, txn)
}

/// Most kept entities one result names; [`LeftEnvPurge::kept_total`] counts
/// them all.
#[allow(dead_code, reason = "L03's OF-158 leave calls this")]
pub(crate) const LEFT_ENV_KEPT_SAMPLE: usize = 64;

/// What one call removed and kept, in fixed counters.
#[allow(dead_code, reason = "L03's OF-158 leave calls this")]
#[derive(Debug, Default)]
pub(crate) struct LeftEnvPurge {
    /// Canonical entity rows removed.
    pub(crate) entities: usize,
    /// `edges_out` and `edges_in` rows removed.
    pub(crate) edges: usize,
    /// Type, time and short-id index rows removed.
    pub(crate) index_rows: usize,
    /// `vault_meta` rows removed.
    pub(crate) side_rows: usize,
    /// `sync_state` rows removed.
    pub(crate) sync_rows: usize,
    /// Derived and queue databases cleared whole that held rows.
    pub(crate) cleared_dbs: usize,
    /// The first [`LEFT_ENV_KEPT_SAMPLE`] kept entities, each with its reason.
    pub(crate) kept: Vec<(EntityId, KeepReason)>,
    /// Every kept entity.
    pub(crate) kept_total: usize,
    /// Side rows under no declared prefix, left in place. Counted over the
    /// rows this call walked: exact once `complete`.
    pub(crate) unknown_rows: usize,
    /// Gate-decision rows kept whole because a legal hold stands
    /// ([`GATE_LEDGER_FAMILIES`]), beyond the families always kept. Counted
    /// over the rows this call walked: exact once `complete`.
    pub(crate) held_ledger_rows: usize,
    /// `false` while the row budget ran out: call again.
    pub(crate) complete: bool,
}

impl LeftEnvPurge {
    fn keep(&mut self, id: EntityId, reason: KeepReason) {
        if self.kept.len() < LEFT_ENV_KEPT_SAMPLE {
            self.kept.push((id, reason));
        }
        self.kept_total += 1;
    }
}

/// Empties a left shared vault's dedicated environment in the caller's write
/// transaction, run on the base [`Store`] only.
///
/// Precondition: the leave has ended the shared lane for good and discarded
/// its outbox, and no observer, window manager or worker can refill this
/// environment.
///
/// Every entity row goes but the [`LEAVE_KEPT_KINDS`], a row a standing legal
/// hold names, and the pack map carrier the kept head pin names (the vault's
/// open refuses without it). A row of the type, time, short-id or side
/// databases stays when its key names a kept entity, an edge when both its
/// ends are kept, and a side row when its family is in
/// [`LEAVE_KEPT_FAMILIES`] or under no declared prefix; while any legal hold
/// stands, every gate-decision family stays whole. Text, phonetic,
/// vector, PPR, job and queue databases are cleared whole, and the HNSW graph
/// shape goes while its compatibility pins stay.
///
/// One call deletes at most `max_rows` rows across its filtered walks; the
/// whole clears run in the first call. Loop, a transaction each, until
/// `complete`: each call re-reads the kept set and walks again.
#[allow(dead_code, reason = "L03's OF-158 leave calls this")]
pub(crate) fn purge_left_shared_env_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    max_rows: usize,
) -> Result<LeftEnvPurge> {
    let mut report = LeftEnvPurge::default();
    let mut budget = Budget {
        left: max_rows,
        spent: false,
    };
    let (kept, doomed) = census(store, txn, &mut budget, &mut report)?;
    remove_entities(store, txn, &doomed, &mut report)?;
    let graph = clear_whole(store, txn, &mut report)?;
    report.index_rows = sweep_indexes(store, txn, &kept, &mut budget)?;
    for db in [&store.edges_out, &store.edges_in] {
        report.edges += sweep(db, txn, &mut budget, |key, _| !kept.holds_edge(key))?;
    }
    sweep_side_tables(store, txn, &kept, &mut budget, &mut report)?;
    if graph {
        crate::hnsw::increment_vector_version(store, txn)?;
    }
    if report.entities > 0 || report.edges > 0 {
        crate::ppr::increment_graph_version(store, txn)?;
    }
    report.complete = !budget.spent;
    Ok(report)
}

/// What one call may still delete across its filtered walks.
struct Budget {
    left: usize,
    spent: bool,
}

impl Budget {
    /// Takes one row; `false`, with the budget spent, when none is left.
    fn take(&mut self) -> bool {
        match self.left.checked_sub(1) {
            Some(left) => {
                self.left = left;
                true
            }
            None => {
                self.spent = true;
                false
            }
        }
    }
}

/// The kept entities, by their raw bytes and by their lowercase hex.
#[derive(Default)]
struct Kept {
    raw: HashSet<Vec<u8>>,
    hex: HashSet<Vec<u8>>,
}

impl Kept {
    fn insert(&mut self, id: &EntityId) {
        self.raw.insert(id.as_bytes().to_vec());
        self.hex.insert(id.to_hex().into_bytes());
    }

    /// Whether `bytes` is a kept id's 16 raw bytes.
    fn is(&self, bytes: &[u8]) -> bool {
        self.raw.contains(bytes)
    }

    /// Whether `key` carries a kept id anywhere, raw or in hex. A false match
    /// only keeps a row.
    fn named_in(&self, key: &[u8]) -> bool {
        key.windows(16).any(|window| self.raw.contains(window))
            || key.windows(32).any(|window| self.hex.contains(window))
    }

    /// Whether an edge key (`source | kind | target`) joins two kept ids. A
    /// key of another length keeps the row when it names a kept id.
    fn holds_edge(&self, key: &[u8]) -> bool {
        match (key.get(..16), key.get(17..)) {
            (Some(source), Some(target)) if key.len() == 33 => self.is(source) && self.is(target),
            _ => self.named_in(key),
        }
    }
}

/// One walk over every canonical row: the kept set, and the keys this call
/// removes. The walk runs to the end whatever the budget, so the kept set is
/// whole before any other database is filtered by it.
fn census(
    store: &Store,
    txn: &RoTxn<'_>,
    budget: &mut Budget,
    report: &mut LeftEnvPurge,
) -> Result<(Kept, Vec<Vec<u8>>)> {
    let carrier = kept_family(&side_table::PACK_BYTE_MAP_LOCAL_HEAD);
    let mut kept = Kept::default();
    let mut doomed = Vec::new();
    for row in store.entities.iter(txn)? {
        let (key, raw) = row?;
        if let Ok(bytes) = <[u8; 16]>::try_from(&*key) {
            let id = EntityId::from_bytes_unchecked(bytes);
            if let Some(reason) = keep_reason(store, txn, &id, &raw, carrier)? {
                kept.insert(&id);
                report.keep(id, reason);
                continue;
            }
        }
        if budget.take() {
            doomed.push(key.into_owned());
        }
    }
    Ok((kept, doomed))
}

fn keep_reason(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
    carrier: bool,
) -> Result<Option<KeepReason>> {
    let kind = EntityMetadataHeader::parse(raw).map(|header| header.entity_type);
    if let Some(kind) = kind.filter(|kind| LEAVE_KEPT_KINDS.contains(kind)) {
        return Ok(Some(KeepReason::Kind(kind)));
    }
    if crate::store::legal_hold::held_in_txn(store, txn, id.as_bytes())? {
        return Ok(Some(KeepReason::LegalHold));
    }
    // A guard that cannot read the pin keeps the row too: keeping is safe.
    if carrier
        && kind == Some(registry::ENTITY_TYPE_ASSET)
        && store.guard_pack_map_carrier_delete_in_txn(txn, id).is_err()
    {
        return Ok(Some(KeepReason::Guarded));
    }
    Ok(None)
}

/// Removes the census's rows with the raw primitive alone, then drops every
/// L2 summary they fed.
fn remove_entities(
    store: &Store,
    txn: &mut RwTxn<'_>,
    doomed: &[Vec<u8>],
    report: &mut LeftEnvPurge,
) -> Result<()> {
    let mut removed = Vec::with_capacity(doomed.len());
    for key in doomed {
        match <[u8; 16]>::try_from(key.as_slice()) {
            Ok(bytes) => {
                let id = EntityId::from_bytes_unchecked(bytes);
                store.port_remove_entity_row(txn, &id)?;
                removed.push(id);
            }
            Err(_) => {
                store.entities.delete(txn, key)?;
            }
        }
        report.entities += 1;
    }
    if !removed.is_empty() {
        let revision = store.env.info().last_txn_id;
        let mut cache = store
            .l2_base_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in &removed {
            cache.erase(id, revision);
        }
    }
    Ok(())
}

/// Clears the derived and queue databases whole, counting those that held
/// rows, and returns whether the vector graph held any. The graph goes
/// through the engine's own clear: vectors, neighbours, count, entry point
/// and one-way exceptions, while every canonical `hnsw_meta` key of the
/// checkpoint's storage tiers stays.
fn clear_whole(store: &Store, txn: &mut RwTxn<'_>, report: &mut LeftEnvPurge) -> Result<bool> {
    let vectors = !store.vectors.is_empty(txn)?;
    let neighbors = !store.hnsw_neighbors.is_empty(txn)?;
    if vectors || neighbors {
        crate::hnsw::clear_hnsw_graph_in_txn(store, txn)?;
        report.cleared_dbs += usize::from(vectors) + usize::from(neighbors);
    }
    for db in [
        &store.text_postings,
        &store.text_meta,
        &store.text_forward,
        &store.text_bm25_field_stats,
        &store.text_doc_field_lengths,
        &store.phonetic_index,
        &store.phonetic_forward,
        &store.ppr_cache,
        &store.ppr_cache_deps,
        &store.attempt_records,
        &store.attempt_ready,
        &store.attempt_dedupe,
        &store.sync_queue,
    ] {
        if !db.is_empty(txn)? {
            db.clear(txn)?;
            report.cleared_dbs += 1;
        }
    }
    Ok(vectors || neighbors)
}

/// The type, time and short-id indexes: a row stays when its key names a kept
/// entity; the forward short-id map names its entity in the value.
fn sweep_indexes(
    store: &Store,
    txn: &mut RwTxn<'_>,
    kept: &Kept,
    budget: &mut Budget,
) -> Result<usize> {
    let mut rows = 0;
    for db in [
        &store.type_index,
        &store.temporal_occurred_start,
        &store.temporal_occurred_end,
        &store.temporal_learned,
        &store.temporal_long_intervals,
        &store.short_ids_reverse,
    ] {
        rows += sweep(db, txn, budget, |key, _| !kept.named_in(key))?;
    }
    rows += sweep(&store.short_ids, txn, budget, |_, value| !kept.is(value))?;
    Ok(rows)
}

/// The side tables, each row by the declared family it falls under.
fn sweep_side_tables(
    store: &Store,
    txn: &mut RwTxn<'_>,
    kept: &Kept,
    budget: &mut Budget,
    report: &mut LeftEnvPurge,
) -> Result<()> {
    let ledger = keeps_gate_ledger(store, txn)?;
    let mut counts = SideCounts::default();
    let families = Families::of(SideDb::VaultMeta, ledger);
    report.side_rows = sweep(&store.vault_meta, txn, budget, |key, _| {
        families.doomed(key, kept, &mut counts)
    })?;
    let families = Families::of(SideDb::SyncState, ledger);
    report.sync_rows = sweep_sync_state(store, txn, budget, |key| {
        families.doomed(key.as_bytes(), kept, &mut counts)
    })?;
    report.unknown_rows = counts.unknown;
    report.held_ledger_rows = counts.held_ledger;
    Ok(())
}

/// Deletes the rows of `db` that `doomed` picks, up to the budget. Nothing is
/// walked once the budget is spent.
fn sweep<F>(
    db: &OverlayDb,
    txn: &mut RwTxn<'_>,
    budget: &mut Budget,
    mut doomed: F,
) -> Result<usize>
where
    F: FnMut(&[u8], &[u8]) -> bool,
{
    if budget.spent {
        return Ok(0);
    }
    let mut keys = Vec::new();
    for row in db.iter(txn)? {
        let (key, value) = row?;
        if doomed(&key[..], &value[..]) {
            if !budget.take() {
                break;
            }
            keys.push(key.into_owned());
        }
    }
    for key in &keys {
        db.delete(txn, key)?;
    }
    Ok(keys.len())
}

/// [`sweep`] over the string-keyed `sync_state`.
fn sweep_sync_state<F>(
    store: &Store,
    txn: &mut RwTxn<'_>,
    budget: &mut Budget,
    mut doomed: F,
) -> Result<usize>
where
    F: FnMut(&str) -> bool,
{
    if budget.spent {
        return Ok(0);
    }
    let mut keys = Vec::new();
    for row in store.sync_state.iter(txn)? {
        let (key, _) = row?;
        if doomed(&key[..]) {
            if !budget.take() {
                break;
            }
            keys.push(key.into_owned());
        }
    }
    for key in &keys {
        store.sync_state.delete(txn, key)?;
    }
    Ok(keys.len())
}

fn kept_family(decl: &SideTableDecl) -> bool {
    LEAVE_KEPT_FAMILIES
        .iter()
        .any(|kept| std::ptr::eq(*kept, decl))
}

/// What a leave does with one declared family's rows.
#[derive(Clone, Copy)]
enum Fate {
    /// Every row goes but those whose key names a kept entity.
    Swept,
    /// In [`LEAVE_KEPT_FAMILIES`].
    Kept,
    /// A gate-decision family a standing legal hold keeps.
    HeldLedger,
}

/// The side rows a walk left in place without a family that always stays.
#[derive(Default)]
struct SideCounts {
    unknown: usize,
    held_ledger: usize,
}

/// One side database's declared families in prefix order, each with its
/// fate.
struct Families(Vec<(&'static SideTableDecl, Fate)>);

impl Families {
    /// `ledger`: whether the gate-decision families stay whole.
    fn of(db: SideDb, ledger: bool) -> Self {
        let fate = |decl: &SideTableDecl| {
            if kept_family(decl) {
                Fate::Kept
            } else if ledger
                && GATE_LEDGER_FAMILIES
                    .iter()
                    .any(|held| std::ptr::eq(*held, decl))
            {
                Fate::HeldLedger
            } else {
                Fate::Swept
            }
        };
        let mut families: Vec<_> = side_table::declared()
            .filter(|decl| decl.db == db)
            .map(|decl| (decl, fate(decl)))
            .collect();
        families.sort_unstable_by_key(|(decl, _)| decl.prefix);
        Self(families)
    }

    /// Whether a side row goes: its family is swept and its key names no kept
    /// entity. A row under no declared prefix, or in a gate-decision family a
    /// hold keeps, stays and is counted.
    fn doomed(&self, key: &[u8], kept: &Kept, counts: &mut SideCounts) -> bool {
        match self.fate(key) {
            Some(Fate::Swept) => !kept.named_in(key),
            Some(Fate::Kept) => false,
            Some(Fate::HeldLedger) => {
                counts.held_ledger += 1;
                false
            }
            None => {
                counts.unknown += 1;
                false
            }
        }
    }

    /// The fate of the family `key` falls under; `None` under no declared
    /// prefix. Declared prefixes are disjoint within one database (the
    /// declaration list's `assert_disjoint`), so the one that holds a key is
    /// its longest match, and the greatest prefix not above the key.
    fn fate(&self, key: &[u8]) -> Option<Fate> {
        let at = self.0.partition_point(|(decl, _)| decl.prefix <= key);
        let (decl, fate) = self.0.get(at.checked_sub(1)?)?;
        key.starts_with(decl.prefix).then_some(*fate)
    }
}
