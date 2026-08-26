// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! Two-vault sync test harness (ONE-1136 / M4-14).
//!
//! Shared by the sync integration suites (each `tests/*.rs` crate that
//! declares `mod sync_harness;` compiles its own copy — hence the
//! `allow(dead_code)`: every consumer uses a subset).
//!
//! Contract anchors:
//! - ARCH-0023b (oneiron-docs generated/oneiron/sync/
//!   oneiron-arch-0023b-crdt-sync-implementation-v1.md): dual storage,
//!   observer split, the pinned startup order (steps 3 → 4 → 5), and the
//!   max-5-convergence-rounds bound [`exchange`] enforces.
//! - ARCH-0034 / contracts.ts `edgeValueLayouts`: 12/24/26 B edge values;
//!   [`assert_converged`] byte-compares edge values INCLUDING the 26 B
//!   hot-flag suffix (`value[24]` = confirmation_status, `value[25]` =
//!   actor_class).
//! - ARCH-0038 / contracts.ts `deleteReasons`: delete-wins semantics the
//!   harness must never weaken — clear/reset helpers here NEVER touch the
//!   `h:` (HardErase sweep), `m:` (monotonic counters) or `x:` (reserved
//!   quarantine, M4-04) families in `sync_queue`. The only queue reset this
//!   harness exposes is [`SyncQueue::clear_all`], whose implementation
//!   deletes `q:`/`e:` rows only.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::affect::Vad;
use oneiron::edge::EdgeActorClass;
use oneiron::registry::ENTITY_TYPE_POLICY_MANIFEST;
use oneiron::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::temporal::TimeRange;
use oneiron::{
    EdgeInfo, EdgeKind, EntityId, HnswConfig, Vault, VaultConfig,
    provenance::EdgeProvenanceClaimBody, provenance::EdgeRef, provenance::SupersessionStatus,
};

/// The harness window every suite shares: March 2026.
pub(crate) const WINDOW: &str = "2026-03";

/// 2026-03-15 00:00 UTC — squarely inside [`WINDOW`].
pub(crate) const T0: u64 = 1_773_532_800;

/// Vault config matching the historical `sync_bridge` baseline (no
/// embedding model — vector writes are rejected, which those tests rely on
/// never exercising).
pub(crate) fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// [`test_config`] with an embedding model id, for suites that write
/// vectors (`ensure_model_id_for_vector_write` requires one).
pub(crate) fn test_config_with_embedding() -> VaultConfig {
    let mut cfg = test_config();
    cfg.embedding_model = Some("test/model@v1".to_owned());
    cfg
}

pub(crate) fn clear_policy_manifests(vault: &Vault) {
    // The seeded default manifest is local engine state. Public deletion is
    // rejected, and sync mirroring skips it, so legacy sync fixtures no longer
    // remove it during setup.
    assert!(
        vault
            .count_entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("count policy manifests")
            <= 1
    );
}

/// Builds the pinned 25-byte entity envelope + body from LITERAL parts
/// (contracts.ts `entityValueEnvelope`: type u8 | occurred_start u64 BE |
/// occurred_end u64 BE | learned_at u64 BE | MessagePack body). Test INPUT —
/// expectations built from this are independent of engine encode paths.
pub(crate) fn entity_blob(
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&occurred.start.to_be_bytes());
    blob.extend_from_slice(&occurred.end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

/// Point-event variant of [`entity_blob`] (occurred == learned_at), the
/// shape the legacy `sync_bridge` helper produced.
pub(crate) fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
    entity_blob(
        entity_type,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        data,
    )
}

pub(crate) fn time_range(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

pub(crate) fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

pub(crate) fn map_insert_bytes(map: &LoroMap, key: &str, value: &[u8]) {
    map.insert(key, value).unwrap();
}

/// Canonical comparison bytes for one CRDT map slot (ONE-1152): a shape
/// tag byte + length-prefixed payload, recursive, map keys sorted. Two
/// slots encode equal iff they hold the same shape AND the same deep
/// content — a String never byte-collides with a Binary of identical
/// content (distinct tags), so cross-shape divergence is always DETECTED
/// by the parity oracle instead of silently dropped.
pub(crate) fn parity_bytes(value: &ValueOrContainer) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        ValueOrContainer::Value(v) => parity_encode_value(&mut out, v),
        // Attached container: tagged as such, then its deep value — a
        // container is never parity-equal to a plain value of the same
        // content.
        ValueOrContainer::Container(_) => {
            out.push(0x09);
            parity_encode_value(&mut out, &value.get_deep_value());
        }
    }
    out
}

fn parity_push_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}

fn parity_encode_value(out: &mut Vec<u8>, value: &LoroValue) {
    match value {
        LoroValue::Null => out.push(0x00),
        LoroValue::Bool(b) => {
            out.push(0x01);
            out.push(u8::from(*b));
        }
        LoroValue::Double(d) => {
            out.push(0x02);
            out.extend_from_slice(&d.to_bits().to_be_bytes());
        }
        LoroValue::I64(i) => {
            out.push(0x03);
            out.extend_from_slice(&i.to_be_bytes());
        }
        LoroValue::Binary(bytes) => {
            out.push(0x04);
            parity_push_len_bytes(out, bytes);
        }
        LoroValue::String(s) => {
            out.push(0x05);
            parity_push_len_bytes(out, s.as_bytes());
        }
        LoroValue::List(items) => {
            out.push(0x06);
            out.extend_from_slice(&u32::try_from(items.len()).unwrap().to_be_bytes());
            for item in items.iter() {
                parity_encode_value(out, item);
            }
        }
        LoroValue::Map(map) => {
            out.push(0x07);
            // FxHashMap iteration order is nondeterministic — sort keys so
            // the encoding is canonical across nodes.
            let ordered: BTreeMap<&String, &LoroValue> = map.iter().collect();
            out.extend_from_slice(&u32::try_from(ordered.len()).unwrap().to_be_bytes());
            for (k, v) in ordered {
                parity_push_len_bytes(out, k.as_bytes());
                parity_encode_value(out, v);
            }
        }
        LoroValue::Container(id) => {
            out.push(0x08);
            parity_push_len_bytes(out, id.to_string().as_bytes());
        }
    }
}

/// ALL entries of a CRDT map, ordered — the comparison form
/// [`assert_converged`] diffs with first-divergent-key output. Values are
/// the [`parity_bytes`] canonical encoding, NOT raw payloads: the pre-fix
/// Binary-only filter dropped string/container values from BOTH sides of
/// the comparison, turning a real divergence into a false green
/// (ONE-1152). Raw Binary payloads for decoding are [`map_get_bytes`]'s
/// attempt.
pub(crate) fn map_entries(map: &LoroMap) -> BTreeMap<String, Vec<u8>> {
    let mut entries = BTreeMap::new();
    map.for_each(|key, value| {
        entries.insert(key.to_owned(), parity_bytes(&value));
    });
    entries
}

/// True when the window's CRDT tombstones map carries ANY entry naming
/// `id` — ANY-value and case-insensitive on the hex key, mirroring the
/// bridge's fail-closed, entity-canonical `tombstone_map_contains_id`
/// gate. A gated id is contract-legitimately absent from LMDB
/// (delete-wins, never resurrect), so the ONE-1148 loud-fail probes skip
/// it.
fn tombstone_gates_materialization(window: &LoadedWindow, id: &EntityId) -> bool {
    let canon = id.to_hex();
    let mut gated = false;
    window.doc.get_map("tombstones").for_each(|key, _value| {
        if key.eq_ignore_ascii_case(&canon) {
            gated = true;
        }
    });
    gated
}

/// One vault + materializer + live windows — half of a two-vault pair.
pub(crate) struct TestNode {
    /// Loro peer id AND user id — pinned so LWW tie-breaks are
    /// deterministic per pair (higher peer wins equal-lamport conflicts).
    pub(crate) peer_id: u64,
    pub(crate) name: &'static str,
    pub(crate) vault: Arc<Vault>,
    pub(crate) materializer: Arc<Materializer>,
    /// Live windows by `YYYY-MM` key (observers attached).
    pub(crate) windows: BTreeMap<String, LoadedWindow>,
    _dir: tempfile::TempDir,
}

impl TestNode {
    pub(crate) fn new(name: &'static str, peer_id: u64) -> Self {
        Self::with_config(name, peer_id, test_config())
    }

    pub(crate) fn with_config(name: &'static str, peer_id: u64, cfg: VaultConfig) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), cfg).unwrap());
        clear_policy_manifests(&vault);
        Self {
            peer_id,
            name,
            vault,
            materializer: Arc::new(Materializer::new()),
            windows: BTreeMap::new(),
            _dir: dir,
        }
    }

    /// Opens a fresh window doc with observers attached (test/bootstrap
    /// path — recovery is [`Self::recover`]). Mirrors production's
    /// fresh-doc fallback (`WindowManager::open_window`): pending
    /// `u:w:{key}:*` rows replay onto the bare doc BEFORE observers attach
    /// — they can exist without any `d:w:` snapshot, and skipping the
    /// replay silently drops accepted sync data on re-open (ONE-1152;
    /// tombstones especially, whose LMDB purge already ran).
    pub(crate) fn open_window(&mut self, key: &str) -> &LoadedWindow {
        let window_key = WindowKey::new(key);
        let doc = oneiron::sync::schema::create_window_doc(self.name, &window_key);
        doc.set_peer_id(self.peer_id).unwrap();
        window::apply_pending_window_updates(&self.vault, &doc, &window_key).unwrap();
        let window = LoadedWindow::from_doc(doc, window_key, &self.vault, &self.materializer);
        self.windows.insert(key.to_owned(), window);
        self.window(key)
    }

    /// Drops the live window WITHOUT persisting `d:w:{key}` (crash-shaped:
    /// process exit before unload) — the pending `u:w:` rows Observer A
    /// already persisted are then the ONLY durable record of the doc's
    /// ops. Pair with [`Self::open_window`] to exercise the fresh-doc
    /// pending-update replay (ONE-1152).
    pub(crate) fn drop_window_without_persist(&mut self, key: &str) {
        self.windows.remove(key);
    }

    pub(crate) fn window(&self, key: &str) -> &LoadedWindow {
        self.windows
            .get(key)
            .unwrap_or_else(|| panic!("{}: window {key} not open", self.name))
    }

    pub(crate) fn doc(&self, key: &str) -> &LoroDoc {
        &self.window(key).doc
    }

    /// Persists the live window's state to `d:w:{key}` and closes it
    /// (observer subscriptions drop with the `LoadedWindow`). Mirrors the
    /// production `WindowManager::unload_window` persist-before-deregister
    /// order. No-op if the window is not open.
    pub(crate) fn close_window(&mut self, key: &str) {
        if let Some(window) = self.windows.remove(key) {
            window.persist_state(&self.vault).unwrap();
        }
    }

    /// ARCH-0023b crash-recovery for one window, in the PINNED order the
    /// production `WindowManager::open_window` enforces — the live window
    /// (if any) is persisted + closed first (imported remote ops live only
    /// in the doc until persisted; Observer A covers local commits only),
    /// then on the bare doc:
    ///
    /// 1. load `d:w:{key}` + pending `u:w:{key}:*` (steps 1-2), fresh doc
    ///    if nothing was persisted;
    /// 2. `pt:` pending-tombstone replay (ONE-1132: a sync-enabled boot
    ///    replays deletion intents BEFORE pending mirrors so a fresh
    ///    tombstone suppresses any pm of the same entity);
    /// 3. `pm:` replay → reverse remat → forward remat (steps 3 → 4 → 5);
    /// 4. observers re-attach LAST (step 6).
    pub(crate) fn recover(&mut self, key: &str) {
        // Persist-then-detach: recovery runs on the bare reloaded doc.
        self.close_window(key);

        let window_key = WindowKey::new(key);
        let doc = match window::load_window_from_state(&self.vault, self.name, &window_key) {
            Ok(doc) => doc,
            Err(oneiron::Error::WindowNotFound { .. }) => {
                oneiron::sync::schema::create_window_doc(self.name, &window_key)
            }
            Err(err) => panic!("{}: load window {key}: {err}", self.name),
        };
        doc.set_peer_id(self.peer_id).unwrap();

        window::replay_pending_tombstones(&self.vault, &doc, &window_key).unwrap();
        window::replay_pending_mirrors(&self.vault, &doc, &window_key).unwrap();
        window::reverse_rematerialize(&self.vault, &doc, &window_key).unwrap();
        window::forward_rematerialize(&self.vault, &doc, &self.materializer, &window_key).unwrap();

        let window = LoadedWindow::from_doc(doc, window_key, &self.vault, &self.materializer);
        self.windows.insert(key.to_owned(), window);
    }

    /// Writes an entity blob into the window doc (CRDT-first device write;
    /// Observer B materializes it into LMDB synchronously) and asserts
    /// post-commit materialization (ONE-1148, see
    /// [`Self::assert_entity_write_materialized`]).
    pub(crate) fn put_entity_in_window(&self, key: &str, id: &EntityId, blob: &[u8]) {
        let window = self.window(key);
        let entities = window.doc.get_map("entities");
        map_insert_bytes(&entities, id.to_hex().as_str(), blob);
        window.doc.commit();
        self.assert_entity_write_materialized(key, id);
    }

    /// Post-commit loud-fail probe (ONE-1148): Observer B materializes
    /// synchronously on commit but SWALLOWS env-level batch-commit
    /// failures into a `tracing::error` (the ONE-1147 surface) — an
    /// env-level Storage/Io error used to surface only much later as a
    /// confusing `assert_converged` divergence on a `None` row. The
    /// harness fails AT THE WRITE SITE instead: a helper write Observer B
    /// has no contract reason to suppress MUST be readable back from LMDB
    /// immediately after the commit. PRESENCE-only on purpose — byte
    /// parity stays [`assert_converged`]'s responsibility (LWW displacement and the
    /// ONE-1134 keep-local receipt rule legitimately leave bytes ≠ the
    /// just-written blob).
    ///
    /// Contract-legitimate suppression skipped here: tombstone-gated ids
    /// (delete-wins; ARCH-0023b "if tombstoned in CRDT → never
    /// resurrect"). NOT skipped: the `dt:` local hard-delete marker
    /// without a live-doc tombstone (crafted tombstone-removal
    /// resurrection shapes) and write-gate quarantine of the blob itself —
    /// tests modelling those write through the doc maps directly, never
    /// via this helper.
    fn assert_entity_write_materialized(&self, key: &str, id: &EntityId) {
        let window = self.window(key);
        if tombstone_gates_materialization(window, id) {
            return;
        }
        let raw = self.vault.get_raw(id).unwrap_or_else(|e| {
            panic!(
                "{}: get_raw({}) errored right after CRDT commit — \
                 env-level write failure (see ONE-1148): {e}",
                self.name,
                id.to_hex(),
            )
        });
        assert!(
            raw.is_some(),
            "{}: entity {} absent from LMDB right after CRDT commit — \
             env-level write failure (see ONE-1148): Observer B swallowed a batch-commit error",
            self.name,
            id.to_hex(),
        );
    }

    /// Edge sibling of [`Self::assert_entity_write_materialized`]
    /// (ONE-1148). Skips the bridge's contract-legitimate edge deferrals
    /// FIRST — endpoint absent from the CRDT entities map, endpoint
    /// tombstone-gated, or endpoint never materialized into LMDB (the
    /// rejected-endpoint-blob quarantine shape); in all of those the edge
    /// staying out of LMDB IS the Observer B contract ("the edge stays in
    /// the CRDT and re-materializes when its endpoints do"). Past those
    /// gates the edge MUST be readable back via `edges_out`.
    fn assert_edge_write_materialized(
        &self,
        key: &str,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
    ) {
        let window = self.window(key);
        let entities = window.doc.get_map("entities");
        for endpoint in [src, tgt] {
            if entities.get(endpoint.to_hex().as_str()).is_none()
                || tombstone_gates_materialization(window, endpoint)
            {
                return; // deferred: re-materializes with its endpoints
            }
            match self.vault.get_raw(endpoint) {
                Ok(Some(_)) => {}
                // Endpoint never materialized (rejected/quarantined
                // endpoint blob ⇒ the edge op is quarantined with it);
                // an env-level failure on the endpoint write itself
                // already failed loud at ITS write site.
                Ok(None) => return,
                Err(e) => panic!(
                    "{}: get_raw({}) errored right after CRDT commit — \
                     env-level write failure (see ONE-1148): {e}",
                    self.name,
                    endpoint.to_hex(),
                ),
            }
        }
        let edges = self.vault.edges_out(src).unwrap_or_else(|e| {
            panic!(
                "{}: edges_out({}) errored right after CRDT commit — \
                 env-level write failure (see ONE-1148): {e}",
                self.name,
                src.to_hex(),
            )
        });
        assert!(
            edges.iter().any(|e| e.kind == kind && e.target == *tgt),
            "{}: edge {} absent from LMDB right after CRDT commit — \
             env-level write failure (see ONE-1148): Observer B swallowed a batch-commit error",
            self.name,
            format_edge_key(src, kind, tgt),
        );
    }

    /// Writes an edge value into the window doc using the ARCH-0034 layout
    /// for `kind` (CRDT-first; Observer B materializes).
    #[allow(clippy::too_many_arguments)] // mirrors the pinned edge value field set
    pub(crate) fn put_edge_in_window(
        &self,
        key: &str,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        created_at: u64,
        vad: Vad,
    ) {
        let window = self.window(key);
        let edge_key = format_edge_key(src, kind, tgt);
        let edge_val =
            encode_edge_value_for_crdt(kind, weight, created_at, Some(vad), None).unwrap();
        let edges = window.doc.get_map("edges");
        map_insert_bytes(&edges, edge_key.as_str(), &edge_val);
        window.doc.commit();
        self.assert_edge_write_materialized(key, src, kind, tgt);
    }

    /// `h:{seq:8BE}` HardErase sweep rows (ARCH-0038; ONE-1091 preserved
    /// family). Read-only — the harness never mutates this family.
    pub(crate) fn sweep_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.vault.sync_queue_rows_with_prefix(b"h:").unwrap()
    }

    /// `m:` monotonic counter rows (`m:last_update_seq`,
    /// `m:last_hard_erase_sweep_seq`). Read-only.
    pub(crate) fn counter_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.vault.sync_queue_rows_with_prefix(b"m:").unwrap()
    }

    /// `x:{seq:8BE}` reserved quarantine rows (M4-04). Read-only.
    pub(crate) fn quarantine_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.vault.sync_queue_rows_with_prefix(b"x:").unwrap()
    }

    /// `q:{seq:8BE}` offline replay rows. Read-only.
    pub(crate) fn queued_update_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.vault.sync_queue_rows_with_prefix(b"q:").unwrap()
    }
}

/// A two-vault pair with [`WINDOW`] open on both: node A = peer 1, node B =
/// peer 2 (deterministic LWW tie-break: B wins equal-lamport conflicts).
pub(crate) fn vault_pair() -> (TestNode, TestNode) {
    let mut a = TestNode::new("node-a", 1);
    let mut b = TestNode::new("node-b", 2);
    a.open_window(WINDOW);
    b.open_window(WINDOW);
    (a, b)
}

/// Bidirectional delta exchange until both window docs' oplog version
/// vectors are EQUAL — bounded at 5 rounds per ARCH-0023b ("Max 5
/// convergence rounds before forcing full re-bootstrap"). Returns the
/// number of rounds used; panics (re-bootstrap territory) if the bound is
/// exceeded.
///
/// Uses raw Loro deltas (`export(ExportMode::updates(&peer_vv))` →
/// `import`) — the crate's delta helpers are `#[cfg(test)] pub(crate)` and
/// unreachable from integration tests.
pub(crate) fn exchange(a: &TestNode, b: &TestNode, key: &str) -> u32 {
    exchange_docs(a.name, a.doc(key), b.name, b.doc(key))
}

/// Doc-level form of [`exchange`], for nodes managed outside [`TestNode`]
/// (e.g. a `WindowManager`-routed live window).
pub(crate) fn exchange_docs(a_name: &str, doc_a: &LoroDoc, b_name: &str, doc_b: &LoroDoc) -> u32 {
    for round in 0..5u32 {
        let vv_a = doc_a.oplog_vv();
        let vv_b = doc_b.oplog_vv();
        if vv_a == vv_b {
            return round;
        }
        let a_to_b = doc_a.export(ExportMode::updates(&vv_b)).unwrap();
        doc_b.import(&a_to_b).unwrap();
        let b_to_a = doc_b.export(ExportMode::updates(&vv_a)).unwrap();
        doc_a.import(&b_to_a).unwrap();
    }
    assert_eq!(
        doc_a.oplog_vv(),
        doc_b.oplog_vv(),
        "{a_name} ↔ {b_name}: version vectors still diverge after 5 rounds — \
         ARCH-0023b mandates full re-bootstrap past this bound"
    );
    5
}

/// First-divergent-key diff of two ordered byte-maps.
fn assert_btree_eq(
    what: &str,
    left_name: &str,
    right_name: &str,
    left: &BTreeMap<String, Vec<u8>>,
    right: &BTreeMap<String, Vec<u8>>,
) {
    let keys: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
    for key in keys {
        match (left.get(key), right.get(key)) {
            (Some(l), Some(r)) if l == r => {}
            (l, r) => panic!(
                "{what}: first divergent key {key:?}\n  {left_name}: {l:02x?}\n  {right_name}: {r:02x?}",
            ),
        }
    }
}

/// Full convergence assertion for one window across a node pair:
///
/// - CRDT map parity (entities / edges / tombstones), byte-exact, with
///   first-divergent-key output;
/// - LMDB entity rows byte-exact via `get_raw` for every non-tombstoned
///   CRDT entity;
/// - tombstone effect parity: hard (per ARCH-0038 fail-closed decode) ⇒ no
///   row on either node; soft (`user_delete`) ⇒ each node holds either no
///   row or the 25 B shell, and shells agree byte-exactly when both exist
///   (the shell is local-history-dependent: it exists only where the body
///   was materialized before the delete arrived);
/// - edge value byte-exactness INCLUDING `value[24]`/`value[25]`
///   (re-encoded through the pinned ARCH-0034 layout from each vault's
///   decoded fields — lossless for every legal stored value);
/// - `type_index` membership parity (`entities_by_type` per type byte seen
///   on either node);
/// - `temporal_learned` membership parity (`entities_in_learned_range`
///   over the full range + per-id `get_learned_at`).
pub(crate) fn assert_converged(a: &TestNode, b: &TestNode, key: &str) {
    let doc_a = a.doc(key);
    let doc_b = b.doc(key);

    // CRDT layer parity.
    let mut tombstones: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for map_name in ["entities", "edges", "tombstones"] {
        let left = map_entries(&doc_a.get_map(map_name));
        let right = map_entries(&doc_b.get_map(map_name));
        assert_btree_eq(
            &format!("CRDT {map_name} map ({key})"),
            a.name,
            b.name,
            &left,
            &right,
        );
        if map_name == "tombstones" {
            tombstones = left;
        }
    }

    // LMDB entity parity for every live CRDT entity.
    let entities = map_entries(&doc_a.get_map("entities"));
    for hex in entities.keys() {
        let id = EntityId::from_hex(hex).unwrap();
        if tombstones.contains_key(hex) {
            continue;
        }
        let raw_a = a.vault.get_raw(&id).unwrap();
        let raw_b = b.vault.get_raw(&id).unwrap();
        assert_eq!(
            raw_a, raw_b,
            "entity {hex}: LMDB bytes diverge between {} and {}",
            a.name, b.name
        );
    }

    // Tombstone effect parity (ARCH-0038 / ONE-1133 reason-aware replay).
    for hex in tombstones.keys() {
        let id = EntityId::from_hex(hex).unwrap();
        // `tombstones` holds parity-encoded comparison bytes (ONE-1152) —
        // decode from the RAW Binary wire value instead. A PRESENT
        // non-Binary tombstone value reads as the empty slice, which
        // decodes HARD — fail closed, mirroring production's
        // `apply_tombstone_to_window_doc` read.
        let raw = map_get_bytes(&doc_a.get_map("tombstones"), hex).unwrap_or_default();
        let decoded = oneiron::deletion::decode_tombstone_value(&raw);
        let raw_a = a.vault.get_raw(&id).unwrap();
        let raw_b = b.vault.get_raw(&id).unwrap();
        if decoded.is_hard() {
            assert!(
                raw_a.is_none() && raw_b.is_none(),
                "hard-tombstoned entity {hex} still has a row ({}: {:?}, {}: {:?})",
                a.name,
                raw_a.map(|r| r.len()),
                b.name,
                raw_b.map(|r| r.len())
            );
        } else {
            for (name, raw) in [(a.name, &raw_a), (b.name, &raw_b)] {
                if let Some(raw) = raw {
                    assert_eq!(
                        raw.len(),
                        25,
                        "soft-tombstoned entity {hex} on {name} must be the 25 B shell"
                    );
                }
            }
            if let (Some(ra), Some(rb)) = (&raw_a, &raw_b) {
                assert_eq!(ra, rb, "soft shells diverge for {hex}");
            }
        }
    }

    // Edge byte-exactness incl. the 26 B hot-flag suffix.
    let live_ids: Vec<EntityId> = entities
        .keys()
        .filter(|hex| !tombstones.contains_key(*hex))
        .map(|hex| EntityId::from_hex(hex).unwrap())
        .collect();
    for id in &live_ids {
        let edges_a = edge_bytes_out(&a.vault, id);
        let edges_b = edge_bytes_out(&b.vault, id);
        assert_btree_eq(
            &format!("edges_out of {}", id.to_hex()),
            a.name,
            b.name,
            &edges_a,
            &edges_b,
        );
    }

    // type_index membership parity.
    let mut type_bytes = BTreeSet::new();
    for id in &live_ids {
        let ta = a.vault.get_entity_type(id).unwrap();
        let tb = b.vault.get_entity_type(id).unwrap();
        assert_eq!(ta, tb, "type byte diverges for {}", id.to_hex());
        if let Some(t) = ta {
            type_bytes.insert(t);
        }
    }
    for t in type_bytes {
        let mut by_type_a = a.vault.entities_by_type(t).unwrap();
        let mut by_type_b = b.vault.entities_by_type(t).unwrap();
        by_type_a.sort();
        by_type_b.sort();
        assert_eq!(
            by_type_a, by_type_b,
            "type_index membership diverges for type byte {t}"
        );
    }

    // temporal_learned membership parity.
    let mut learned_a = a.vault.entities_in_learned_range(0, u64::MAX).unwrap();
    let mut learned_b = b.vault.entities_in_learned_range(0, u64::MAX).unwrap();
    learned_a.sort();
    learned_b.sort();
    assert_eq!(
        learned_a, learned_b,
        "temporal_learned membership diverges between {} and {}",
        a.name, b.name
    );
    for id in &live_ids {
        assert_eq!(
            a.vault.get_learned_at(id).unwrap(),
            b.vault.get_learned_at(id).unwrap(),
            "learned_at diverges for {}",
            id.to_hex()
        );
    }
}

/// Outbound edges of `id` re-encoded through the pinned ARCH-0034 layout —
/// byte-comparison form (`edge key` → 12/24/26 B value). Lossless: the
/// stored value is a fixed-width function of the decoded fields.
pub(crate) fn edge_bytes_out(vault: &Vault, id: &EntityId) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for edge in vault.edges_out(id).unwrap() {
        let key = format_edge_key(id, edge.kind, &edge.target);
        let value = reencode_edge_value(&edge);
        out.insert(key, value);
    }
    out
}

pub(crate) fn reencode_edge_value(edge: &EdgeInfo) -> Vec<u8> {
    encode_edge_value_for_crdt(
        edge.kind,
        edge.weight,
        edge.created_at,
        edge.vad,
        edge.provenance,
    )
    .unwrap()
}

/// Builds an `edge.provenance` Claim body (contracts.ts
/// `edgeProvenanceClaim.fields`): required actor ref + confidence +
/// supersession status; optional refs stay absent.
pub(crate) fn edge_provenance_claim_body(
    actor: EntityId,
    confidence: f32,
    status: SupersessionStatus,
) -> EdgeProvenanceClaimBody {
    EdgeProvenanceClaimBody::new(actor, confidence, status)
}

/// Writes a PROVENANCED subject edge through the real unit (ARCH-0034
/// EDGE-PROVENANCE = C): `put_edge` + `put_edge_provenance` derive the two
/// hot flags from the truth-Claim — never hand-stamped. For
/// `confirmation_status == Retracted` the Claim goes through the REAL
/// retraction lifecycle (`retract_edge_provenance`), which re-stamps the
/// edge and KEEPS it (contracts.ts retractionRules RETRACT).
///
/// Returns the Claim id. Caller must have created `src`, `tgt`, and the
/// `actor` entity already.
#[allow(clippy::too_many_arguments)] // mirrors the pinned provenance field set
pub(crate) fn provenanced_edge(
    node: &TestNode,
    actor: &EntityId,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    weight: f32,
    confirmation_status: SupersessionStatus,
    learned_at: u64,
) -> EntityId {
    node.vault.put_edge(src, kind, tgt, weight).unwrap();
    let claim_id = EntityId::now();
    let subject = EdgeRef::new(*src, kind, *tgt);
    let initial_status = match confirmation_status {
        // Retraction is a lifecycle transition, not an authored state.
        SupersessionStatus::Retracted => SupersessionStatus::Confirmed,
        other => other,
    };
    let body = edge_provenance_claim_body(*actor, 0.75, initial_status);
    node.vault
        .put_edge_provenance(
            &claim_id,
            &subject,
            &body,
            EdgeActorClass::Human,
            learned_at,
        )
        .unwrap();
    if confirmation_status == SupersessionStatus::Retracted {
        node.vault
            .retract_edge_provenance(&claim_id, learned_at + 1)
            .unwrap();
    }
    claim_id
}

/// Hyphen-stripped lowercase hex of raw bytes.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns the hyphenated `request_id` string from a REDACTION_AUDIT
/// receipt body (25 B envelope + MessagePack body; contracts.ts
/// `redactionAuditReceipt.fields`).
pub(crate) fn receipt_request_id(vault: &Vault, receipt_id: &EntityId) -> String {
    let raw = vault.get_raw(receipt_id).unwrap().expect("receipt raw");
    let body: serde_json::Value = rmp_serde::from_slice(&raw[25..]).expect("receipt body");
    body["request_id"]
        .as_str()
        .expect("request_id string")
        .to_owned()
}

/// All REDACTION_AUDIT receipts on a vault.
pub(crate) fn redaction_audit_receipts(vault: &Vault) -> Vec<EntityId> {
    vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_REDACTION_AUDIT)
        .unwrap()
}

#[test]
fn harness_window_constants_agree() {
    assert_eq!(WindowKey::from_timestamp(T0).as_str(), WINDOW);
    let key = WindowKey::new(WINDOW);
    let start = key.start_timestamp().unwrap();
    let end = key.end_timestamp().unwrap();
    assert!(start <= T0 && T0 <= end, "T0 must sit inside {WINDOW}");
}

/// ONE-1152 (b) oracle self-test: a non-Binary CRDT map value must be
/// VISIBLE to convergence parity. Node A carries a String value in its
/// entities map that node B lacks; the pre-fix Binary-only `map_entries`
/// dropped the entry from A's side of the comparison, so this exact
/// divergence sailed through [`assert_converged`] as a false green.
/// (Direct doc-map write on purpose: Observer B quarantines the
/// protocol-violating value rather than materializing it, and the
/// harness write helpers are reserved for contract-clean writes.)
#[test]
#[should_panic(expected = "CRDT entities map")]
fn parity_oracle_detects_non_binary_map_divergence() {
    let (a, b) = vault_pair();
    let id = EntityId::now();
    let entities = a.doc(WINDOW).get_map("entities");
    entities
        .insert(id.to_hex().as_str(), "not-a-binary-blob")
        .unwrap();
    a.doc(WINDOW).commit();
    assert_converged(&a, &b, WINDOW);
}

/// ONE-1152 (c) oracle self-test: pending `u:w:{key}:*` rows (persisted by
/// Observer A on every local commit) must replay on a harness fresh open,
/// exactly like production's `WindowManager::open_window` fresh-doc
/// fallback. Pre-fix, [`TestNode::open_window`] produced a bare doc — the
/// accepted update was invisible and any test of "what survives a re-open
/// without a `d:w:` snapshot" silently diverged from production.
#[test]
fn fresh_open_replays_pending_window_updates() {
    let mut a = TestNode::new("node-a", 1);
    a.open_window(WINDOW);

    let id = EntityId::now();
    let blob = make_entity_blob(1, T0 + 1, b"pending-update-survivor");
    a.put_entity_in_window(WINDOW, &id, &blob);

    // Crash-shaped drop: no d:w: snapshot is ever written — Observer A's
    // u:w: rows are the only durable CRDT record of the op.
    a.drop_window_without_persist(WINDOW);
    a.open_window(WINDOW);

    assert_eq!(
        map_get_bytes(&a.doc(WINDOW).get_map("entities"), &id.to_hex()).as_deref(),
        Some(blob.as_slice()),
        "pending u:w: update must be visible in the freshly opened doc \
         (production fresh-doc fallback parity, ONE-1152)"
    );
}
