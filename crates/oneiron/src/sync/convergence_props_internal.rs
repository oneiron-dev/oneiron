//! ONE-1136 (M4-14) — store-internal halves of the convergence property
//! suite. The integration suite (`tests/sync_convergence_props.rs`)
//! asserts everything reachable through the public API; the asserts here
//! need raw `Store` access (named-DB dumps, `hnsw_meta` version keys,
//! DUP_SORT posting rows), which integration tests cannot reach — so they
//! live as crate-internal unit tests. Test code only; no production
//! surface.

use std::collections::BTreeMap;
use std::sync::Arc;

use loro::ExportMode;

use crate::Vault;
use crate::batch::LONG_INTERVAL_THRESHOLD_SECS;
use crate::store::{GRAPH_VERSION_KEY, Store, VECTOR_VERSION_KEY};
use crate::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use crate::sync::queue::SyncQueue;
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window::LoadedWindow;
use crate::types::{EdgeKind, EntityId, TimeRange, Vad, VaultConfig};

/// 2026-03-15 00:00 UTC — matches `tests/sync_harness::T0`.
const T0: u64 = 1_773_532_800;
const WINDOW: &str = "2026-03";

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg
}

fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    (dir, vault)
}

fn entity_blob(entity_type: u8, occurred: TimeRange, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&occurred.start.to_be_bytes());
    blob.extend_from_slice(&occurred.end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

/// Named-DB byte dump: db name → ordered `(key, value)` rows.
type DbDump = BTreeMap<&'static str, Vec<(Vec<u8>, Vec<u8>)>>;

/// Full byte dump of every named LMDB database (DB manifest,
/// contracts.ts `dbManifest`) — the strongest possible "nothing changed"
/// comparison form. DUP_SORT duplicates (text_postings) appear as repeated
/// keys in iteration order.
fn dump_all_dbs(vault: &Vault) -> DbDump {
    let store = &vault.store;
    let rtxn = store.env.read_txn().unwrap();
    let mut out: DbDump = BTreeMap::new();

    macro_rules! dump_bytes_dbs {
        ($($name:ident),* $(,)?) => {$(
            let mut rows = Vec::new();
            for entry in store.$name.iter(&rtxn).unwrap() {
                let (k, v) = entry.unwrap();
                rows.push((k.to_vec(), v.to_vec()));
            }
            out.insert(stringify!($name), rows);
        )*};
    }
    dump_bytes_dbs!(
        entities,
        edges_out,
        edges_in,
        vectors,
        hnsw_neighbors,
        hnsw_meta,
        text_postings,
        text_meta,
        text_forward,
        text_bm25_field_stats,
        text_doc_field_lengths,
        vault_meta,
        ppr_cache,
        ppr_cache_deps,
        type_index,
        temporal_occurred_start,
        temporal_occurred_end,
        temporal_learned,
        temporal_long_intervals,
        phonetic_index,
        phonetic_forward,
        short_ids,
        short_ids_reverse,
        sync_queue,
    );

    let mut sync_state_rows = Vec::new();
    for entry in store.sync_state.iter(&rtxn).unwrap() {
        let (k, v) = entry.unwrap();
        sync_state_rows.push((k.as_bytes().to_vec(), v.to_vec()));
    }
    out.insert("sync_state", sync_state_rows);
    out
}

fn read_u64_meta(vault: &Vault, key: &[u8]) -> Option<u64> {
    let rtxn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .hnsw_meta
        .get(&rtxn, key)
        .unwrap()
        .map(|raw| u64::from_le_bytes(raw.try_into().expect("8-byte version value")))
}

/// Spec 2(c), internal half: importing the SAME update bytes twice leaves
/// the replica's LMDB byte-identical across ALL named databases, with
/// `hnsw_meta` `graph_version` / `vector_version` unchanged and no
/// duplicate DUP_SORT posting rows minted.
#[test]
fn reimport_same_update_bytes_is_byte_stable_across_all_dbs_and_versions() {
    // Author node: entity pair + semantic edge through the CRDT path.
    let (_dir_a, vault_a) = open_vault();
    let materializer_a = Arc::new(Materializer::new());
    let window_a = LoadedWindow::new("node-a", WindowKey::new(WINDOW), &vault_a, &materializer_a);
    let src = EntityId::now();
    let tgt = EntityId::now();
    let range = TimeRange {
        start: T0 + 1,
        end: T0 + 1,
    };
    {
        let entities = window_a.doc.get_map("entities");
        entities
            .insert(
                src.to_hex().as_str(),
                entity_blob(1, range, T0 + 1, b"reimport-src").as_slice(),
            )
            .unwrap();
        entities
            .insert(
                tgt.to_hex().as_str(),
                entity_blob(4, range, T0 + 1, b"reimport-tgt").as_slice(),
            )
            .unwrap();
        let edges = window_a.doc.get_map("edges");
        let edge_val =
            encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, T0 + 2, Some(Vad::NEUTRAL), None)
                .unwrap();
        edges
            .insert(
                format_edge_key(&src, EdgeKind::Mentions, &tgt).as_str(),
                edge_val.as_slice(),
            )
            .unwrap();
        window_a.doc.commit();
    }
    let update = window_a.doc.export(ExportMode::all_updates()).unwrap();

    // Replica: import once, snapshot EVERYTHING, import the same bytes
    // again, compare.
    let (_dir_b, vault_b) = open_vault();
    let materializer_b = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &vault_b, &materializer_b);
    window_b.doc.import(&update).unwrap();
    assert_eq!(
        vault_b.get(&src).unwrap().as_deref(),
        Some(b"reimport-src".as_slice()),
        "first import must materialize"
    );

    let before = dump_all_dbs(&vault_b);
    let graph_before = read_u64_meta(&vault_b, GRAPH_VERSION_KEY);
    let vector_before = read_u64_meta(&vault_b, VECTOR_VERSION_KEY);

    window_b.doc.import(&update).unwrap();

    let after = dump_all_dbs(&vault_b);
    for (db, rows_before) in &before {
        assert_eq!(
            rows_before,
            after.get(db).unwrap(),
            "db {db}: re-import of identical update bytes must be byte-stable"
        );
    }
    assert_eq!(
        read_u64_meta(&vault_b, GRAPH_VERSION_KEY),
        graph_before,
        "hnsw_meta graph_version must not change on idempotent re-import"
    );
    assert_eq!(
        read_u64_meta(&vault_b, VECTOR_VERSION_KEY),
        vector_before,
        "hnsw_meta vector_version must not change on idempotent re-import"
    );

    // DUP_SORT postings: counted explicitly so a duplicate-posting
    // regression names the failure even if the full dump assert changes.
    assert_eq!(
        before.get("text_postings").unwrap().len(),
        after.get("text_postings").unwrap().len(),
        "no duplicate text postings may be minted by re-import"
    );
}

/// Spec 2(b), internal half: after a concurrent same-entity LWW merge, the
/// LOSING node's raw index rows for its losing metadata are fully
/// displaced — temporal_occurred_start/end, temporal_learned,
/// temporal_long_intervals, and type_index hold winner-shaped rows only
/// (no orphans keyed by the loser's timestamps).
#[test]
fn lww_loser_temporal_and_type_rows_fully_displaced_no_orphans() {
    let (_dir_l, vault_loser) = open_vault();
    let materializer = Arc::new(Materializer::new());
    let window_l = LoadedWindow::new(
        "node-loser",
        WindowKey::new(WINDOW),
        &vault_loser,
        &materializer,
    );
    window_l.doc.set_peer_id(1).unwrap();

    let id = EntityId::now();
    // Loser payload: LONG occurred interval (> 14 d threshold) so a
    // temporal_long_intervals row exists to displace.
    let loser_learned = T0 + 100;
    let loser_occurred = TimeRange {
        start: T0,
        end: T0 + 20 * 86_400 + LONG_INTERVAL_THRESHOLD_SECS,
    };
    let loser_blob = entity_blob(1, loser_occurred, loser_learned, b"loser-payload");
    {
        let entities = window_l.doc.get_map("entities");
        entities
            .insert(id.to_hex().as_str(), loser_blob.as_slice())
            .unwrap();
        window_l.doc.commit();
    }

    // Pre-merge: loser rows exist.
    {
        let rtxn = vault_loser.store.env.read_txn().unwrap();
        for (db, ts) in [
            (
                &vault_loser.store.temporal_occurred_start,
                loser_occurred.start,
            ),
            (&vault_loser.store.temporal_occurred_end, loser_occurred.end),
            (&vault_loser.store.temporal_learned, loser_learned),
            (
                &vault_loser.store.temporal_long_intervals,
                loser_occurred.end,
            ),
        ] {
            assert!(
                db.get(&rtxn, &Store::encode_temporal_key(ts, &id))
                    .unwrap()
                    .is_some(),
                "precondition: loser temporal row at ts={ts} must exist"
            );
        }
    }

    // Winner doc: higher lamport (an extra prior commit) makes its write
    // the deterministic LWW winner; point event, different learned_at.
    let winner_doc = create_window_doc("node-winner", &WindowKey::new(WINDOW));
    winner_doc.set_peer_id(2).unwrap();
    let warmup = EntityId::now();
    let winner_learned = T0 + 200;
    let winner_blob = entity_blob(
        1,
        TimeRange {
            start: winner_learned,
            end: winner_learned,
        },
        winner_learned,
        b"winner-payload",
    );
    {
        let entities = winner_doc.get_map("entities");
        entities
            .insert(
                warmup.to_hex().as_str(),
                entity_blob(1, TimeRange { start: T0, end: T0 }, T0, b"lamport-warmup").as_slice(),
            )
            .unwrap();
        winner_doc.commit();
        entities
            .insert(id.to_hex().as_str(), winner_blob.as_slice())
            .unwrap();
        winner_doc.commit();
    }

    // Merge into the loser node (its Observer B materializes the winner).
    let update = winner_doc.export(ExportMode::all_updates()).unwrap();
    window_l.doc.import(&update).unwrap();
    assert_eq!(
        vault_loser.get_raw(&id).unwrap(),
        Some(winner_blob),
        "winner payload must have replaced the loser's row"
    );

    let rtxn = vault_loser.store.env.read_txn().unwrap();
    // Loser-keyed rows are gone from every temporal index…
    for (db_name, db, ts) in [
        (
            "temporal_occurred_start",
            &vault_loser.store.temporal_occurred_start,
            loser_occurred.start,
        ),
        (
            "temporal_occurred_end",
            &vault_loser.store.temporal_occurred_end,
            loser_occurred.end,
        ),
        (
            "temporal_learned",
            &vault_loser.store.temporal_learned,
            loser_learned,
        ),
        (
            "temporal_long_intervals",
            &vault_loser.store.temporal_long_intervals,
            loser_occurred.end,
        ),
    ] {
        assert!(
            db.get(&rtxn, &Store::encode_temporal_key(ts, &id))
                .unwrap()
                .is_none(),
            "{db_name}: loser row at ts={ts} must be displaced (orphan)"
        );
    }
    // …the winner rows exist…
    assert!(
        vault_loser
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(winner_learned, &id))
            .unwrap()
            .is_some(),
        "winner temporal_learned row must exist"
    );
    // …and type_index holds exactly one row for the id (same immutable
    // type byte; no duplicate or orphan type rows).
    let mut type_rows = 0;
    for entry in vault_loser.store.type_index.iter(&rtxn).unwrap() {
        let (k, _) = entry.unwrap();
        if k.len() == 17 && &k[1..] == id.as_bytes() {
            type_rows += 1;
            assert_eq!(k[0], 1, "type_index row must carry the immutable type byte");
        }
    }
    assert_eq!(
        type_rows, 1,
        "exactly one type_index row for the merged entity"
    );
}

/// Spec deliverable 5, internal half: the reserved `x:` quarantine family
/// (M4-04 storage pin) survives the queue re-bootstrap clear byte-identical
/// — extends the pinned `h:`/`m:` preservation (ONE-1091) to `x:`. No `x:`
/// writer exists in this base yet, so the row is seeded raw; the contract
/// under test is `clear_all`'s preservation behavior, not the writer.
#[test]
fn queue_rebootstrap_clear_preserves_reserved_x_rows_byte_identical() {
    let (_dir, vault) = open_vault();
    let queue = SyncQueue::new(Arc::clone(&vault)).unwrap();

    queue.push(WINDOW, &[1, 2, 3]).unwrap();
    queue.push_embed_job(&EntityId::now(), 1).unwrap();

    let mut x_key = b"x:".to_vec();
    x_key.extend_from_slice(&7_u64.to_be_bytes());
    let x_value = b"reserved-quarantine-record".to_vec();
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &x_key, &x_value)
            .unwrap();
        wtxn.commit().unwrap();
    }

    queue.clear_all().unwrap();

    let rows = vault.sync_queue_rows_with_prefix(b"x:").unwrap();
    assert_eq!(
        rows,
        vec![(x_key, x_value)],
        "clear_all (re-bootstrap) must preserve x: rows byte-identical"
    );
    assert!(
        vault.sync_queue_rows_with_prefix(b"q:").unwrap().is_empty(),
        "q: rows must be cleared"
    );
    assert!(
        vault.sync_queue_rows_with_prefix(b"e:").unwrap().is_empty(),
        "e: rows must be cleared"
    );
}
