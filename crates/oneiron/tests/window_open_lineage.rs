//! A window opens over the rows learned in its month (WINDOW-LINEAGE-RSLOT).
//!
//! The open's reverse pass asks the source-audience verdict of each row
//! while it reads the row, its edges and its mirrors in read transactions of
//! their own. The vendored heed has no NOTLS, so the pass must not hold a
//! read transaction across those reads: a second read transaction on one
//! thread fails with MDB_BAD_RSLOT. The verdict pass reads each ask in a
//! snapshot of its own (`LineagePass::per_ask`).
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! window_open_lineage`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, HnswConfig, Vault, VaultConfig};

/// The window every row here lands in: March 2026.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;

fn config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// Opens the window over the rows `rows` (id, entity type) learned in its
/// month, and returns the ids its doc carries.
fn open_over(rows: &[(EntityId, u8)]) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), config()).unwrap());
    for (id, entity_type) in rows {
        // A TURN's body is the map its readers decode; a PERSON's is free.
        let body = if *entity_type == ENTITY_TYPE_TURN {
            rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
                .unwrap()
        } else {
            b"learned this month".to_vec()
        };
        vault
            .put_entity(
                id,
                *entity_type,
                TimeRange { start: T0, end: T0 },
                T0,
                &body,
            )
            .unwrap();
    }
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "window-open-lineage",
    ));
    let window = manager
        .open_window(&WindowKey::new(WINDOW))
        .unwrap_or_else(|error| panic!("the window does not open over its rows: {error:?}"));
    let entities = window.doc.get_map("entities");
    rows.iter()
        .map(|(id, _)| id.to_hex())
        .filter(|hex| entities.get(hex).is_some())
        .collect()
}

#[test]
fn a_window_opens_over_a_person_learned_in_its_month() {
    let person = EntityId::from_bytes([0x63; 16]).unwrap();
    assert_eq!(
        open_over(&[(person, ENTITY_TYPE_PERSON)]),
        vec![person.to_hex()],
        "the window carries the PERSON its month learned"
    );
}

#[test]
fn a_window_opens_over_several_rows_learned_in_its_month() {
    let rows = [
        (EntityId::from_bytes([0x61; 16]).unwrap(), ENTITY_TYPE_PERSON),
        (EntityId::from_bytes([0x62; 16]).unwrap(), ENTITY_TYPE_TURN),
        (EntityId::from_bytes([0x64; 16]).unwrap(), ENTITY_TYPE_PERSON),
    ];
    let carried = open_over(&rows);
    assert_eq!(
        carried.len(),
        rows.len(),
        "the window carries every row its month learned: {carried:?}"
    );
}
