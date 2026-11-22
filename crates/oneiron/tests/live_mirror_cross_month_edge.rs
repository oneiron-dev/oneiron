//! FIX LIVE-MIRROR-CROSS-MONTH-EDGE-SOURCE-DROPPED: the write door queues an
//! edge by its source row, and an edge from a BASE row to a world's row rides
//! that world's window of the target's birth month. The live pass kept a
//! queued row only when it was learned in the window's month, so an edge from a
//! base row learned in an earlier month never reached a loaded world window (or
//! its peers) until that window was rebuilt. The live pass now takes such a
//! source's edges into the world window, never its row.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test live_mirror_cross_month_edge`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use oneiron::test_doors::live_mirror_cross_month_edge::base_edges_into_live_world_window;
use oneiron::{HnswConfig, Vault, VaultConfig};

fn config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

#[test]
fn an_earlier_base_row_edge_reaches_the_loaded_world_window() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), config()).unwrap());
    let run = base_edges_into_live_world_window(&vault, Duration::from_secs(10))
        .expect("write the rows, open the world window and commit the edges");

    assert!(
        run.target_loaded,
        "precondition: the world window holds the world's claim once it opens"
    );
    assert!(
        run.edges_absent_before_write,
        "precondition: the world window holds neither edge before the batch"
    );
    assert!(
        run.same_month_edge_mirrored,
        "precondition: the live pass mirrors the edge from the base row learned in the \
         window's month"
    );
    assert!(
        run.earlier_month_edge_mirrored,
        "the live pass mirrors the edge from the base row learned in an earlier month into \
         the world window of its target's month"
    );
    assert!(
        !run.earlier_base_row_in_window,
        "the earlier base row itself stays out of the world window"
    );
}
