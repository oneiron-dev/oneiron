//! Consolidated integration-test binary for the `sync`-feature cluster.
//!
//! The Cargo target carries `required-features = ["sync"]`, so this binary
//! only builds when the feature is enabled; each module also keeps the
//! `#![cfg(feature = "sync")]` gate it carried as a standalone target.
//!
//! `sync_harness` is the shared two-vault harness used only by this cluster;
//! `common` is shared with `tests/it/main.rs` and stays at
//! `tests/common/mod.rs`.

#[path = "../common/mod.rs"]
mod common;
mod sync_harness;

mod rung0_cold_start_conformance;
mod sync_bridge;
mod sync_byzantine_lww;
mod sync_client_wiring;
mod sync_convergence_props;
mod sync_delete_propagation;
mod sync_edge_kind_gating;
mod sync_facet_of_admission_boundary;
mod sync_facet_of_replay_gating;
mod sync_maintenance_quota;
mod sync_quarantine;
mod sync_receipt_replay;
mod sync_remat_correctness;
mod sync_replay_reason;
mod sync_sweep_executor;
mod sync_tombstone_v2;
mod sync_window_manager;
