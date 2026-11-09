//! Doors for the integration tests to crate-private items (Engine 19:23
//! HARNESS-GUARD). Compiled only under `--cfg oneiron_test_support`, which only
//! the test command sets (`RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! ... --test <stem>`); never behind a cargo feature, so no `--all-features`
//! build reaches them. Hidden; never API.

pub mod run_hold;

/// Runs the identity-topology reconcile that a replica's sync ingest runs,
/// over this vault's own ledger: shell edges, redirects and split assignment
/// rows re-derived from the fold. A test compares what a replica derives
/// from a history with what the local doors left.
pub fn reconcile_identity_topology(vault: &crate::Vault) -> crate::error::Result<()> {
    vault.with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
}
