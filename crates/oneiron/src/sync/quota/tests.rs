use super::*;

use crate::config::VaultConfig;
use crate::error::SyncError;

fn test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    (dir, vault)
}

fn authority_peer(seed: u8) -> MaintenanceIngestPeerKey {
    peer_key_from_authority_key(&AuthorityKey::Ed25519([seed; 32]))
}

fn accept_maintenance_peer_at(
    vault: &Vault,
    peer_key: MaintenanceIngestPeerKey,
    now_secs: u64,
) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        let _debit = try_accept_maintenance_ingest_peer_in_txn(vault, wtxn, peer_key, now_secs)?;
        Ok(())
    })
}

fn set_maintenance_quota(vault: &Vault, max_ops: u32, window_secs: u64) -> Result<()> {
    set_maintenance_ingest_quota_config(
        vault,
        MaintenanceIngestQuotaConfig {
            max_ops_per_peer_window: max_ops,
            quota_window_secs: window_secs,
        },
    )
}

#[test]
fn other_peer_unaffected() -> Result<()> {
    let (_dir, vault) = test_vault();
    let peer_a = authority_peer(10);
    let peer_b = authority_peer(11);
    set_maintenance_quota(&vault, 1, 60)?;

    accept_maintenance_peer_at(&vault, peer_a, 180)?;
    let err = accept_maintenance_peer_at(&vault, peer_a, 181)
        .expect_err("same peer must be capped in the same quota window");

    assert!(matches!(
        err,
        Error::Sync(SyncError::MaintenanceIngestQuotaExceeded {
            peer_key_hex,
            accepted_count: 1,
            max_ops_per_peer_window: 1,
            window_start_secs: 180,
            quota_window_secs: 60,
        }) if peer_key_hex == bytes_to_hex_lower(&peer_a.0)
    ));

    accept_maintenance_peer_at(&vault, peer_b, 182)?;
    let snapshots = maintenance_ingest_quota_snapshots(&vault)?;
    assert!(snapshots.iter().any(|snapshot| {
        snapshot.peer_key_hex == bytes_to_hex_lower(&peer_b.0)
            && snapshot.accepted_count == 1
            && snapshot.window_start_secs == 180
    }));
    Ok(())
}

#[test]
fn quota_resets_per_window() -> Result<()> {
    let (_dir, vault) = test_vault();
    let peer_key = authority_peer(12);
    set_maintenance_quota(&vault, 1, 10)?;

    accept_maintenance_peer_at(&vault, peer_key, 19)?;
    let same_window_err = accept_maintenance_peer_at(&vault, peer_key, 19)
        .expect_err("same window must remain capped");
    assert!(matches!(
        same_window_err,
        Error::Sync(SyncError::MaintenanceIngestQuotaExceeded {
            peer_key_hex,
            accepted_count: 1,
            max_ops_per_peer_window: 1,
            window_start_secs: 10,
            quota_window_secs: 10,
        }) if peer_key_hex == bytes_to_hex_lower(&peer_key.0)
    ));

    accept_maintenance_peer_at(&vault, peer_key, 20)?;
    let next_window_err = accept_maintenance_peer_at(&vault, peer_key, 20)
        .expect_err("new window must allow one ingest before capping again");
    assert!(matches!(
        next_window_err,
        Error::Sync(SyncError::MaintenanceIngestQuotaExceeded {
            peer_key_hex,
            accepted_count: 1,
            max_ops_per_peer_window: 1,
            window_start_secs: 20,
            quota_window_secs: 10,
        }) if peer_key_hex == bytes_to_hex_lower(&peer_key.0)
    ));
    Ok(())
}
