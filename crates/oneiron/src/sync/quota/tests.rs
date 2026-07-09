use super::*;

use crate::config::VaultConfig;

fn key(value: &str) -> WindowKey {
    WindowKey::new(value)
}

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
fn federation_quota_allows_known_windows_after_quota_is_reached() {
    let now = Instant::now();
    let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 30));

    assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
    assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
    assert_eq!(quota.snapshot(now).windows_touched, 1);
}

#[test]
fn federation_quota_exceeded_enters_observable_pause() {
    let now = Instant::now();
    let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 30));

    assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
    assert_eq!(
        quota.allow_window(&key("2026-04"), now),
        AllowBlock::Pause(FederationPauseReason::WindowQuotaExceeded)
    );

    let snapshot = quota.snapshot(now);
    assert_eq!(
        snapshot.decision,
        AllowBlock::Pause(FederationPauseReason::FloodPauseActive)
    );
    assert_eq!(snapshot.pause_remaining, Some(Duration::from_secs(30)));
    assert_eq!(snapshot.windows_touched, 1);
}

#[test]
fn federation_pause_resumes_after_pause_duration() {
    let now = Instant::now();
    let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 1));

    assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
    assert_eq!(
        quota.allow_window(&key("2026-04"), now),
        AllowBlock::Pause(FederationPauseReason::WindowQuotaExceeded)
    );
    assert_eq!(
        quota.allow_window(&key("2026-03"), now),
        AllowBlock::Pause(FederationPauseReason::FloodPauseActive)
    );

    let resumed = now + Duration::from_secs(1);
    assert_eq!(
        quota.allow_window(&key("2026-03"), resumed),
        AllowBlock::Allow
    );
}

#[test]
fn zero_federation_quota_blocks_connection() {
    let now = Instant::now();
    let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(0, 30));

    assert_eq!(
        quota.allow_window(&key("2026-03"), now),
        AllowBlock::Block(FederationBlockReason::WindowQuotaDisabled)
    );
    assert_eq!(
        quota.snapshot(now).decision,
        AllowBlock::Block(FederationBlockReason::WindowQuotaDisabled)
    );
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
        Error::MaintenanceIngestQuotaExceeded {
            peer_key_hex,
            accepted_count: 1,
            max_ops_per_peer_window: 1,
            window_start_secs: 180,
            quota_window_secs: 60,
        } if peer_key_hex == bytes_to_hex_lower(&peer_a.0)
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
        Error::MaintenanceIngestQuotaExceeded {
            peer_key_hex,
            accepted_count: 1,
            max_ops_per_peer_window: 1,
            window_start_secs: 10,
            quota_window_secs: 10,
        } if peer_key_hex == bytes_to_hex_lower(&peer_key.0)
    ));

    accept_maintenance_peer_at(&vault, peer_key, 20)?;
    let next_window_err = accept_maintenance_peer_at(&vault, peer_key, 20)
        .expect_err("new window must allow one ingest before capping again");
    assert!(matches!(
        next_window_err,
        Error::MaintenanceIngestQuotaExceeded {
            peer_key_hex,
            accepted_count: 1,
            max_ops_per_peer_window: 1,
            window_start_secs: 20,
            quota_window_secs: 10,
        } if peer_key_hex == bytes_to_hex_lower(&peer_key.0)
    ));
    Ok(())
}
