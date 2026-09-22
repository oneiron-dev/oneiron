//! Replay-window boundaries, persistence, and fail-closed capacity.
use super::*;

fn record(vault: &Vault, timestamp: u64, nonce: &[u8], now: u64) -> Result<()> {
    vault.with_write_txn(|txn| record_nonce(vault, txn, &[7; 32], nonce, timestamp, now))
}

#[test]
fn timed_replay_survives_reopen_and_rotation_never_reopens_an_old_proof() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let nonce = b"11111111111111111111111111111111";
    // A future-skewed request stays protected through its inclusive +60 boundary.
    record(&vault, 180, nonce, 120).unwrap();
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    assert!(record(&vault, 180, nonce, 240).is_err());
    assert!(request_challenge(180, nonce, 240).is_ok());
    assert!(request_challenge(180, nonce, 241).is_err());
    // Bucket 6 reuses bucket 3's slot, but only after every bucket-3 proof expired.
    record(&vault, 360, nonce, 300).unwrap();
    assert!(record(&vault, 180, nonce, 300).is_err());
    assert!(record(&vault, 360, nonce, 300).is_err());
}

#[test]
fn full_live_replay_window_refuses_without_eviction_then_rotates() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    // Seed a full persisted window directly rather than perform 4096 signed requests.
    let window = ReplayWindow {
        bucket: 3,
        nonces: (0..MAX_WINDOW_NONCES)
            .map(|n| {
                let mut digest = [0; 32];
                digest[..8].copy_from_slice(&(n as u64).to_be_bytes());
                digest
            })
            .collect(),
    };
    vault
        .with_write_txn(|txn| {
            vault.store.sync_state.put(
                txn,
                "authority:slip-replay:v1:0",
                &rmp_serde::to_vec_named(&window).unwrap(),
            )?;
            Ok(())
        })
        .unwrap();
    let nonce = b"22222222222222222222222222222222";
    assert!(record(&vault, 180, nonce, 180).is_err());
    record(&vault, 360, nonce, 300).unwrap();
    assert!(record(&vault, 360, nonce, 300).is_err());
}
