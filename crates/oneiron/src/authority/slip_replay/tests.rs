//! Replay-window boundaries, persistence, and eviction by timestamp.
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
fn a_crowded_replay_window_admits_the_next_fresh_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    // Seed the live rows directly rather than perform 4097 signed requests.
    vault
        .with_write_txn(|txn| {
            for n in 0..4097_u64 {
                let key = format!(
                    "{REPLAY_PREFIX}{:016x}:{}",
                    180,
                    blake3::hash(&n.to_be_bytes()).to_hex()
                );
                vault.store.sync_state.put(txn, &key, &[])?;
            }
            Ok(())
        })
        .unwrap();
    let fresh = b"33333333333333333333333333333333";
    assert!(record(&vault, 180, fresh, 180).is_ok());
}

#[test]
fn a_nonce_older_than_the_window_is_evicted() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    record(&vault, 180, b"44444444444444444444444444444444", 180).unwrap();
    record(&vault, 300, b"55555555555555555555555555555555", 300).unwrap();
    let old = format!("{REPLAY_PREFIX}{:016x}:", 180);
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        vault
            .store
            .sync_state
            .prefix_iter(&rtxn, &old)
            .unwrap()
            .count(),
        0
    );
}
