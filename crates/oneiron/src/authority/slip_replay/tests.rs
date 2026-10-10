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
