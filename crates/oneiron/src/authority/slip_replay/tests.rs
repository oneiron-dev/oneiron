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

/// A wall clock that steps back across a reopen cannot readmit a proof whose
/// row a later admission evicted: that admission committed its clock reading
/// beside the rows it kept.
#[test]
fn a_wall_clock_stepped_back_across_a_reopen_never_readmits_an_evicted_proof() {
    use crate::authority::{HostSlipIssuer, pairing_binding_transcript};
    use ed25519_dalek::{Signer, SigningKey};
    let dir = tempfile::tempdir().unwrap();
    let start = 1_900_000_000;
    let clock = crate::ports::ManualClock::new(start);
    let open = || {
        let mut config = crate::VaultConfig::default();
        config.store_clock = clock.bundle();
        Vault::open(dir.path(), config).unwrap()
    };
    let vault = open();
    let issuer = HostSlipIssuer::from_secret(b"replay-step-back-issuer").unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    let holder = SigningKey::from_bytes(&[94; 32]);
    let binding_key = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, crate::federation::Scope::top(), 86_400)
        .unwrap();
    let receipt = holder
        .sign(&pairing_binding_transcript(&link.code, &binding_key, "step-back-holder").unwrap())
        .to_bytes();
    let slip = vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            "step-back-holder",
            binding_key,
            &receipt,
        )
        .unwrap();
    let admit = |vault: &Vault, timestamp: u64, nonce: &str| {
        let challenge = holder_proof_challenge(timestamp, nonce);
        let signature = holder
            .sign(&slip.binding_transcript(&challenge).unwrap())
            .to_bytes();
        vault.admit_capability_slip_request(&slip, timestamp, &signature, nonce.as_bytes())
    };
    let first = "11111111111111111111111111111111";
    admit(&vault, start, first).unwrap();
    // A later proof moves the window past the first one and evicts its row.
    clock.set(start + 61);
    admit(&vault, start + 61, "22222222222222222222222222222222").unwrap();
    drop(vault);
    clock.set(start);
    let vault = open();
    assert!(admit(&vault, start, first).is_err());
    admit(&vault, start + 61, "33333333333333333333333333333333").unwrap();
}
