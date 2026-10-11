//! Replay-window boundaries, persistence, and eviction by timestamp.
use super::*;

fn record(vault: &Vault, timestamp: u64, nonce: &[u8], now: u64) -> Result<()> {
    vault.with_write_txn(|txn| {
        record_nonce(vault, txn, &[7; 32], nonce, timestamp, ProofClock::at(now))
    })
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
    assert!(request_challenge(180, nonce, ProofClock::at(240)).is_ok());
    assert!(request_challenge(180, nonce, ProofClock::at(241)).is_err());
    // A later proof with the same nonce is its own row; the earlier one stays refused.
    record(&vault, 360, nonce, 300).unwrap();
    assert!(record(&vault, 180, nonce, 300).is_err());
    assert!(record(&vault, 360, nonce, 300).is_err());
}

/// A wall clock that steps back across a reopen cannot readmit a proof whose
/// row a later admission evicted, and the proof clock stays where that
/// admission committed it. So does the vault's recording clock, which every
/// admission observes.
#[test]
fn a_wall_clock_stepped_back_across_a_reopen_never_readmits_an_evicted_proof() {
    use crate::authority::{HostSlipIssuer, pairing_binding_transcript};
    use ed25519_dalek::{Signer, SigningKey};
    let dir = tempfile::tempdir().unwrap();
    let start = 1_900_000_000;
    let clock = crate::ports::ManualClock::new(start);
    let open = || {
        let config = crate::VaultConfig {
            store_clock: clock.bundle(),
            ..crate::VaultConfig::default()
        };
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
    // A proof a day later moves the window past the first one and evicts its row.
    let later = start + RETAIN_SECS + 61;
    clock.set(later);
    admit(&vault, later, "22222222222222222222222222222222").unwrap();
    assert!(
        admit(&vault, start, "44444444444444444444444444444444").is_err(),
        "the window has moved past the first proof's time"
    );
    drop(vault);
    clock.set(start);
    let vault = open();
    assert_eq!(
        vault.now_recorded_at(),
        later,
        "the recording clock keeps the admission's reading"
    );
    assert!(admit(&vault, start, first).is_err(), "the evicted proof");
    assert!(
        admit(&vault, start + 30, "55555555555555555555555555555555").is_err(),
        "a fresh proof on the stepped-back wall clock"
    );
    admit(&vault, later, "33333333333333333333333333333333").unwrap();
}

const YEAR: u64 = 365 * 24 * 60 * 60;

/// One paired holder on an owned vault whose wall clock the test sets.
struct Holder {
    _dir: tempfile::TempDir,
    clock: std::sync::Arc<crate::ports::ManualClock>,
    vault: Vault,
    key: ed25519_dalek::SigningKey,
    slip: crate::authority::CapabilitySlip,
}

impl Holder {
    fn paired(start: u64) -> Self {
        use crate::authority::{HostSlipIssuer, pairing_binding_transcript};
        use ed25519_dalek::Signer;
        let dir = tempfile::tempdir().unwrap();
        let clock = crate::ports::ManualClock::new(start);
        let config = crate::VaultConfig {
            store_clock: clock.bundle(),
            ..crate::VaultConfig::default()
        };
        let vault = Vault::open_owned(dir.path(), config).unwrap();
        let issuer = HostSlipIssuer::from_secret(b"clock-recovery-issuer").unwrap();
        vault.ensure_host_root_slip(&issuer).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[95; 32]);
        let binding_key = key.verifying_key().to_bytes();
        let link = vault
            .issue_pairing_link(&issuer, crate::federation::Scope::top(), 86_400)
            .unwrap();
        let receipt = key
            .sign(&pairing_binding_transcript(&link.code, &binding_key, "recovery-holder").unwrap())
            .to_bytes();
        let slip = vault
            .redeem_pairing_link(
                &issuer,
                &link.code,
                "recovery-holder",
                binding_key,
                &receipt,
            )
            .unwrap();
        Self {
            _dir: dir,
            clock,
            vault,
            key,
            slip,
        }
    }

    /// The nonce `n` and `key`'s signature over the proof at `timestamp`.
    fn sign(&self, key: &ed25519_dalek::SigningKey, timestamp: u64, n: u32) -> (String, [u8; 64]) {
        use ed25519_dalek::Signer;
        let nonce = format!("{n:032x}");
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = key.sign(&self.slip.binding_transcript(&challenge).unwrap());
        (nonce, signature.to_bytes())
    }

    /// Sends the proof signed at `timestamp` with nonce `n`.
    fn admit(&self, timestamp: u64, n: u32) -> Result<()> {
        let (nonce, signature) = self.sign(&self.key, timestamp, n);
        self.vault
            .admit_capability_slip_request(&self.slip, timestamp, &signature, nonce.as_bytes())
            .map(drop)
    }

    /// What the 401 diagnosis finds for the proof `key` signed at `timestamp`.
    fn ahead(&self, key: &ed25519_dalek::SigningKey, timestamp: u64) -> Option<ProofClockAhead> {
        self.ahead_on(&self.slip, key, timestamp, 99)
    }

    fn ahead_on(
        &self,
        slip: &crate::authority::CapabilitySlip,
        key: &ed25519_dalek::SigningKey,
        timestamp: u64,
        n: u32,
    ) -> Option<ProofClockAhead> {
        use ed25519_dalek::Signer;
        let nonce = format!("{n:032x}");
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = key
            .sign(&slip.binding_transcript(&challenge).unwrap())
            .to_bytes();
        self.vault
            .proof_clock_ahead(slip, timestamp, &signature, nonce.as_bytes())
            .unwrap()
            .map(|(ahead, _)| ahead)
    }

    fn recover(&self) -> Result<ProofClockRecovery> {
        let actor = self.vault.ensure_embedded_owner_actor().unwrap();
        let owner = self
            .vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                true,
                crate::store::GateDecisionId::now(),
            )
            .unwrap();
        self.vault.recover_proof_clock(&owner)
    }
}

/// The host clock runs a year ahead for a minute and is set back: every
/// fresh proof is refused, for that reason, until the owner's clock
/// recovery. After it, the holder's next fresh proof gets in, and neither a
/// proof captured before the jump nor one signed then and held back unsent
/// gets in, inside its own window.
#[test]
fn a_clock_recovery_admits_the_next_fresh_proof_and_no_proof_signed_before_it() {
    let start = 1_900_000_000;
    let holder = Holder::paired(start);
    holder.admit(start, 1).unwrap();
    let held_back = start + 20;
    holder.clock.set(start + YEAR);
    holder.admit(start + YEAR, 2).unwrap();
    holder.clock.set(start + 40);
    assert!(holder.admit(start + 40, 3).is_err(), "a fresh proof");
    assert_eq!(
        holder.ahead(&holder.key, start + 40),
        Some(ProofClockAhead {
            floor: start + YEAR,
            wall: start + 40,
        })
    );
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[96; 32]);
    assert_eq!(
        holder.ahead(&stranger, start + 40),
        None,
        "a proof the holder did not sign"
    );
    let mut once = holder.slip.clone();
    once.attenuate(
        crate::authority::SlipCaveat {
            single_use: true,
            expires_at: Some(once.claims.issued_at + 300),
            ..Default::default()
        },
        &holder.key,
    )
    .unwrap();
    assert_eq!(
        holder.ahead_on(&once, &holder.key, start + 40, 99),
        None,
        "a one-shot slip, which no transport takes"
    );

    assert_eq!(
        holder.recover().unwrap(),
        ProofClockRecovery::Recovered {
            old_floor: start + YEAR,
            new_floor: start + 40,
            not_before: start + 40,
        }
    );
    assert!(
        holder.admit(start, 1).is_err(),
        "the proof captured before the jump"
    );
    assert!(
        holder.admit(held_back, 4).is_err(),
        "the proof held back unsent"
    );
    holder.admit(start + 40, 5).unwrap();
    assert_eq!(holder.ahead(&holder.key, start + 40), None);
    assert!(
        matches!(holder.recover(), Ok(ProofClockRecovery::NotAhead { .. })),
        "nothing left to recover"
    );
    holder.clock.set(start + 200);
    holder.admit(start + 200, 6).unwrap();
    holder.clock.set(start + 100);
    assert!(
        holder.admit(start + 100, 7).is_err(),
        "after a recovery, a wall clock that steps back fails closed again"
    );

    let replayed = Holder::paired(start);
    replayed.admit(start, 1).unwrap();
    replayed.clock.set(start + 120);
    replayed.admit(start + 120, 2).unwrap();
    replayed.clock.set(start);
    assert!(replayed.ahead(&replayed.key, start).is_some());
    assert_eq!(
        replayed.ahead_on(&replayed.slip, &replayed.key, start, 1),
        None,
        "a proof the vault admitted before, which no recovery lets in"
    );

    let first = Holder::paired(start);
    first.clock.set(start + YEAR);
    first.admit(start + YEAR, 1).unwrap();
    first.clock.set(start + 40);
    assert_eq!(
        first.recover().unwrap(),
        ProofClockRecovery::Recovered {
            old_floor: start + YEAR,
            new_floor: start + 40,
            not_before: start + 40,
        },
        "the holder's first proof came during the jump"
    );
    first.admit(start + 40, 2).unwrap();
}

/// Proofs whose rows the jump evicted stay refused after a recovery, even
/// when signed after its wall time: one signed a minute ahead before the
/// jump, and one admitted during the jump and followed by a later proof.
/// A jump that stays ahead for over a day forgets proofs a recovery would
/// reopen, so the recovery refuses and changes nothing.
#[test]
fn a_clock_recovery_reopens_no_proof_the_jump_evicted() {
    let start = 1_900_000_000;
    let holder = Holder::paired(start);
    holder.admit(start + 60, 1).unwrap();
    holder.clock.set(start + YEAR + 60);
    holder.admit(start + YEAR, 2).unwrap();
    holder.clock.set(start + YEAR + 61);
    holder.admit(start + YEAR + 61, 3).unwrap();
    holder.clock.set(start + 40);
    assert_eq!(
        holder.recover().unwrap(),
        ProofClockRecovery::Recovered {
            old_floor: start + YEAR + 61,
            new_floor: start + 40,
            not_before: start + 61,
        }
    );
    assert!(
        holder.admit(start + 60, 1).is_err(),
        "signed ahead before the jump"
    );
    holder.admit(start + 61, 4).unwrap();
    holder.clock.set(start + YEAR);
    assert!(
        holder.admit(start + YEAR, 2).is_err(),
        "admitted during the jump"
    );
    holder.admit(start + YEAR, 5).unwrap();

    let held = Holder::paired(start);
    held.admit(start, 1).unwrap();
    held.clock.set(start + YEAR);
    held.admit(start + YEAR, 2).unwrap();
    held.clock.set(start + YEAR + RETAIN_SECS + 1);
    held.admit(start + YEAR + RETAIN_SECS + 1, 3).unwrap();
    held.clock.set(start + 40);
    assert_eq!(
        held.recover().unwrap(),
        ProofClockRecovery::Forgotten {
            floor: start + YEAR + RETAIN_SECS + 1,
            forgotten_before: start + YEAR + 1,
            wall: start + 40,
        }
    );
    assert!(
        held.admit(start + 40, 4).is_err(),
        "the clock stays where it was"
    );
}

/// A vault whose admissions kept neither the proof clock nor the mark, as
/// before them: its recording floor stands in for the proof clock, and the
/// oldest nonce row left bounds what those admissions evicted. A jump that
/// only moved the recording clock recovers. One whose admissions evicted
/// rows cannot say how far ahead the evicted proofs were signed, so the
/// recovery refuses.
#[test]
fn a_vault_without_the_mark_recovers_unless_a_proof_admitted_in_the_jump_evicted_rows() {
    let start = 1_900_000_000;
    let unmark = |holder: &Holder| {
        let store = &holder.vault.store;
        let mut txn = store.env.write_txn().unwrap();
        PROOF_CLOCK_FLOOR.delete(store, &mut txn, &()).unwrap();
        PROOF_NOT_BEFORE.delete(store, &mut txn, &()).unwrap();
        txn.commit().unwrap();
    };
    let moved = Holder::paired(start);
    moved.admit(start, 1).unwrap();
    unmark(&moved);
    moved.clock.set(start + YEAR);
    moved.vault.store.authorization_now().unwrap();
    moved.clock.set(start + 40);
    assert!(
        moved.admit(start + 40, 2).is_err(),
        "the recording floor stands in"
    );
    assert_eq!(
        moved.recover().unwrap(),
        ProofClockRecovery::Recovered {
            old_floor: start + YEAR,
            new_floor: start + 40,
            not_before: start + 40,
        }
    );
    assert!(
        moved.admit(start, 1).is_err(),
        "the proof captured before the jump"
    );
    moved.admit(start + 40, 3).unwrap();

    let jumped = Holder::paired(start);
    jumped.admit(start, 1).unwrap();
    jumped.clock.set(start + YEAR);
    jumped.admit(start + YEAR, 2).unwrap();
    jumped.vault.store.authorization_now().unwrap();
    unmark(&jumped);
    jumped.clock.set(start + 40);
    assert_eq!(
        jumped.recover().unwrap(),
        ProofClockRecovery::Forgotten {
            floor: start + YEAR,
            forgotten_before: start + YEAR - 60,
            wall: start + 40,
        }
    );
}

/// A restore made for the vault's place, published after the vault admitted
/// a proof and recovered its proof clock, would know neither: that proof
/// would get in again. The swap refuses it and nothing moves.
#[test]
fn a_restore_made_before_a_clock_recovery_is_refused_at_its_swap() {
    let start = 1_900_000_000;
    let holder = Holder::paired(start);
    holder.clock.set(start + 50);
    holder.admit(start + 50, 1).unwrap();
    let root = tempfile::tempdir().unwrap();
    let image = root.path().join("image");
    holder
        .vault
        .snapshot_checkpoint(&image, start + 50)
        .unwrap();
    let config = crate::VaultConfig {
        store_clock: holder.clock.bundle(),
        ..crate::VaultConfig::default()
    };
    let (replacement, _) = Vault::restore_checkpoint_replacing(
        &image,
        &root.path().join("staged"),
        config,
        &holder.vault,
        start + 50,
    )
    .unwrap();
    holder.clock.set(start + 40);
    holder.admit(start + 20, 2).unwrap();
    assert_eq!(
        holder.recover().unwrap(),
        ProofClockRecovery::Recovered {
            old_floor: start + 50,
            new_floor: start + 40,
            not_before: start + 40,
        }
    );

    let swapped = std::cell::Cell::new(false);
    let refused = holder.vault.swap_in_replacement(&replacement, || {
        swapped.set(true);
        Ok(())
    });
    assert!(
        matches!(refused, Err(Error::InvalidConfig(_))),
        "{refused:?}"
    );
    assert!(!swapped.get(), "the swap never ran");
    assert!(
        holder.admit(start + 20, 2).is_err(),
        "the proof admitted after the restore was made"
    );
    holder.admit(start + 41, 3).unwrap();
}
