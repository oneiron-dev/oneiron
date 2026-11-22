// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `self.off_record.execute` binds its session run to the write actor of the
//! request's own credential (`CoreAuth::write_actor`). A Human slip handed on
//! to another key runs as its key holder, never as the person it names
//! (HANDED-ON-SLIP-PERSON, 15 Nov: Q1 = A, Q2 = A; the door built the run's
//! actor unmarked, so a handed-on owner slip's run wrote as the owner in
//! person).
//!
//! No test server runs a code-mode host, so the run itself is out of reach;
//! the door builds the run's actor at one site through `CoreAuth::write_actor`,
//! and these tests read that actor through
//! `oneiron_server::test_doors::credential_write_actor`. The red fails at the
//! base (the actor acts as the owner) and passes with the change; the guard
//! (the owner's own slip) passes on both.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --features oneiron/test-support --test handed_on_session_run`.
#![cfg(oneiron_test_support)]

use ed25519_dalek::Signer;
use oneiron::authority::{HostSlipIssuer, SlipCaveat, VerifiedSlip};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::test_doors::credential_write_actor::write_actor_for;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer =
            HostSlipIssuer::from_secret(b"handed-on-session-run").expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        Self {
            vault,
            owner,
            issuer,
            _directory: directory,
        }
    }

    /// A Human slip for the owner from the host root, held by the owner or
    /// handed on to another key first.
    fn owner_slip(&self, handed_on: bool) -> VerifiedSlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root")
            .claims;
        claims.slip_id = slip_id();
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip");
        if !handed_on {
            let challenge = b"handed-on session run own slip";
            let binding = self
                .issuer
                .binding_proof(&slip, challenge)
                .expect("the own binding proof");
            let own = self
                .vault
                .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &binding)
                .expect("the own slip verifies");
            assert!(!own.is_transferred(), "control: the owner holds this one");
            return own;
        }
        let next = ed25519_dalek::SigningKey::from_bytes(
            blake3::hash(b"handed-on session run handed holder").as_bytes(),
        );
        let mut handed = slip;
        self.issuer
            .attenuate_to(
                &mut handed,
                SlipCaveat::default(),
                next.verifying_key().to_bytes(),
            )
            .expect("the slip is handed on");
        let challenge = b"handed-on session run handed slip";
        let binding = next
            .sign(
                &handed
                    .binding_transcript(challenge)
                    .expect("the binding transcript"),
            )
            .to_bytes();
        let handed = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &handed, challenge, &binding)
            .expect("the handed slip verifies");
        assert!(handed.is_transferred(), "control: the slip was handed on");
        handed
    }
}

/// A fresh slip id.
fn slip_id() -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(EntityId::now().as_bytes());
    id[16..].copy_from_slice(EntityId::now().as_bytes());
    id
}

#[test]
fn a_handed_on_owner_slips_session_run_acts_as_no_person() {
    let fixture = Fixture::new();
    let slip = fixture.owner_slip(true);
    let actor = write_actor_for(slip, false, fixture.owner, EdgeActorClass::Human)
        .expect("the handed-on slip admits a request");
    assert!(
        !actor.acts_as_own_person(),
        "a session run on a handed-on owner slip must act as its key holder, never as the owner",
    );
}

#[test]
fn the_owners_own_slips_session_run_still_acts_as_the_owner() {
    let fixture = Fixture::new();
    let slip = fixture.owner_slip(false);
    let actor = write_actor_for(slip, true, fixture.owner, EdgeActorClass::Human)
        .expect("the own slip admits a request");
    assert!(
        actor.acts_as_own_person(),
        "the owner's own slip still runs as the owner",
    );
}
