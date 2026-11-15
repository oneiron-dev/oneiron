// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A tail row folds past an adopted checkpoint image (FIX 11760).
//!
//! Home vault H roots, writes a few rows, and keeps a clean attested image.
//! Adopting vault A opens empty under H's storage id, adopts the image, and
//! holds no covered row. Each test signs a tail row on H, stores it on both
//! vaults, and compares A's adopted fold with H's whole-history fold.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test foldpast_tail_scope`.
#![cfg(all(feature = "test-support", oneiron_test_support))]

use ed25519_dalek::SigningKey;
use oneiron::authority::{
    AuthorityAttestation, AuthorityCheckpointV2, AuthorityConfirmAction, AuthorityConfirmKind,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityTier, DeviceAuthority,
    FederationLifecycleAction, FederationPactStatus, HostSlipIssuer, ROLE_AGENT, ROLE_OWNER,
    authority_entry_hash,
};
use oneiron::error::{Error, RecordError};
use oneiron::test_doors::foldpast::{
    connect_action, disconnect_action, put_signed_entries, sign_next_host_op,
};
use oneiron::{EntityId, OpenOptions, Vault, VaultConfig, VaultStorageId};

/// Home vault H, adopting vault A, and H's host issuer. The vaults close
/// before their directories go.
struct Fixture {
    home: Vault,
    adopting: Vault,
    issuer: HostSlipIssuer,
    _home_dir: tempfile::TempDir,
    _adopt_dir: tempfile::TempDir,
}

/// A fresh device row for `seed` at `roles`.
fn fresh_device(seed: u8, roles: u16) -> DeviceAuthority {
    let public = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    DeviceAuthority {
        key: AuthorityKey::Ed25519(public),
        transport_key_binding: [0x07; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".into(),
            evidence: Vec::new(),
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

/// Builds a clean attested image on `home` and opens an empty adopter of it.
fn checkpoint_and_adopt(home: &Vault, issuer: &HostSlipIssuer) -> (Vault, tempfile::TempDir) {
    let home_fold = home.authority_fold().expect("home folds");
    assert!(home_fold.issues.is_empty(), "home fold has no issues");
    let head = home
        .write_authority_checkpoint_v2(issuer)
        .expect("write image");
    let kept = home
        .authority_checkpoint_v2_head()
        .expect("head")
        .expect("head some");
    assert_eq!(kept, head, "head is the written image");
    let image: AuthorityCheckpointV2 = home
        .authority_checkpoint_v2(&head)
        .expect("read image")
        .expect("image some");
    assert!(!image.covered.is_empty(), "image covers rows");
    let image_fold = image.fold();
    assert!(image_fold.issues.is_empty(), "image has no issues");
    for hash in &image.covered {
        assert!(image_fold.valid_entries.contains(hash), "covered row valid");
    }
    let bytes = image.encode().expect("image encodes");
    let attestations = home
        .authority_checkpoint_attestations(&head)
        .expect("attestations");
    assert!(!attestations.is_empty(), "image is attested");
    let pin = home
        .authority_checkpoint_pin([0x5a; 32])
        .expect("pin")
        .expect("pin some");
    let storage_id = VaultStorageId::from_verified_pin(&pin);
    let adopt_dir = tempfile::tempdir().expect("adopt dir");
    let adopting = Vault::open_owned_with(
        adopt_dir.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(storage_id),
    )
    .expect("adopting opens");
    match image.building_pin {
        Some(root) => {
            let fixed = pin.digest().expect("pin digest");
            adopting
                .adopt_recovered_authority_checkpoint(&pin, &bytes, &attestations, fixed, root)
                .expect("adopt image");
        }
        None => adopting
            .adopt_authority_checkpoint(&pin, &bytes, &attestations)
            .expect("adopt image"),
    }
    adopting.authority_fold().expect("empty tail projects");
    (adopting, adopt_dir)
}

/// Roots home with one agent row.
fn root_home() -> (Vault, HostSlipIssuer, tempfile::TempDir) {
    let home_dir = tempfile::tempdir().expect("home dir");
    let home = Vault::open_owned(home_dir.path(), VaultConfig::default()).expect("home opens");
    let issuer = HostSlipIssuer::from_secret(b"foldpast-test-host-secret").expect("host issuer");
    home.ensure_host_root_slip(&issuer).expect("host root");
    let agent = fresh_device(0x51, ROLE_AGENT);
    let enroll = sign_next_host_op(&home, &issuer, AuthorityOp::EnrollDevice { device: agent })
        .expect("sign agent enroll");
    put_signed_entries(&home, &[enroll]).expect("store agent enroll");
    (home, issuer, home_dir)
}

/// Home rooted with one agent row, a clean attested image, and an empty
/// adopter of it whose empty tail already projects.
fn fixture() -> Fixture {
    let (home, issuer, home_dir) = root_home();
    let (adopting, adopt_dir) = checkpoint_and_adopt(&home, &issuer);
    Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    }
}

/// Home with a connected pact covered, its adopter, and the Connect.
fn pact_fixture() -> (Fixture, FederationLifecycleAction) {
    let (home, issuer, home_dir) = root_home();
    let grant = EntityId::now();
    let connect = connect_action(&home, grant).expect("connect action");
    let entry = sign_next_host_op(
        &home,
        &issuer,
        AuthorityOp::FederationLifecycle(connect.clone()),
    )
    .expect("sign connect");
    put_signed_entries(&home, &[entry]).expect("store connect");
    let (adopting, adopt_dir) = checkpoint_and_adopt(&home, &issuer);
    let fixture = Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    };
    (fixture, connect)
}

/// Home with a federation confirm covered, its adopter, and the confirm.
fn confirm_fixture() -> (Fixture, AuthorityConfirmAction) {
    let (home, issuer, home_dir) = root_home();
    let covered = AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id: [0xD1; 32],
        peer_vault_id: [0xD2; 32],
        epoch: 1,
        nonce: [0xD3; 16],
    };
    let entry = sign_next_host_op(
        &home,
        &issuer,
        AuthorityOp::FederationConfirm(covered.clone()),
    )
    .expect("sign covered confirm");
    put_signed_entries(&home, &[entry]).expect("store covered confirm");
    let (adopting, adopt_dir) = checkpoint_and_adopt(&home, &issuer);
    let fixture = Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    };
    (fixture, covered)
}

/// Signs `op` on home and stores it on both vaults.
fn sign_and_share(fixture: &Fixture, op: AuthorityOp) -> AuthorityLogEntry {
    let entry = sign_next_host_op(&fixture.home, &fixture.issuer, op).expect("sign tail");
    put_signed_entries(&fixture.home, std::slice::from_ref(&entry)).expect("store tail on home");
    put_signed_entries(&fixture.adopting, std::slice::from_ref(&entry))
        .expect("store tail on adopting");
    entry
}

#[test]
fn key_rotation_past_an_adopted_image_folds_as_rejected() {
    let fixture = fixture();
    let before = fixture
        .home
        .authority_fold()
        .expect("home folds")
        .roster
        .clone();
    let new_device = fresh_device(0x52, ROLE_OWNER);
    let op = AuthorityOp::RotateKey {
        old_key: fixture.issuer.public_key(),
        new_device,
    };
    let tail = sign_and_share(&fixture, op);
    let hash = authority_entry_hash(&tail).expect("tail hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds tail");
    assert!(
        !home_fold.valid_entries.contains(&hash),
        "home rejects the rotation"
    );
    assert!(
        !adopting_fold.valid_entries.contains(&hash),
        "adopting rejects the rotation"
    );
    assert_eq!(home_fold.roster, before, "home roster unchanged");
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(
        adopting_fold.federation_pacts, home_fold.federation_pacts,
        "pacts match"
    );
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
}

#[test]
fn non_agent_enrollment_past_an_adopted_image_folds_as_rejected() {
    let fixture = fixture();
    let before = fixture
        .home
        .authority_fold()
        .expect("home folds")
        .roster
        .clone();
    let device = fresh_device(0x53, ROLE_OWNER);
    let tail = sign_and_share(&fixture, AuthorityOp::EnrollDevice { device });
    let hash = authority_entry_hash(&tail).expect("tail hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds tail");
    assert!(
        !home_fold.valid_entries.contains(&hash),
        "home rejects the enrollment"
    );
    assert!(
        !adopting_fold.valid_entries.contains(&hash),
        "adopting rejects the enrollment"
    );
    assert_eq!(home_fold.roster, before, "home roster unchanged");
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(
        adopting_fold.federation_pacts, home_fold.federation_pacts,
        "pacts match"
    );
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
}

#[test]
fn rejected_row_beside_a_serial_withdrawal_still_needs_history() {
    let fixture = fixture();
    let epoch = fixture
        .home
        .authority_fold()
        .expect("home folds")
        .actor_bindings
        .get(&fixture.issuer.public_key())
        .expect("host binds owner")
        .epoch;
    let revoke = AuthorityOp::RevokeActor {
        authority_key: fixture.issuer.public_key(),
        epoch,
    };
    let first = sign_next_host_op(&fixture.home, &fixture.issuer, revoke).expect("sign revoke");
    put_signed_entries(&fixture.home, std::slice::from_ref(&first)).expect("store revoke on home");
    let new_device = fresh_device(0x54, ROLE_OWNER);
    let rotate = AuthorityOp::RotateKey {
        old_key: fixture.issuer.public_key(),
        new_device,
    };
    let second = sign_next_host_op(&fixture.home, &fixture.issuer, rotate).expect("sign rotate");
    put_signed_entries(&fixture.home, std::slice::from_ref(&second)).expect("store rotate on home");
    put_signed_entries(&fixture.adopting, &[first.clone(), second.clone()])
        .expect("store tail on adopting");
    let home_fold = fixture.home.authority_fold().expect("home folds both");
    let first_hash = authority_entry_hash(&first).expect("revoke hash");
    let second_hash = authority_entry_hash(&second).expect("rotate hash");
    assert!(
        home_fold.valid_entries.contains(&first_hash),
        "home counts the revoke"
    );
    assert!(
        !home_fold.valid_entries.contains(&second_hash),
        "home rejects the rotation"
    );
    let err = fixture
        .adopting
        .authority_fold()
        .expect_err("adopting needs history");
    assert!(
        matches!(
            err,
            Error::Record(RecordError::AuthorityHistoryRequired { .. })
        ),
        "history required, got {err:?}"
    );
}

#[test]
fn agent_enrollment_with_fresh_key_still_folds() {
    let fixture = fixture();
    let device = fresh_device(0x55, ROLE_AGENT);
    let key = device.key.clone();
    let tail = sign_and_share(&fixture, AuthorityOp::EnrollDevice { device });
    let hash = authority_entry_hash(&tail).expect("tail hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds tail");
    assert!(
        home_fold.valid_entries.contains(&hash),
        "home counts the enrollment"
    );
    assert!(
        adopting_fold.valid_entries.contains(&hash),
        "adopting counts the enrollment"
    );
    assert!(
        home_fold.roster.contains_key(&key),
        "home rosters the agent key"
    );
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(
        adopting_fold.federation_pacts, home_fold.federation_pacts,
        "pacts match"
    );
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
}

#[test]
fn disconnect_past_an_adopted_image_folds_and_matches_home() {
    let (fixture, connect) = pact_fixture();
    let disconnect = disconnect_action(&connect);
    let pact_id = disconnect.pact_id;
    let tail = sign_and_share(&fixture, AuthorityOp::FederationLifecycle(disconnect));
    let hash = authority_entry_hash(&tail).expect("tail hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds tail");
    assert!(
        home_fold.valid_entries.contains(&hash),
        "home counts the disconnect"
    );
    assert!(
        adopting_fold.valid_entries.contains(&hash),
        "adopting counts the disconnect"
    );
    let home_pact = home_fold.federation_pacts.get(&pact_id).expect("home pact");
    let adopting_pact = adopting_fold
        .federation_pacts
        .get(&pact_id)
        .expect("adopting pact");
    assert_eq!(
        home_pact.status,
        FederationPactStatus::Disconnected,
        "home disconnects"
    );
    assert_eq!(adopting_pact, home_pact, "pact matches");
    assert_eq!(
        adopting_fold.federation_pacts, home_fold.federation_pacts,
        "all pacts match"
    );
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
}

#[test]
fn confirm_reusing_a_covered_id_folds_as_rejected() {
    let (fixture, covered) = confirm_fixture();
    let before = fixture
        .home
        .authority_fold()
        .expect("home folds")
        .roster
        .clone();
    let tail_action = AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id: covered.confirm_id,
        peer_vault_id: covered.peer_vault_id,
        epoch: 1,
        nonce: [0xD4; 16],
    };
    let tail = sign_and_share(&fixture, AuthorityOp::FederationConfirm(tail_action));
    let hash = authority_entry_hash(&tail).expect("tail hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds tail");
    assert!(
        !home_fold.valid_entries.contains(&hash),
        "home rejects the reused confirm"
    );
    assert!(
        !adopting_fold.valid_entries.contains(&hash),
        "adopting rejects the reused confirm"
    );
    assert_eq!(home_fold.roster, before, "home roster unchanged");
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(
        adopting_fold.federation_pacts, home_fold.federation_pacts,
        "pacts match"
    );
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
}
