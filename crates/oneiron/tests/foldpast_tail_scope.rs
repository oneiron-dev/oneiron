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
#![cfg(all(feature = "test-support", feature = "test-hooks", oneiron_test_support))]

use ed25519_dalek::SigningKey;
use oneiron::authority::{
    AuthorityAttestation, AuthorityCheckpointV2, AuthorityConfirmAction, AuthorityConfirmKind,
    AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityTier,
    DeviceAuthority, FederationLifecycleAction, FederationPactStatus, HostSlipIssuer, ROLE_AGENT,
    ROLE_OWNER, authority_entry_hash,
};
use oneiron::error::{Error, RecordError};
use oneiron::test_doors::foldpast::{
    connect_action, disconnect_action, forget_first_seen_receipt, put_signed_entries,
    sign_next_host_op, sign_next_host_op_cosigned, sign_next_op_as,
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

/// Writes a newer clean attested image on `home` and adopts it on
/// `adopting`, which adopted an older one.
fn adopt_newer_image(home: &Vault, issuer: &HostSlipIssuer, adopting: &Vault) {
    let head = home
        .write_authority_checkpoint_v2(issuer)
        .expect("write newer image");
    let image: AuthorityCheckpointV2 = home
        .authority_checkpoint_v2(&head)
        .expect("read newer image")
        .expect("newer image some");
    let bytes = image.encode().expect("newer image encodes");
    let attestations = home
        .authority_checkpoint_attestations(&head)
        .expect("newer attestations");
    let pin = home
        .authority_checkpoint_pin([0x5a; 32])
        .expect("newer pin")
        .expect("newer pin some");
    match image.building_pin {
        Some(root) => {
            let fixed = pin.digest().expect("pin digest");
            adopting
                .adopt_recovered_authority_checkpoint(&pin, &bytes, &attestations, fixed, root)
                .expect("adopt newer image");
        }
        None => {
            adopting
                .adopt_authority_checkpoint(&pin, &bytes, &attestations)
                .expect("adopt newer image");
        }
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

/// A first agent binding of `key` to `actor`.
fn agent_binding(key: &AuthorityKey, actor: EntityId) -> AuthorityOp {
    AuthorityOp::BindActor {
        authority_key: key.clone(),
        actor_ref: actor,
        actor_class: "agent".to_owned(),
        epoch: 1,
    }
}

/// Home with two agent keys covered, the first bound to an actor, its
/// adopter, the bound key, the unbound key and the bound actor.
fn binding_fixture() -> (Fixture, AuthorityKey, AuthorityKey, EntityId) {
    let (home, issuer, home_dir) = root_home();
    let bound = fresh_device(0x61, ROLE_AGENT);
    let unbound = fresh_device(0x62, ROLE_AGENT);
    let (bound_key, unbound_key) = (bound.key.clone(), unbound.key.clone());
    let actor = EntityId::now();
    for op in [
        AuthorityOp::EnrollDevice { device: bound },
        AuthorityOp::EnrollDevice { device: unbound },
        agent_binding(&bound_key, actor),
    ] {
        let entry = sign_next_host_op(&home, &issuer, op).expect("sign covered row");
        let hash = authority_entry_hash(&entry).expect("covered hash");
        put_signed_entries(&home, &[entry]).expect("store covered row");
        assert!(
            home.authority_fold()
                .expect("home folds covered row")
                .valid_entries
                .contains(&hash),
            "every covered row folds valid, so the image is clean"
        );
    }
    let (adopting, adopt_dir) = checkpoint_and_adopt(&home, &issuer);
    let fixture = Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    };
    (fixture, bound_key, unbound_key, actor)
}

/// The slip id the burn fixture mints.
const BURNED_SLIP: [u8; 32] = [0x91; 32];

/// Home with a live capability slip and a federation confirm covered, its
/// adopter, and the confirm.
fn burn_fixture() -> (Fixture, AuthorityConfirmAction) {
    let (home, issuer, home_dir) = root_home();
    let root = home.ensure_host_root_slip(&issuer).expect("host root slip");
    let issued_at = home.capability_slip_now().expect("slip clock");
    let mut claims = root.claims;
    claims.slip_id = BURNED_SLIP;
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    home.mint_capability_slip(&issuer, claims)
        .expect("mint covered slip");
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
    let slips = home.authority_fold().expect("home folds").slips;
    assert!(
        slips.mints.contains_key(&BURNED_SLIP) && !slips.consumed.contains(&BURNED_SLIP),
        "the covered slip is live"
    );
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

/// The signing key of the agent row `root_home` enrolls.
fn agent_signing() -> SigningKey {
    SigningKey::from_bytes(&[0x51; 32])
}

/// The authority key of the agent row `root_home` enrolls.
fn agent_key() -> AuthorityKey {
    fresh_device(0x51, ROLE_AGENT).key
}

/// A fresh federation confirm `seed` names.
fn fresh_confirm(seed: u8) -> AuthorityConfirmAction {
    AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id: [seed; 32],
        peer_vault_id: [seed.wrapping_add(1); 32],
        epoch: 1,
        nonce: [seed.wrapping_add(2); 16],
    }
}

/// Home with a federation confirm the host signed and the agent cosigned
/// covered (an approval resting on the agent's key), its adopter, and the
/// confirm's hash.
fn cosigned_confirm_fixture() -> (Fixture, [u8; 32]) {
    let (home, issuer, home_dir) = root_home();
    let entry = sign_next_host_op_cosigned(
        &home,
        &issuer,
        AuthorityOp::FederationConfirm(fresh_confirm(0xE1)),
        &agent_signing(),
    )
    .expect("sign cosigned confirm");
    let hash = authority_entry_hash(&entry).expect("confirm hash");
    put_signed_entries(&home, &[entry]).expect("store cosigned confirm");
    assert!(
        home.authority_fold()
            .expect("home folds confirm")
            .valid_entries
            .contains(&hash),
        "home counts the cosigned confirm"
    );
    let (adopting, adopt_dir) = checkpoint_and_adopt(&home, &issuer);
    let fixture = Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    };
    (fixture, hash)
}

/// The host's revocation of the agent's key, signed on home and stored on
/// both vaults.
fn revoke_agent(fixture: &Fixture) -> AuthorityLogEntry {
    sign_and_share(
        fixture,
        AuthorityOp::RevokeDevice {
            revoked_key: agent_key(),
        },
    )
}

/// Three stale-roster windows (24 h each by default): past every deadline a
/// row first seen in this test sets.
const PAST_THE_WINDOW_SECS: u64 = 3 * 24 * 60 * 60;

#[test]
fn device_revocation_past_an_adopted_image_folds() {
    let fixture = fixture();
    let key = agent_key();
    let revoke = revoke_agent(&fixture);
    let hash = authority_entry_hash(&revoke).expect("revoke hash");
    let home_fold = fixture.home.authority_fold().expect("home folds revoke");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds revoke");
    assert!(
        home_fold.valid_entries.contains(&hash),
        "home counts the revoke"
    );
    assert!(
        adopting_fold.valid_entries.contains(&hash),
        "adopting counts the revoke"
    );
    assert!(
        adopting_fold
            .roster
            .get(&key)
            .is_some_and(|device| device.revoked),
        "adopting holds the agent key revoked"
    );
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(
        adopting_fold.federation_pacts, home_fold.federation_pacts,
        "pacts match"
    );
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
    // A later row the revoked key signs folds rejected on both.
    let later = sign_next_op_as(
        &fixture.home,
        &agent_signing(),
        AuthorityOp::FederationConfirm(fresh_confirm(0xE4)),
    )
    .expect("sign as the agent");
    let later_hash = authority_entry_hash(&later).expect("later hash");
    put_signed_entries(&fixture.home, std::slice::from_ref(&later)).expect("store later on home");
    put_signed_entries(&fixture.adopting, std::slice::from_ref(&later))
        .expect("store later on adopting");
    let home_fold = fixture.home.authority_fold().expect("home folds later");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds later");
    for (vault, fold) in [("home", &home_fold), ("adopting", &adopting_fold)] {
        assert!(
            !fold.valid_entries.contains(&later_hash),
            "{vault} rejects the revoked key's row"
        );
        assert!(
            fold.issues
                .contains(&AuthorityFoldIssue::SignerNotInAncestry(later_hash)),
            "{vault} rejects it as signed by a revoked key"
        );
    }
    assert_eq!(
        adopting_fold.roster, home_fold.roster,
        "rosters still match"
    );
}

#[test]
fn covered_approval_on_a_revoked_device_lapses_on_the_adoption_clock() {
    let (fixture, confirm) = cosigned_confirm_fixture();
    let key = agent_key();
    let revoke = revoke_agent(&fixture);
    let revoke_hash = authority_entry_hash(&revoke).expect("revoke hash");
    let home_fold = fixture.home.authority_fold().expect("home folds revoke");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds revoke");
    assert!(
        adopting_fold.valid_entries.contains(&revoke_hash),
        "adopting counts the revoke"
    );
    assert!(
        adopting_fold
            .roster
            .get(&key)
            .is_some_and(|device| device.revoked),
        "adopting holds the agent key revoked"
    );
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    // Inside the window each vault still counts the approval: home from its
    // own first sight, the adopter from its adoption of the image.
    assert!(
        home_fold.valid_entries.contains(&confirm),
        "home counts the approval inside its window"
    );
    assert!(
        adopting_fold.valid_entries.contains(&confirm),
        "adopting counts the approval inside the adoption's window"
    );
    // Past min(first seen, revocation first seen) + window + 1 on each
    // vault's own clock, the approval lapses on both.
    for (name, vault) in [("home", &fixture.home), ("adopting", &fixture.adopting)] {
        vault
            .advance_authority_clock_for_test(vault.now_recorded_at() + PAST_THE_WINDOW_SECS)
            .expect("advance the clock");
        let fold = vault.authority_fold().expect("folds past the window");
        assert!(
            !fold.valid_entries.contains(&confirm),
            "{name} lets the approval lapse"
        );
        assert!(
            fold.issues
                .contains(&AuthorityFoldIssue::StaleRosterApproval(confirm)),
            "{name} lapses it as a stale roster approval"
        );
        assert!(
            fold.valid_entries.contains(&revoke_hash),
            "{name} still counts the revoke"
        );
    }
}

#[test]
fn covered_approval_with_no_adoption_receipt_needs_history() {
    let (fixture, confirm) = cosigned_confirm_fixture();
    assert!(
        forget_first_seen_receipt(&fixture.adopting, &confirm).expect("forget the receipt"),
        "adoption kept a first-seen receipt of the covered approval"
    );
    revoke_agent(&fixture);
    fixture.home.authority_fold().expect("home folds revoke");
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
fn confirm_reusing_a_covered_nonce_folds_as_rejected() {
    let (fixture, covered) = confirm_fixture();
    let tail_action = AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id: [0xD5; 32],
        peer_vault_id: covered.peer_vault_id,
        epoch: 1,
        nonce: covered.nonce,
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
        "home rejects the reused nonce"
    );
    assert!(
        !adopting_fold.valid_entries.contains(&hash),
        "adopting rejects the reused nonce"
    );
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(
        adopting_fold.federation_pacts, home_fold.federation_pacts,
        "pacts match"
    );
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
}

#[test]
fn binding_a_covered_bound_key_again_folds_as_rejected() {
    let (fixture, bound_key, _, _) = binding_fixture();
    let tail = sign_and_share(&fixture, agent_binding(&bound_key, EntityId::now()));
    let hash = authority_entry_hash(&tail).expect("tail hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds tail");
    assert!(
        !home_fold.valid_entries.contains(&hash),
        "home rejects a second binding of a bound key"
    );
    assert!(
        !adopting_fold.valid_entries.contains(&hash),
        "adopting rejects a second binding of a bound key"
    );
    assert_eq!(
        adopting_fold.actor_bindings, home_fold.actor_bindings,
        "bindings match"
    );
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
}

#[test]
fn binding_an_actor_a_covered_row_bound_still_needs_history() {
    let (fixture, _, unbound_key, actor) = binding_fixture();
    let tail = sign_and_share(&fixture, agent_binding(&unbound_key, actor));
    let hash = authority_entry_hash(&tail).expect("tail hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    assert!(
        home_fold.valid_entries.contains(&hash),
        "home accepts a second key's binding of the same actor"
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
fn readoption_keeps_no_receipt_for_a_row_the_prior_image_covered() {
    let (fixture, confirm) = cosigned_confirm_fixture();
    // As a vault that adopted before adoptions kept receipts.
    assert!(
        forget_first_seen_receipt(&fixture.adopting, &confirm).expect("forget the receipt"),
        "adoption kept a first-seen receipt of the covered approval"
    );
    let unrelated = sign_next_host_op(
        &fixture.home,
        &fixture.issuer,
        AuthorityOp::FederationConfirm(fresh_confirm(0xE7)),
    )
    .expect("sign unrelated confirm");
    put_signed_entries(&fixture.home, &[unrelated]).expect("store unrelated confirm");
    adopt_newer_image(&fixture.home, &fixture.issuer, &fixture.adopting);
    assert!(
        !forget_first_seen_receipt(&fixture.adopting, &confirm).expect("probe the receipt"),
        "the newer adoption kept no receipt for a row the prior image covered"
    );
    revoke_agent(&fixture);
    fixture.home.authority_fold().expect("home folds revoke");
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
fn slip_burn_below_a_rejected_tail_row_still_needs_history() {
    let (fixture, covered) = burn_fixture();
    let reused = AuthorityConfirmAction {
        nonce: [0xD4; 16],
        ..covered
    };
    let rejected = sign_and_share(&fixture, AuthorityOp::FederationConfirm(reused));
    let rejected_hash = authority_entry_hash(&rejected).expect("rejected hash");
    let burn = sign_and_share(
        &fixture,
        AuthorityOp::SlipConsume {
            slip_id: BURNED_SLIP,
        },
    );
    assert!(
        burn.parent_hashes.contains(&rejected_hash),
        "the burn stands on the rejected confirm"
    );
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    assert!(
        !home_fold.valid_entries.contains(&rejected_hash),
        "home rejects the reused confirm"
    );
    assert!(
        home_fold.slips.consumed.contains(&BURNED_SLIP),
        "home proves the burn past the rejected confirm"
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
