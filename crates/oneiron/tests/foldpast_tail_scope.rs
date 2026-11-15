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

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AuthorityAttestation, AuthorityCheckpointV2, AuthorityConfirmAction, AuthorityConfirmKind,
    AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthorityTier,
    DeviceAuthority, FederationLifecycleAction, FederationPactStatus, HostSlipIssuer,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineOwnership, MachineProfile, MachineRole, ROLE_ADMIN, ROLE_AGENT,
    ROLE_OWNER, authority_entry_hash, machine_profile_proof_transcript,
};
use oneiron::error::{Error, RecordError};
use oneiron::test_doors::foldpast::{
    connect_action, disconnect_action, forget_first_seen_receipt, put_signed_entries,
    sign_host_op_beside_next, sign_next_host_op, sign_next_host_op_cosigned, sign_next_op_as,
};
use oneiron::{EntityId, OpenOptions, Vault, VaultConfig, VaultStorageId};
use oneiron_contracts::authority::AuthorityHistoryReason;

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
    adopt_image(home, &head, &image)
}

/// Opens an empty adopter of `image`, the attested image `head` that `home`
/// keeps, and folds its empty tail.
fn adopt_image(
    home: &Vault,
    head: &[u8; 32],
    image: &AuthorityCheckpointV2,
) -> (Vault, tempfile::TempDir) {
    let bytes = image.encode().expect("image encodes");
    let attestations = home
        .authority_checkpoint_attestations(head)
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
    match image.building_pin.clone() {
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
    binding_fixture_then(|_, _| Vec::new())
}

/// [`binding_fixture`], with the rows `then` makes of the bound key and
/// actor covered after the binding.
fn binding_fixture_then(
    then: impl FnOnce(&AuthorityKey, EntityId) -> Vec<AuthorityOp>,
) -> (Fixture, AuthorityKey, AuthorityKey, EntityId) {
    let (home, issuer, home_dir) = root_home();
    let bound = fresh_device(0x61, ROLE_AGENT);
    let unbound = fresh_device(0x62, ROLE_AGENT);
    let (bound_key, unbound_key) = (bound.key.clone(), unbound.key.clone());
    let actor = EntityId::now();
    let later = then(&bound_key, actor);
    for op in [
        AuthorityOp::EnrollDevice { device: bound },
        AuthorityOp::EnrollDevice { device: unbound },
        agent_binding(&bound_key, actor),
    ]
    .into_iter()
    .chain(later)
    {
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

/// Signs `op` on home and stores it there alone.
fn sign_on_home(fixture: &Fixture, op: AuthorityOp) -> AuthorityLogEntry {
    let entry = sign_next_host_op(&fixture.home, &fixture.issuer, op).expect("sign tail");
    put_signed_entries(&fixture.home, std::slice::from_ref(&entry)).expect("store tail on home");
    entry
}

/// Asserts that `result`, a store and then a fold on the adopting vault,
/// asked for the history, for `reason`. A batch of grants alone that only
/// the history folds is kept as pending evidence, and its store asks for the
/// history itself; any other batch is stored, and its fold asks.
fn asks_history<T: std::fmt::Debug>(
    result: oneiron::error::Result<T>,
    reason: AuthorityHistoryReason,
) {
    let err = result.expect_err("adopting needs history");
    assert!(
        matches!(
            &err,
            Error::Record(RecordError::AuthorityHistoryRequired { reason: asked, .. })
                if *asked == Some(reason)
        ),
        "history required for {reason:?}, got {err:?}"
    );
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

/// The image `vault` writes now as `issuer`'s host root.
fn written_image(vault: &Vault, issuer: &HostSlipIssuer) -> AuthorityCheckpointV2 {
    let head = vault
        .write_authority_checkpoint_v2(issuer)
        .expect("write image");
    vault
        .authority_checkpoint_v2(&head)
        .expect("read image")
        .expect("image some")
}

#[test]
fn successor_image_past_a_rejected_owner_enrollment_keeps_the_whole_history_issuers() {
    let fixture = fixture();
    let device = fresh_device(0x55, ROLE_OWNER);
    let key = device.key.clone();
    sign_and_share(&fixture, AuthorityOp::EnrollDevice { device });
    // Home's image over its whole history, and the image the adopting vault
    // builds past its adopted one, over the same rows.
    let home_issuers = oneiron::test_doors::foldpast::image_slip_issuers(&written_image(
        &fixture.home,
        &fixture.issuer,
    ));
    assert!(
        home_issuers.contains(&key),
        "home's consent structure admits the enrolled owner key its fold rejects"
    );
    let successor = written_image(&fixture.adopting, &fixture.issuer);
    assert_eq!(
        oneiron::test_doors::foldpast::image_slip_issuers(&successor),
        home_issuers,
        "the successor image keeps home's slip issuers"
    );
}

/// Home rooted with one agent row and two concurrent agent rows on it, all
/// stored, with the sequence past both and their hashes, sorted: the heads a
/// join of both names.
struct ConcurrentHome {
    home: Vault,
    issuer: HostSlipIssuer,
    home_dir: tempfile::TempDir,
    next_seq: u64,
    heads: Vec<[u8; 32]>,
}

/// Roots home and stores two concurrent agent rows on its agent row.
fn concurrent_home() -> ConcurrentHome {
    let (home, issuer, home_dir) = root_home();
    let first = sign_next_host_op(
        &home,
        &issuer,
        AuthorityOp::EnrollDevice {
            device: fresh_device(0x56, ROLE_AGENT),
        },
    )
    .expect("sign first");
    let second = oneiron::test_doors::foldpast::sign_host_op_at(
        &home,
        &issuer,
        AuthorityOp::EnrollDevice {
            device: fresh_device(0x57, ROLE_AGENT),
        },
        first.seq + 1,
        first.parent_hashes.clone(),
    )
    .expect("sign second");
    let mut heads = vec![
        authority_entry_hash(&first).expect("first hash"),
        authority_entry_hash(&second).expect("second hash"),
    ];
    heads.sort_unstable();
    let next_seq = first.seq + 2;
    put_signed_entries(&home, &[first, second]).expect("store the concurrent rows");
    ConcurrentHome {
        home,
        issuer,
        home_dir,
        next_seq,
        heads,
    }
}

/// A world's side join of `heads` that the host root signs at `seq` for an
/// install: a side row the fold rejects.
fn rejected_side_join(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    seq: u64,
    heads: Vec<[u8; 32]>,
) -> AuthorityLogEntry {
    oneiron::test_doors::foldpast::sign_host_op_at(
        vault,
        issuer,
        oneiron::test_doors::foldpast::world_frontier_join_op(EntityId::now(), EntityId::now()),
        seq,
        heads,
    )
    .expect("sign side join")
}

/// Asserts that both folds reject `enrollment`, an owner enrollment of `key`
/// the host root signed on a world's side row, that home's image over its
/// whole history leaves `key` out of its slip issuers, and that the adopting
/// vault's successor image keeps home's issuers.
fn assert_successor_keeps_home_issuers(
    fixture: &Fixture,
    enrollment: &AuthorityLogEntry,
    key: &AuthorityKey,
) {
    let hash = authority_entry_hash(enrollment).expect("enrollment hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds tail");
    assert!(
        !home_fold.valid_entries.contains(&hash),
        "home judges no row off another world's side row"
    );
    assert!(
        !adopting_fold.valid_entries.contains(&hash),
        "adopting judges no row off another world's side row"
    );
    let home_issuers = oneiron::test_doors::foldpast::image_slip_issuers(&written_image(
        &fixture.home,
        &fixture.issuer,
    ));
    assert!(
        !home_issuers.contains(key),
        "home's consent structure reads only the rows its fold judges"
    );
    let successor = written_image(&fixture.adopting, &fixture.issuer);
    assert_eq!(
        oneiron::test_doors::foldpast::image_slip_issuers(&successor),
        home_issuers,
        "the successor image keeps home's slip issuers"
    );
}

#[test]
fn successor_image_past_an_owner_enrollment_off_a_world_side_row_keeps_the_whole_history_issuers() {
    let ConcurrentHome {
        home,
        issuer,
        home_dir,
        next_seq,
        heads,
    } = concurrent_home();
    let (adopting, adopt_dir) = checkpoint_and_adopt(&home, &issuer);
    let fixture = Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    };
    // A tail of a world's side join of the image's frontier and an owner
    // enrollment the host root signs on it: a main-log row that hangs off a
    // world's side row.
    let side = rejected_side_join(&fixture.home, &fixture.issuer, next_seq, heads);
    let device = fresh_device(0x59, ROLE_OWNER);
    let key = device.key.clone();
    let enrollment = oneiron::test_doors::foldpast::sign_host_op_at(
        &fixture.home,
        &fixture.issuer,
        AuthorityOp::EnrollDevice { device },
        next_seq + 1,
        vec![authority_entry_hash(&side).expect("side hash")],
    )
    .expect("sign enrollment");
    let tail = [side, enrollment.clone()];
    put_signed_entries(&fixture.home, &tail).expect("store tail on home");
    put_signed_entries(&fixture.adopting, &tail).expect("store tail on adopting");
    assert_successor_keeps_home_issuers(&fixture, &enrollment, &key);
}

#[test]
fn successor_image_past_a_covered_owner_enrollment_off_a_world_side_row_keeps_the_whole_history_issuers()
 {
    let ConcurrentHome {
        home,
        issuer,
        home_dir,
        next_seq,
        heads,
    } = concurrent_home();
    // Covered: a world's side join, an owner enrollment the host root signs
    // on it (a main-log row off a world's side row, which the image carries
    // whole), and a main agent row beside them. The image keeps the issues.
    let side = rejected_side_join(&home, &issuer, next_seq, heads.clone());
    let device = fresh_device(0x5a, ROLE_OWNER);
    let key = device.key.clone();
    let enrollment = oneiron::test_doors::foldpast::sign_host_op_at(
        &home,
        &issuer,
        AuthorityOp::EnrollDevice { device },
        next_seq + 1,
        vec![authority_entry_hash(&side).expect("side hash")],
    )
    .expect("sign enrollment");
    let main = oneiron::test_doors::foldpast::sign_host_op_at(
        &home,
        &issuer,
        AuthorityOp::EnrollDevice {
            device: fresh_device(0x5b, ROLE_AGENT),
        },
        next_seq + 2,
        heads,
    )
    .expect("sign main row");
    put_signed_entries(&home, &[side, enrollment.clone(), main.clone()])
        .expect("store the covered rows");
    let head = home
        .write_authority_checkpoint_v2(&issuer)
        .expect("write image");
    let image = home
        .authority_checkpoint_v2(&head)
        .expect("read image")
        .expect("image some");
    assert!(
        !image.fold().issues.is_empty(),
        "the image keeps its issues"
    );
    let (adopting, adopt_dir) = adopt_image(&home, &head, &image);
    let fixture = Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    };
    // An agent enrollment on the main row, a kind that folds past any image.
    let tail = oneiron::test_doors::foldpast::sign_host_op_at(
        &fixture.home,
        &fixture.issuer,
        AuthorityOp::EnrollDevice {
            device: fresh_device(0x5c, ROLE_AGENT),
        },
        next_seq + 3,
        vec![authority_entry_hash(&main).expect("main hash")],
    )
    .expect("sign tail");
    put_signed_entries(&fixture.home, std::slice::from_ref(&tail)).expect("store tail on home");
    put_signed_entries(&fixture.adopting, std::slice::from_ref(&tail))
        .expect("store tail on adopting");
    let hash = authority_entry_hash(&tail).expect("tail hash");
    assert!(
        fixture
            .adopting
            .authority_fold()
            .expect("adopting folds tail")
            .valid_entries
            .contains(&hash),
        "the agent enrollment folds past the image"
    );
    assert_successor_keeps_home_issuers(&fixture, &enrollment, &key);
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
    // The serial row's tail folds whole, and the rotation folds rejected.
    asks_history(
        fixture.adopting.authority_fold(),
        AuthorityHistoryReason::RejectedRowCrossed,
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
    asks_history(
        fixture.adopting.authority_fold(),
        AuthorityHistoryReason::StaleRosterWindow,
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
fn binding_an_actor_a_covered_row_bound_folds_and_matches_home() {
    let (fixture, _, unbound_key, actor) = binding_fixture();
    let tail = sign_and_share(&fixture, agent_binding(&unbound_key, actor));
    let hash = authority_entry_hash(&tail).expect("tail hash");
    let home_fold = fixture.home.authority_fold().expect("home folds tail");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds tail");
    for (vault, fold) in [("home", &home_fold), ("adopting", &adopting_fold)] {
        assert!(
            fold.valid_entries.contains(&hash),
            "{vault} accepts a second key's binding of the same actor"
        );
    }
    assert_bindings_match(&home_fold, &adopting_fold);
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
    asks_history(
        fixture.adopting.authority_fold(),
        AuthorityHistoryReason::StaleRosterWindow,
    );
}

#[test]
fn stored_covered_row_with_no_receipt_is_corruption_past_an_image() {
    let fixture = fixture();
    // A row the adopter stores past its image, which a newer image covers.
    let enroll = sign_and_share(
        &fixture,
        AuthorityOp::EnrollDevice {
            device: fresh_device(0x56, ROLE_AGENT),
        },
    );
    let hash = authority_entry_hash(&enroll).expect("enroll hash");
    fixture
        .adopting
        .authority_fold()
        .expect("adopting folds the enrollment");
    adopt_newer_image(&fixture.home, &fixture.issuer, &fixture.adopting);
    assert!(
        forget_first_seen_receipt(&fixture.adopting, &hash).expect("forget the receipt"),
        "the adopter kept its own receipt of the row it stored"
    );
    // A later second: the fold reads the sidecar again.
    fixture
        .adopting
        .advance_authority_clock_for_test(fixture.adopting.now_recorded_at() + 60)
        .expect("advance the clock");
    let err = fixture
        .adopting
        .authority_fold()
        .expect_err("a stored row's lost receipt is corruption");
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "corruption, as the whole-history read finds it, got {err:?}"
    );
}

#[test]
fn slip_burn_below_a_rejected_tail_row_still_needs_history() {
    let (fixture, covered) = burn_fixture();
    let reused = AuthorityConfirmAction {
        nonce: [0xD4; 16],
        ..covered
    };
    let rejected = sign_on_home(&fixture, AuthorityOp::FederationConfirm(reused));
    let rejected_hash = authority_entry_hash(&rejected).expect("rejected hash");
    // A rejected row is no head, so the burn names it as its parent by hand,
    // one sequence past it.
    let burn = oneiron::test_doors::foldpast::sign_host_op_at(
        &fixture.home,
        &fixture.issuer,
        AuthorityOp::SlipConsume {
            slip_id: BURNED_SLIP,
        },
        rejected.seq + 1,
        vec![rejected_hash],
    )
    .expect("sign the burn on the rejected confirm");
    put_signed_entries(&fixture.home, std::slice::from_ref(&burn)).expect("store burn on home");
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
    // One batch: a burn is no grant, so the adopter stores both rows and its
    // fold asks for the history.
    asks_history(
        put_signed_entries(&fixture.adopting, &[rejected, burn])
            .and_then(|()| fixture.adopting.authority_fold()),
        AuthorityHistoryReason::RejectedRowCrossed,
    );
}

/// The host issuer a re-root hands the vault to.
fn successor_issuer(secret: &[u8]) -> HostSlipIssuer {
    HostSlipIssuer::from_secret(secret).expect("successor issuer")
}

/// A re-root handing the vault to `successor`'s key, as owner and admin.
fn re_root_to(successor: &HostSlipIssuer) -> AuthorityOp {
    AuthorityOp::ReRoot {
        new_device: DeviceAuthority {
            key: successor.public_key(),
            transport_key_binding: successor.binding_key(),
            attestation: AuthorityAttestation {
                kind: "SoftwareArgon2id".into(),
                evidence: Vec::new(),
            },
            tier: AuthorityTier::Software,
            roles: ROLE_OWNER | ROLE_ADMIN,
        },
    }
}

#[test]
fn re_root_past_an_adopted_image_folds_and_matches_home() {
    let fixture = fixture();
    let successor = successor_issuer(b"foldpast-test-successor-secret");
    let handoff = sign_and_share(&fixture, re_root_to(&successor));
    let hash = authority_entry_hash(&handoff).expect("re-root hash");
    let home_fold = fixture.home.authority_fold().expect("home folds re-root");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds re-root");
    for (vault, fold) in [("home", &home_fold), ("adopting", &adopting_fold)] {
        assert!(
            fold.valid_entries.contains(&hash),
            "{vault} counts the re-root"
        );
        assert!(
            fold.retired_keys.contains(&fixture.issuer.public_key()),
            "{vault} retires the old root"
        );
        assert!(
            fold.retired_keys.contains(&agent_key()),
            "{vault} retires every key the old roster held"
        );
        assert!(
            fold.roster
                .get(&successor.public_key())
                .is_some_and(|device| !device.revoked),
            "{vault} installs the successor"
        );
    }
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    assert_eq!(
        adopting_fold.retired_keys, home_fold.retired_keys,
        "retired keys match"
    );
    assert_eq!(
        adopting_fold.federation_pacts, home_fold.federation_pacts,
        "pacts match"
    );
    assert_eq!(adopting_fold.slips, home_fold.slips, "slips match");
    // The successor's own row past the re-root folds on both.
    let enroll = sign_next_host_op(
        &fixture.home,
        &successor,
        AuthorityOp::EnrollDevice {
            device: fresh_device(0x54, ROLE_AGENT),
        },
    )
    .expect("sign as the successor");
    let enroll_hash = authority_entry_hash(&enroll).expect("enroll hash");
    put_signed_entries(&fixture.home, std::slice::from_ref(&enroll)).expect("store on home");
    put_signed_entries(&fixture.adopting, std::slice::from_ref(&enroll))
        .expect("store on adopting");
    let home_fold = fixture.home.authority_fold().expect("home folds enroll");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds enroll");
    for (vault, fold) in [("home", &home_fold), ("adopting", &adopting_fold)] {
        assert!(
            fold.valid_entries.contains(&enroll_hash),
            "{vault} counts the successor's enrollment"
        );
    }
    assert_eq!(
        adopting_fold.roster, home_fold.roster,
        "rosters still match"
    );
    assert_eq!(
        adopting_fold.retired_keys, home_fold.retired_keys,
        "retired keys still match"
    );
}

#[test]
fn covered_approval_on_a_re_rooted_key_lapses_on_the_adoption_clock() {
    let (fixture, confirm) = cosigned_confirm_fixture();
    let successor = successor_issuer(b"foldpast-test-successor-secret");
    let handoff = sign_and_share(&fixture, re_root_to(&successor));
    let hash = authority_entry_hash(&handoff).expect("re-root hash");
    let home_fold = fixture.home.authority_fold().expect("home folds re-root");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds re-root");
    assert!(
        adopting_fold.valid_entries.contains(&hash),
        "adopting counts the re-root"
    );
    assert_eq!(adopting_fold.roster, home_fold.roster, "rosters match");
    // Inside the window each vault still counts the approval resting on
    // the keys the re-root retired: home from its own first sight, the
    // adopter from its adoption of the image.
    assert!(
        home_fold.valid_entries.contains(&confirm),
        "home counts the approval inside its window"
    );
    assert!(
        adopting_fold.valid_entries.contains(&confirm),
        "adopting counts the approval inside the adoption's window"
    );
    // Past min(first seen, re-root first seen) + window + 1 on each vault's
    // own clock, the approval lapses on both.
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
            fold.valid_entries.contains(&hash),
            "{name} still counts the re-root"
        );
    }
}

#[test]
fn old_root_row_beside_a_re_root_still_needs_history() {
    let fixture = fixture();
    let successor = successor_issuer(b"foldpast-test-successor-secret");
    // Both on the image's frontier: the old root's confirm at its next
    // sequence, the re-root one past it.
    let beside = sign_next_host_op(
        &fixture.home,
        &fixture.issuer,
        AuthorityOp::FederationConfirm(fresh_confirm(0xE7)),
    )
    .expect("sign the old root's row");
    let handoff = sign_host_op_beside_next(&fixture.home, &fixture.issuer, re_root_to(&successor))
        .expect("sign the re-root beside it");
    assert_eq!(
        beside.parent_hashes, handoff.parent_hashes,
        "the two rows stand side by side"
    );
    let beside_hash = authority_entry_hash(&beside).expect("beside hash");
    let hash = authority_entry_hash(&handoff).expect("re-root hash");
    for vault in [&fixture.home, &fixture.adopting] {
        put_signed_entries(vault, std::slice::from_ref(&beside)).expect("store the old root's row");
    }
    put_signed_entries(&fixture.home, std::slice::from_ref(&handoff)).expect("store on home");
    let home_fold = fixture.home.authority_fold().expect("home folds re-root");
    assert!(
        home_fold.valid_entries.contains(&hash),
        "home settles the re-root"
    );
    assert!(
        !home_fold.valid_entries.contains(&beside_hash),
        "home drops the old root's row beside it"
    );
    assert!(
        home_fold
            .issues
            .contains(&AuthorityFoldIssue::RetiredSigner(beside_hash)),
        "home drops it as signed by a retired key"
    );
    asks_history(
        put_signed_entries(&fixture.adopting, std::slice::from_ref(&handoff))
            .and_then(|()| fixture.adopting.authority_fold()),
        AuthorityHistoryReason::HandoffFence,
    );
}

#[test]
fn two_re_roots_in_one_tail_still_need_history() {
    let fixture = fixture();
    let first = sign_next_host_op(
        &fixture.home,
        &fixture.issuer,
        re_root_to(&successor_issuer(b"foldpast-test-successor-secret")),
    )
    .expect("sign the first re-root");
    let second = sign_host_op_beside_next(
        &fixture.home,
        &fixture.issuer,
        re_root_to(&successor_issuer(b"foldpast-test-second-successor")),
    )
    .expect("sign the second re-root");
    let (first_hash, second_hash) = (
        authority_entry_hash(&first).expect("first hash"),
        authority_entry_hash(&second).expect("second hash"),
    );
    let both = [first, second];
    put_signed_entries(&fixture.home, &both).expect("store both on home");
    let home_fold = fixture.home.authority_fold().expect("home folds both");
    for hash in [first_hash, second_hash] {
        assert!(
            !home_fold.valid_entries.contains(&hash),
            "home settles neither re-root alone"
        );
        assert!(
            home_fold
                .issues
                .contains(&AuthorityFoldIssue::UnsettledHandoff(hash)),
            "home holds the two in conflict"
        );
    }
    asks_history(
        put_signed_entries(&fixture.adopting, &both)
            .and_then(|()| fixture.adopting.authority_fold()),
        AuthorityHistoryReason::OpNotFoldedPast,
    );
}

#[test]
fn successor_image_past_a_re_root_keeps_the_whole_history_issuers() {
    let fixture = fixture();
    let successor = successor_issuer(b"foldpast-test-successor-secret");
    sign_and_share(&fixture, re_root_to(&successor));
    // Home's image over its whole history, and the image the adopting vault
    // builds past its adopted one, over the same rows, both as the successor
    // root.
    let home_issuers = oneiron::test_doors::foldpast::image_slip_issuers(&written_image(
        &fixture.home,
        &successor,
    ));
    assert!(
        home_issuers.contains(&successor.public_key()),
        "home's consent structure admits the successor root"
    );
    let adopted = written_image(&fixture.adopting, &successor);
    assert_eq!(
        oneiron::test_doors::foldpast::image_slip_issuers(&adopted),
        home_issuers,
        "the successor image keeps home's slip issuers"
    );
}

#[test]
fn successor_image_past_a_re_root_keeps_its_retired_keys() {
    let fixture = fixture();
    let successor = successor_issuer(b"foldpast-test-successor-secret");
    let handoff = sign_and_share(&fixture, re_root_to(&successor));
    let hash = authority_entry_hash(&handoff).expect("re-root hash");
    let home_fold = fixture.home.authority_fold().expect("home folds re-root");
    // A newer image the successor root builds on the adopting vault, past
    // its adopted image, and an empty adopter of that newer image.
    let (readopting, _readopt_dir) = checkpoint_and_adopt(&fixture.adopting, &successor);
    let fold = readopting
        .authority_fold()
        .expect("the newer image projects");
    assert!(
        fold.valid_entries.contains(&hash),
        "the newer image covers the re-root"
    );
    assert!(
        fold.retired_keys.contains(&fixture.issuer.public_key()),
        "the newer image keeps the old root retired"
    );
    assert_eq!(
        fold.retired_keys, home_fold.retired_keys,
        "retired keys match home's"
    );
    assert_eq!(fold.roster, home_fold.roster, "rosters match home's");
}

/// Asserts that the adopting vault's fold holds home's actor bindings,
/// their write frontiers and revocations, roster and slips.
fn assert_bindings_match(
    home: &oneiron::authority::AuthorityFold,
    adopting: &oneiron::authority::AuthorityFold,
) {
    assert_eq!(
        adopting.actor_bindings, home.actor_bindings,
        "bindings match"
    );
    assert_eq!(
        adopting.actor_write_frontiers, home.actor_write_frontiers,
        "write frontiers match"
    );
    assert_eq!(
        adopting.revoked_actor_keys, home.revoked_actor_keys,
        "revoked actor keys match"
    );
    assert_eq!(
        adopting.actor_revocation_affected_writers, home.actor_revocation_affected_writers,
        "revocation-affected writers match"
    );
    assert_eq!(adopting.roster, home.roster, "rosters match");
    assert_eq!(adopting.slips, home.slips, "slips match");
}

/// The rebinding of `key` to `actor` at `epoch`.
fn agent_rebinding(key: &AuthorityKey, actor: EntityId, epoch: u64) -> AuthorityOp {
    AuthorityOp::RebindActor {
        authority_key: key.clone(),
        actor_ref: actor,
        actor_class: "agent".to_owned(),
        epoch,
    }
}

/// Asserts that `fold` binds `key` live to `actor`, with `hash` among the
/// key's write frontiers.
fn binds_live(
    fold: &oneiron::authority::AuthorityFold,
    key: &AuthorityKey,
    actor: EntityId,
    hash: &[u8; 32],
) {
    let binding = fold.actor_bindings.get(key).expect("the key's binding");
    assert_eq!(binding.actor_ref, actor, "bound to the tail's actor");
    assert_eq!(
        binding.status,
        oneiron::authority::ActorBindingStatus::Active,
        "the binding is live"
    );
    assert!(
        fold.actor_write_frontiers
            .get(key)
            .is_some_and(|frontiers| frontiers.contains(hash)),
        "the tail row is a write frontier of the key"
    );
}

#[test]
fn rebinding_a_covered_bound_key_folds_and_matches_home() {
    let (fixture, bound_key, _, _) = binding_fixture();
    let actor = EntityId::now();
    let tail = sign_and_share(&fixture, agent_rebinding(&bound_key, actor, 2));
    let hash = authority_entry_hash(&tail).expect("rebinding hash");
    let home_fold = fixture.home.authority_fold().expect("home folds rebinding");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds rebinding");
    for fold in [&home_fold, &adopting_fold] {
        assert!(fold.valid_entries.contains(&hash), "the rebinding is valid");
        binds_live(fold, &bound_key, actor, &hash);
    }
    assert_bindings_match(&home_fold, &adopting_fold);
}

#[test]
fn binding_a_covered_revoked_key_again_folds_and_matches_home() {
    let (fixture, bound_key, _, _) = binding_fixture_then(|key, _| {
        vec![AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        }]
    });
    let actor = EntityId::now();
    let tail = sign_and_share(
        &fixture,
        AuthorityOp::BindActor {
            authority_key: bound_key.clone(),
            actor_ref: actor,
            actor_class: "agent".to_owned(),
            epoch: 2,
        },
    );
    let hash = authority_entry_hash(&tail).expect("binding hash");
    let home_fold = fixture.home.authority_fold().expect("home folds binding");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds binding");
    for fold in [&home_fold, &adopting_fold] {
        assert!(
            fold.valid_entries.contains(&hash),
            "the new binding is valid"
        );
        binds_live(fold, &bound_key, actor, &hash);
    }
    assert_bindings_match(&home_fold, &adopting_fold);
}

#[test]
fn actor_revocation_beside_a_rebinding_still_revokes_the_key() {
    let (fixture, bound_key, _, _) = binding_fixture();
    let rebinding = sign_next_host_op(
        &fixture.home,
        &fixture.issuer,
        agent_rebinding(&bound_key, EntityId::now(), 2),
    )
    .expect("sign the rebinding");
    let revocation = sign_host_op_beside_next(
        &fixture.home,
        &fixture.issuer,
        AuthorityOp::RevokeActor {
            authority_key: bound_key.clone(),
            epoch: 1,
        },
    )
    .expect("sign the revocation beside it");
    let hashes = [
        authority_entry_hash(&rebinding).expect("rebinding hash"),
        authority_entry_hash(&revocation).expect("revocation hash"),
    ];
    let both = [rebinding, revocation];
    put_signed_entries(&fixture.home, &both).expect("store both on home");
    put_signed_entries(&fixture.adopting, &both).expect("store both on adopting");
    let home_fold = fixture.home.authority_fold().expect("home folds both");
    let adopting_fold = fixture
        .adopting
        .authority_fold()
        .expect("adopting folds both");
    for (vault, fold) in [("home", &home_fold), ("adopting", &adopting_fold)] {
        for hash in &hashes {
            assert!(
                fold.valid_entries.contains(hash),
                "{vault} counts both rows"
            );
        }
        assert_eq!(
            fold.actor_bindings
                .get(&bound_key)
                .expect("the key's binding")
                .status,
            oneiron::authority::ActorBindingStatus::Revoked,
            "{vault} holds the key revoked: the rebinding never saw the revocation"
        );
        assert!(
            fold.revoked_actor_keys.contains(&bound_key),
            "{vault} lists the key revoked"
        );
    }
    assert_bindings_match(&home_fold, &adopting_fold);
}

#[test]
fn rebinding_a_key_back_to_a_covered_actor_still_needs_history() {
    let (fixture, bound_key, _, actor) =
        binding_fixture_then(|key, _| vec![agent_rebinding(key, EntityId::now(), 2)]);
    let tail = sign_on_home(&fixture, agent_rebinding(&bound_key, actor, 3));
    let hash = authority_entry_hash(&tail).expect("rebinding hash");
    let home_fold = fixture.home.authority_fold().expect("home folds rebinding");
    binds_live(&home_fold, &bound_key, actor, &hash);
    assert!(
        names_a_covered_frontier(&home_fold, &bound_key, &hash),
        "home's frontiers of the key name a covered row, the first binding"
    );
    asks_history(
        put_signed_entries(&fixture.adopting, std::slice::from_ref(&tail))
            .and_then(|()| fixture.adopting.authority_fold()),
        AuthorityHistoryReason::UnsettledMove,
    );
}

#[test]
fn rebinding_back_past_a_successor_image_still_needs_history() {
    let (fixture, bound_key, _, actor) = binding_fixture();
    sign_and_share(&fixture, agent_rebinding(&bound_key, EntityId::now(), 2));
    // A newer image built on the adopting vault, past its adopted image,
    // and an empty adopter of that newer image: the first binding, which
    // only the older image covered, is still a write frontier for a
    // rebinding back to its actor.
    let (readopting, _readopt_dir) = checkpoint_and_adopt(&fixture.adopting, &fixture.issuer);
    let tail = sign_on_home(&fixture, agent_rebinding(&bound_key, actor, 3));
    let hash = authority_entry_hash(&tail).expect("rebinding hash");
    let home_fold = fixture.home.authority_fold().expect("home folds rebinding");
    binds_live(&home_fold, &bound_key, actor, &hash);
    assert!(
        names_a_covered_frontier(&home_fold, &bound_key, &hash),
        "home's frontiers of the key name a covered row, the first binding"
    );
    asks_history(
        put_signed_entries(&readopting, std::slice::from_ref(&tail))
            .and_then(|()| readopting.authority_fold()),
        AuthorityHistoryReason::UnsettledMove,
    );
}

/// Whether `fold`'s write frontiers of `key` name a row other than the tail
/// row `hash`.
fn names_a_covered_frontier(
    fold: &oneiron::authority::AuthorityFold,
    key: &AuthorityKey,
    hash: &[u8; 32],
) -> bool {
    fold.actor_write_frontiers
        .get(key)
        .is_some_and(|frontiers| frontiers.iter().any(|frontier| frontier != hash))
}

/// An owned machine's role, as its owner answers "yours".
const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);

/// Home with a machine's roster revisions covered, its adopter, the
/// machine, its install key and the owner its profiles name.
struct MachineHome {
    fixture: Fixture,
    machine: EntityId,
    key: SigningKey,
    owner: EntityId,
}

impl MachineHome {
    /// The machine's roster revision `revision` in `role`.
    fn profile(&self, role: MachineRole, revision: u64) -> AuthorityOp {
        machine_profile(
            &self.fixture.home,
            self.machine,
            self.owner,
            &self.key,
            role,
            revision,
        )
    }
}

/// A machine profile with no owner act: `machine`'s revision `revision` in
/// `role` for `owner`, which `key`, its install key, proves for `home`'s
/// vault.
fn machine_profile(
    home: &Vault,
    machine: EntityId,
    owner: EntityId,
    key: &SigningKey,
    role: MachineRole,
    revision: u64,
) -> AuthorityOp {
    let vault_id = home
        .authority_fold()
        .expect("home folds")
        .vault_id
        .expect("home's vault id");
    let machine_key = key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = key
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            device_class,
            &encryption_key,
        ))
        .to_bytes();
    AuthorityOp::MachineProfile(MachineProfile {
        machine,
        owner,
        machine_key,
        device_class,
        encryption_key,
        role,
        revision,
        machine_proof,
        seen_world_edits: std::collections::BTreeSet::new(),
        carrier: None,
        act: None,
    })
}

/// Home with one machine whose roster revisions 1, 2, ... take `roles`,
/// each signed by the host root and covered, and its adopter.
fn machine_fixture(roles: &[MachineRole]) -> MachineHome {
    let (home, issuer, home_dir) = root_home();
    let machine = EntityId::now();
    let owner = EntityId::now();
    let key = SigningKey::from_bytes(&[0x71; 32]);
    for (revision, role) in (1..).zip(roles) {
        let op = machine_profile(&home, machine, owner, &key, *role, revision);
        let entry = sign_next_host_op(&home, &issuer, op).expect("sign covered profile");
        let hash = authority_entry_hash(&entry).expect("covered profile hash");
        put_signed_entries(&home, &[entry]).expect("store covered profile");
        assert!(
            home.authority_fold()
                .expect("home folds covered profile")
                .valid_entries
                .contains(&hash),
            "every covered profile folds valid, so the image is clean"
        );
    }
    let (adopting, adopt_dir) = checkpoint_and_adopt(&home, &issuer);
    MachineHome {
        fixture: Fixture {
            home,
            adopting,
            issuer,
            _home_dir: home_dir,
            _adopt_dir: adopt_dir,
        },
        machine,
        key,
        owner,
    }
}

/// Asserts that `fold` holds the profile `hash` valid at the head of
/// `machine`'s roster chain, removed when `removed`.
fn heads_roster(
    fold: &oneiron::authority::AuthorityFold,
    machine: EntityId,
    hash: &[u8; 32],
    removed: bool,
) {
    assert!(fold.valid_entries.contains(hash), "the profile folds valid");
    let roster = fold
        .machines
        .get(&machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("the machine's roster revision");
    assert_eq!(&roster.entry, hash, "the profile heads the roster chain");
    assert_eq!(roster.removed, removed, "the machine is removed or not");
}

/// Asserts that the adopting vault's fold holds home's machines and roster.
fn assert_machines_match(
    home: &oneiron::authority::AuthorityFold,
    adopting: &oneiron::authority::AuthorityFold,
) {
    assert_eq!(adopting.machines, home.machines, "machines match");
    assert_eq!(adopting.roster, home.roster, "rosters match");
}

/// Asserts that home's image over its whole history keeps the tail
/// profile `hash` as a roster mark, and as a restrictive fact exactly when
/// it is a removal, and that the adopting vault's successor image keeps
/// home's marks, facts and slip issuers.
fn assert_successor_keeps_home_machine_safety(fixture: &Fixture, hash: &[u8; 32], removal: bool) {
    use oneiron::test_doors::foldpast::{
        image_revoke_fact_rows, image_roster_marks, image_slip_issuers,
    };
    let home_image = written_image(&fixture.home, &fixture.issuer);
    let home_marks = image_roster_marks(&home_image);
    assert!(
        home_marks.contains(hash),
        "home's image keeps the tail profile's mark"
    );
    let home_facts = image_revoke_fact_rows(&home_image);
    assert_eq!(
        home_facts.contains(hash),
        removal,
        "home's image proves a fact for a removal alone"
    );
    let successor = written_image(&fixture.adopting, &fixture.issuer);
    assert_eq!(
        image_roster_marks(&successor),
        home_marks,
        "the successor image keeps home's roster marks"
    );
    assert_eq!(
        image_revoke_fact_rows(&successor),
        home_facts,
        "the successor image keeps home's restrictive facts"
    );
    assert_eq!(
        image_slip_issuers(&successor),
        image_slip_issuers(&home_image),
        "the successor image keeps home's slip issuers"
    );
}

#[test]
fn machine_revision_past_an_adopted_image_folds_and_matches_home() {
    let home = machine_fixture(&[YOURS]);
    let tail = sign_and_share(
        &home.fixture,
        home.profile(MachineRole::Owned(MachineOwnership::WorkSchool), 2),
    );
    let hash = authority_entry_hash(&tail).expect("revision hash");
    let home_fold = home
        .fixture
        .home
        .authority_fold()
        .expect("home folds revision");
    let adopting_fold = home
        .fixture
        .adopting
        .authority_fold()
        .expect("adopting folds revision");
    heads_roster(&home_fold, home.machine, &hash, false);
    heads_roster(&adopting_fold, home.machine, &hash, false);
    assert_machines_match(&home_fold, &adopting_fold);
    assert_successor_keeps_home_machine_safety(&home.fixture, &hash, false);
}

#[test]
fn machine_removal_past_an_adopted_image_folds_and_matches_home() {
    let home = machine_fixture(&[YOURS]);
    let tail = sign_and_share(&home.fixture, home.profile(MachineRole::Removed, 2));
    let hash = authority_entry_hash(&tail).expect("removal hash");
    let home_fold = home
        .fixture
        .home
        .authority_fold()
        .expect("home folds removal");
    let adopting_fold = home
        .fixture
        .adopting
        .authority_fold()
        .expect("adopting folds removal");
    heads_roster(&home_fold, home.machine, &hash, true);
    heads_roster(&adopting_fold, home.machine, &hash, true);
    assert_machines_match(&home_fold, &adopting_fold);
    assert_successor_keeps_home_machine_safety(&home.fixture, &hash, true);
}

#[test]
fn machine_revision_past_a_covered_removal_stays_removed() {
    let home = machine_fixture(&[YOURS, MachineRole::Removed]);
    let tail = sign_and_share(&home.fixture, home.profile(YOURS, 3));
    let hash = authority_entry_hash(&tail).expect("revision hash");
    let home_fold = home
        .fixture
        .home
        .authority_fold()
        .expect("home folds revision");
    let adopting_fold = home
        .fixture
        .adopting
        .authority_fold()
        .expect("adopting folds revision");
    heads_roster(&home_fold, home.machine, &hash, true);
    heads_roster(&adopting_fold, home.machine, &hash, true);
    assert_machines_match(&home_fold, &adopting_fold);
}

#[test]
fn machine_revision_then_removal_past_an_adopted_image_folds_and_matches_home() {
    let home = machine_fixture(&[YOURS]);
    let revision = sign_and_share(
        &home.fixture,
        home.profile(MachineRole::Owned(MachineOwnership::WorkSchool), 2),
    );
    let revision = authority_entry_hash(&revision).expect("revision hash");
    let removal = sign_and_share(&home.fixture, home.profile(MachineRole::Removed, 3));
    let removal = authority_entry_hash(&removal).expect("removal hash");
    let home_fold = home
        .fixture
        .home
        .authority_fold()
        .expect("home folds the two rows");
    let adopting_fold = home
        .fixture
        .adopting
        .authority_fold()
        .expect("adopting folds the two rows");
    // Two machine rows in one tail: it folds whole, and the removal heads
    // the roster chain over the revision it follows.
    assert!(
        home_fold.valid_entries.contains(&revision),
        "home folds the revision valid"
    );
    assert!(
        adopting_fold.valid_entries.contains(&revision),
        "adopting folds the revision valid"
    );
    heads_roster(&home_fold, home.machine, &removal, true);
    heads_roster(&adopting_fold, home.machine, &removal, true);
    assert_machines_match(&home_fold, &adopting_fold);
    assert_successor_keeps_home_machine_safety(&home.fixture, &removal, true);
}

#[test]
fn machine_revision_beside_a_covered_row_still_needs_history() {
    let ConcurrentHome {
        home,
        issuer,
        home_dir,
        next_seq,
        heads,
    } = concurrent_home();
    let (adopting, adopt_dir) = checkpoint_and_adopt(&home, &issuer);
    let fixture = Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    };
    // A machine's first revision on one of the image's two frontier rows:
    // the other covered row is beside it, not in its causal past.
    let op = machine_profile(
        &fixture.home,
        EntityId::now(),
        EntityId::now(),
        &SigningKey::from_bytes(&[0x72; 32]),
        YOURS,
        1,
    );
    let tail = oneiron::test_doors::foldpast::sign_host_op_at(
        &fixture.home,
        &fixture.issuer,
        op,
        next_seq,
        vec![heads[0]],
    )
    .expect("sign revision");
    let hash = authority_entry_hash(&tail).expect("revision hash");
    put_signed_entries(&fixture.home, std::slice::from_ref(&tail)).expect("store on home");
    assert!(
        fixture
            .home
            .authority_fold()
            .expect("home folds revision")
            .valid_entries
            .contains(&hash),
        "home folds the revision beside the other covered row"
    );
    asks_history(
        put_signed_entries(&fixture.adopting, std::slice::from_ref(&tail))
            .and_then(|()| fixture.adopting.authority_fold()),
        AuthorityHistoryReason::CoveredRowConcurrent,
    );
}

#[test]
fn machine_revision_by_a_non_owner_still_needs_history() {
    let home = machine_fixture(&[YOURS]);
    let tail = sign_next_op_as(&home.fixture.home, &agent_signing(), home.profile(YOURS, 2))
        .expect("sign agent revision");
    let hash = authority_entry_hash(&tail).expect("revision hash");
    put_signed_entries(&home.fixture.home, std::slice::from_ref(&tail)).expect("store on home");
    assert!(
        !home
            .fixture
            .home
            .authority_fold()
            .expect("home folds revision")
            .valid_entries
            .contains(&hash),
        "home rejects a revision no owner key signed"
    );
    // The adopter folds it rejected too, and a machine profile's tail folds
    // whole: only the whole history tells it.
    asks_history(
        put_signed_entries(&home.fixture.adopting, std::slice::from_ref(&tail))
            .and_then(|()| home.fixture.adopting.authority_fold()),
        AuthorityHistoryReason::RejectedRowCrossed,
    );
}

#[test]
fn tail_row_on_an_unheld_row_asks_for_that_row_alone() {
    let fixture = fixture();
    let first = sign_on_home(
        &fixture,
        AuthorityOp::FederationConfirm(fresh_confirm(0xF0)),
    );
    let second = sign_on_home(
        &fixture,
        AuthorityOp::FederationConfirm(fresh_confirm(0xF4)),
    );
    let first_hash = authority_entry_hash(&first).expect("first hash");
    assert_eq!(
        second.parent_hashes,
        vec![first_hash],
        "the second row stands on the first"
    );
    // The adopter stores the second row alone: its parent is no covered row,
    // and only a fetch of that row closes the request.
    let err = put_signed_entries(&fixture.adopting, std::slice::from_ref(&second))
        .and_then(|()| fixture.adopting.authority_fold())
        .expect_err("adopting needs the first row");
    assert!(
        matches!(
            &err,
            Error::Record(RecordError::AuthorityHistoryRequired {
                missing,
                reason: Some(AuthorityHistoryReason::UnheldRows),
                ..
            }) if *missing == vec![first_hash]
        ),
        "history required for the first row alone, got {err:?}"
    );
    put_signed_entries(&fixture.adopting, std::slice::from_ref(&first))
        .expect("store the named row");
    assert!(
        fixture
            .adopting
            .authority_fold()
            .expect("the fetched row closes the request")
            .valid_entries
            .contains(&first_hash),
        "the adopter folds the fetched row"
    );
}

#[test]
fn device_revocation_past_an_image_with_issues_still_needs_history() {
    let ConcurrentHome {
        home,
        issuer,
        home_dir,
        next_seq,
        heads,
    } = concurrent_home();
    // Covered: a world's side join the fold rejects, and a main agent row
    // beside it: the image covers a row its fold did not accept.
    let side = rejected_side_join(&home, &issuer, next_seq, heads.clone());
    let device = fresh_device(0x5d, ROLE_AGENT);
    let revoked_key = device.key.clone();
    let main = oneiron::test_doors::foldpast::sign_host_op_at(
        &home,
        &issuer,
        AuthorityOp::EnrollDevice { device },
        next_seq + 1,
        heads,
    )
    .expect("sign main row");
    put_signed_entries(&home, &[side, main.clone()]).expect("store the covered rows");
    let head = home
        .write_authority_checkpoint_v2(&issuer)
        .expect("write image");
    let image = home
        .authority_checkpoint_v2(&head)
        .expect("read image")
        .expect("image some");
    let image_fold = image.fold();
    assert!(
        image
            .covered
            .iter()
            .any(|hash| !image_fold.valid_entries.contains(hash)),
        "the image covers the rejected side join"
    );
    let (adopting, adopt_dir) = adopt_image(&home, &head, &image);
    let fixture = Fixture {
        home,
        adopting,
        issuer,
        _home_dir: home_dir,
        _adopt_dir: adopt_dir,
    };
    // A device revocation folds past only a clean image.
    let revoke = oneiron::test_doors::foldpast::sign_host_op_at(
        &fixture.home,
        &fixture.issuer,
        AuthorityOp::RevokeDevice { revoked_key },
        next_seq + 2,
        vec![authority_entry_hash(&main).expect("main hash")],
    )
    .expect("sign revocation");
    asks_history(
        put_signed_entries(&fixture.adopting, std::slice::from_ref(&revoke))
            .and_then(|()| fixture.adopting.authority_fold()),
        AuthorityHistoryReason::UncleanImage,
    );
}
