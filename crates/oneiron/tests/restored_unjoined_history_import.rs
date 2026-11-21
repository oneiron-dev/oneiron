//! Row [RESTORED-UNJOINED-ROUND2-TESTS] (parent row RESTORED-UNJOINED-STARTS-NO-WORK): the
//! round-2 history-import fix reads a fold that misses history it must hold as possibly not
//! joined, so an import into an unjoined copy stages instead of failing before staging, and its
//! post-staging checks still judge what lands.
//! - A full history import carrying the withheld parent stages it, the fold closes with both rows
//!   standing valid, and the held-work wake fires.
//! - A history page carrying the withheld parent does the same through the page door.
//!
//! On the red head (main with the two `possibly` calls switched back) each test fails at its
//! import's expect: the unjoined read folds the broken fold and errors before staging.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_unjoined_history_import`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::attempt_queue::AttemptQueue;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityCheckpointUnresolved, AuthorityEntryHash,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId,
    HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineRole, authority_entry_hash, authority_log_entity_id, authority_transcript,
    encode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::error::{Error, RecordError};
use oneiron::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::HomeCandidacy;

/// The vault's first install: rooted, with its owner bound, its own unanswered serving profile,
/// the vault's root held as its owner key, and the sending agent. It never restored, so it is
/// joined.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    vault_id: [u8; 32],
}

fn sender() -> EntityId {
    EntityId::from_bytes([0x61; 16]).expect("FIXTURE: the sender's id")
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
    vault
        .put_entity(
            &sender(),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"restored send sender",
        )
        .expect("FIXTURE: the sending agent");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        vault_id,
    }
}

/// The seed of the joining machine's machine key.
const JOINING_SEED: u8 = 68;
/// The joining machine's id.
const MACHINE_SEED: u8 = 0x76;
/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn signature_slot(key: AuthorityKey) -> AuthoritySignature {
    AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    }
}

/// `signer` alone signs `op` on `parent_hashes`.
fn signed(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        signer: signature_slot(key_of(signer)),
        cosigns: Vec::new(),
        ts: 1,
    };
    let transcript = authority_transcript(&row).expect("the transcript signs");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a row hashes")
}

/// Another machine's request to join the host's vault, under its own machine key and proof.
fn joining_machine_request(vault_id: AuthorityVaultId) -> MachineEnrolmentRequest {
    let machine = EntityId::from_bytes([MACHINE_SEED; 16]).expect("an id parses");
    let node = signing(JOINING_SEED);
    let machine_key = node.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = node
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            device_class,
            &encryption_key,
        ))
        .to_bytes();
    MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key,
        device_class,
        encryption_key,
        machine_proof,
        restored_from: None,
    }
}

/// The owner enrols the joining machine as his own, carried by the host install, and the request
/// it joined with.
fn enrol_joining_machine(host: &Host) -> MachineEnrolmentRequest {
    let owner = host
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the host owner");
    let proof = host
        .vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the host owner proof");
    let request = joining_machine_request(host.vault_id);
    host.vault
        .enroll_machine(
            &proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("FIXTURE: the owner enrols the joining machine");
    request
}

/// The host adopts its own checkpoint image over the public path: build, host-attest, pin, bundle,
/// adopt. The image covers the whole held log, so the tail past it starts empty.
fn adopt_own_checkpoint(host: &Host) {
    let vault = &host.vault;
    let built = vault
        .build_authority_checkpoint_v2()
        .expect("FIXTURE: the held log builds a checkpoint image");
    assert_eq!(
        built.unresolved,
        AuthorityCheckpointUnresolved::default(),
        "FIXTURE: a clean log's image holds nothing back, so the vault can adopt it"
    );
    let image = vault
        .write_authority_checkpoint_v2(&host.issuer)
        .expect("FIXTURE: the checkpoint image is kept");
    vault
        .host_attest_authority_checkpoint(&host.issuer, image)
        .expect("FIXTURE: the host root attests the image");
    let pin = vault
        .authority_checkpoint_pin([7; 32])
        .expect("FIXTURE: the pin reads")
        .expect("FIXTURE: the attested image pins");
    let bundle = vault
        .authority_checkpoint_bundle(&image)
        .expect("FIXTURE: the bundle reads")
        .expect("FIXTURE: the kept image bundles");
    vault
        .adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations)
        .expect("FIXTURE: the vault adopts its own image");
    assert!(
        vault
            .adopted_authority_checkpoint()
            .expect("FIXTURE: the adoption reads")
            .is_some(),
        "FIXTURE: the adoption stands"
    );
    assert!(
        vault.authority_fold().is_ok(),
        "FIXTURE: the adopted vault's fold reads before the gap"
    );
}

/// Delivers `entry` to `vault` through the replicated ingest door a sync peer's row takes: the
/// public explicit-tier replay, which runs the replicated authority validator and the store door.
fn deliver_via_replicated(vault: &Vault, entry: &AuthorityLogEntry) -> oneiron::Result<()> {
    let body = encode_authority_log_entry_body(entry).expect("the row encodes");
    let id = authority_log_entity_id(entry).expect("the row's content id");
    replay_entity(
        vault,
        ReplicatedEntity {
            id,
            entity_type: ENTITY_TYPE_AUTHORITY_LOG,
            occurred: AT,
            learned_at: 2,
            row_version: 0,
            body: &body,
        },
        ImportTier::OwnDevice,
    )
}

/// The fold needs the withheld `parent`: it errors history-required, naming it.
fn assert_fold_needs_history(vault: &Vault, parent: &AuthorityEntryHash) {
    match vault.authority_fold() {
        Err(Error::Record(RecordError::AuthorityHistoryRequired { missing, .. })) => {
            assert!(
                missing.contains(parent),
                "the fold names the withheld parent: {missing:?}"
            );
        }
        Err(error) => panic!("the fold needs history, got another error: {error:?}"),
        Ok(_) => panic!("the fold reads, but the withheld parent is missing"),
    }
}

/// The enrolled machine's home candidacy over a withheld parent: the parent stays with the test
/// while the child lands through replicated ingest, so the adopted fold needs the parent. The
/// parent's bytes and both rows' hashes.
fn break_fold_with_withheld_parent(
    host: &Host,
    request: &MachineEnrolmentRequest,
) -> (Vec<u8>, AuthorityEntryHash, AuthorityEntryHash) {
    let head = host
        .vault
        .authority_fold()
        .expect("FIXTURE: the fold reads for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("FIXTURE: the vault holds a valid row for the parent's parent");
    let signer = signing(JOINING_SEED);
    let declaration = HomeCandidacy {
        machine: request.machine,
        node_id: 1,
        always_on: false,
        primary: false,
        macro_ready: true,
        cloud: false,
    };
    let parent = signed(
        host.vault_id,
        1,
        vec![head],
        AuthorityOp::HomeCandidacy(declaration),
        &signer,
    );
    let parent_hash = hash(&parent);
    let parent_bytes =
        encode_authority_log_entry_body(&parent).expect("FIXTURE: the parent encodes");
    let child = signed(
        host.vault_id,
        2,
        vec![parent_hash],
        AuthorityOp::HomeCandidacy(declaration),
        &signer,
    );
    let child_hash = hash(&child);
    let child_id = authority_log_entity_id(&child).expect("FIXTURE: the child's content id");
    deliver_via_replicated(&host.vault, &child).expect("the child lands through replicated ingest");
    assert!(
        host.vault
            .get_authority_log_entry(&child_id)
            .expect("the child reads back")
            .is_some(),
        "FIXTURE: the child is stored with its parent missing"
    );
    assert_fold_needs_history(&host.vault, &parent_hash);
    (parent_bytes, parent_hash, child_hash)
}

/// The broken-fold setup: the adopted host with its gap, two copies restored from one image of
/// it (one per import door, since an import closes the gap), the withheld parent's bytes, and
/// both rows' hashes.
struct GapFixture {
    host: Host,
    copy_full: Vault,
    copy_page: Vault,
    parent_bytes: Vec<u8>,
    parent_hash: AuthorityEntryHash,
    child_hash: AuthorityEntryHash,
}

fn gap_fixture(backups: &Path) -> GapFixture {
    let host = rooted_host();
    let request = enrol_joining_machine(&host);
    adopt_own_checkpoint(&host);
    let (parent_bytes, parent_hash, child_hash) = break_fold_with_withheld_parent(&host, &request);
    let image = backups.join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("FIXTURE: the beside restore source");
    let restore_copy = |name: &str| {
        let (vault, _) = Vault::restore_checkpoint_beside(
            &image,
            &key,
            &backups.join(name),
            VaultConfig::device(),
            &origin,
            200,
        )
        .expect("FIXTURE: a copy of the image");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault
    };
    // No owner proof lands on the copies: the imports need none, and the enrolment request and
    // the machine-membership assert would both fold the broken fold.
    let copy_full = restore_copy("copy-full");
    let copy_page = restore_copy("copy-page");
    assert_fold_needs_history(&copy_full, &parent_hash);
    assert_fold_needs_history(&copy_page, &parent_hash);
    GapFixture {
        host,
        copy_full,
        copy_page,
        parent_bytes,
        parent_hash,
        child_hash,
    }
}

/// A history import into an unjoined copy with a broken fold stages instead of failing: the
/// round-2 full-door fix, whose import closes the gap and wakes the held work.
#[test]
fn a_history_import_into_an_unjoined_copy_repairs_its_fold() {
    let backups = oneiron::test_support::restore_tempdir();
    let fixture = gap_fixture(backups.path());
    assert_fold_needs_history(&fixture.copy_full, &fixture.parent_hash);
    let mut woken = AttemptQueue::new(&fixture.copy_full).subscribe();
    let ids = fixture
        .copy_full
        .import_signed_authority_history(&[fixture.parent_bytes.clone()])
        .expect("the full import stages the withheld parent");
    assert_eq!(ids.len(), 1, "one row lands");
    assert!(
        fixture
            .copy_full
            .get_authority_log_entry(&ids[0])
            .expect("the row reads")
            .is_some(),
        "the parent is stored"
    );
    let fold = fixture
        .copy_full
        .authority_fold()
        .expect("the fold closes after the import");
    assert!(
        fold.valid_entries.contains(&fixture.parent_hash)
            && fold.valid_entries.contains(&fixture.child_hash),
        "the parent and the waiting child both stand valid"
    );
    assert!(
        woken.try_recv().is_ok(),
        "the import read possibly-unjoined: the held-work wake fires"
    );

    fixture
        .host
        .vault
        .import_signed_authority_history(&[fixture.parent_bytes])
        .expect("control: the unmarked adopter imports too");
}

/// A history page into an unjoined copy with a broken fold stages instead of failing: the round-2
/// page-door fix, whose import closes the gap and wakes the held work.
#[test]
fn a_history_page_into_an_unjoined_copy_repairs_its_fold() {
    let backups = oneiron::test_support::restore_tempdir();
    let fixture = gap_fixture(backups.path());
    assert_fold_needs_history(&fixture.copy_page, &fixture.parent_hash);
    let mut woken = AttemptQueue::new(&fixture.copy_page).subscribe();
    let ids = fixture
        .copy_page
        .import_signed_authority_page(&[fixture.parent_bytes])
        .expect("the page import stages the withheld parent");
    assert_eq!(ids.len(), 1, "one row lands");
    assert!(
        fixture
            .copy_page
            .get_authority_log_entry(&ids[0])
            .expect("the row reads")
            .is_some(),
        "the parent is stored"
    );
    let fold = fixture
        .copy_page
        .authority_fold()
        .expect("the fold closes after the import");
    assert!(
        fold.valid_entries.contains(&fixture.parent_hash)
            && fold.valid_entries.contains(&fixture.child_hash),
        "the parent and the waiting child both stand valid"
    );
    assert!(
        woken.try_recv().is_ok(),
        "the import read possibly-unjoined: the held-work wake fires"
    );
}
