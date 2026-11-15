//! Pass 27 R4 PR 1 (Engine RULING HOSTED-REROOT-ADMISSION-DOORS = C): the
//! hosted ReRoot refusal at the admission doors. A ReRoot signed by the kit
//! root's authority key on a hosted vault whose host root is live is refused
//! at the signed-history import and at the authority-log puts, each judged
//! against the fold before the row; the host's own move still imports into
//! a fresh hosted replica. Such a
//! ReRoot revokes every roster row, the custodial root included, and every
//! slip the host minted stops verifying (NOTE WAYBACK-REROOT-TRACE, 15 Nov
//! 22:02). The successor asks the owner role alone, so the fold would count
//! the move.
//!
//! Red on head 4494593651b1: the import and the put land the row, and the
//! custodial root is revoked.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test hosted_reroot_admission_doors`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, DeviceAuthority, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
    OwnerKeyEnrollment, ROLE_OWNER, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::re_root_stale_sweep::re_root_authority_as_host;
use oneiron::test_doors::root_recovery::released_authority_seed;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, ErrorKind, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};

/// The seed of the owner's enrolled device key.
const DEVICE_KEY_SEED: u8 = 21;
/// The seed of the ReRoot successor the refusals name.
const RE_ROOT_SEED: u8 = 35;
/// The seed of the host's next root, for the host's own move.
const NEXT_HOST_ROOT_SEED: u8 = 36;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn live(vault: &Vault, key: &AuthorityKey) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .roster
        .get(key)
        .is_some_and(|device| !device.revoked)
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// A software device with the owner role alone, keyed by `seed`'s key.
fn owner_device(seed: u8) -> DeviceAuthority {
    DeviceAuthority {
        key: key_of(&SigningKey::from_bytes(&[seed; 32])),
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles: ROLE_OWNER,
    }
}

/// A hosted vault with a live custodial host root, one enrolled owner device
/// key, and the kit root's authority key enrolled live.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    vault_id: [u8; 32],
    root_key: AuthorityKey,
    root_signing: SigningKey,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("the hosted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let machine = vault
        .prepare_install_signing()
        .expect("this install's machine");
    let authority = ActAuthority::Owner(proof(&vault, person), ActSurface::ThisInstall);

    // The owner's device key, enrolled under the custodial root.
    let device_key = SigningKey::from_bytes(&[DEVICE_KEY_SEED; 32]);
    let public_key = device_key.verifying_key().to_bytes();
    let challenge = vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("the challenge");
    vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: device_key.sign(&challenge).to_bytes().to_vec(),
            },
            &issuer,
        )
        .expect("the owner enrols a device key");

    // The kit's root, its authority key enrolled before the loss.
    let seed = RecoveryRootSeed::generate().expect("a root seed");
    let pieces = issue_recovery_root_kit(
        &KitIssue {
            vault_id,
            homes: [
                PieceHome::ThisMachine,
                PieceHome::OtherMachine(EntityId::now()),
                PieceHome::OtherMachine(EntityId::now()),
            ],
            passphrase: None,
            cost: PassphraseCost::FLOOR,
            only_machine: false,
        },
        &seed.kit_bytes(),
    )
    .expect("the kit")
    .into_pieces();
    let restore = || {
        restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &[&pieces[0], &pieces[1]],
            None,
        )
        .expect("two stored pieces restore the seed")
    };
    let restored = RecoveryRootSeed::from_restored_kit(restore()).expect("the seed");
    let receipt = vault
        .enrol_recovery_authority_key_as_host(&authority, machine, &restored, &issuer)
        .expect("the owner enrols the root's authority key");
    let root_key = AuthorityKey::Ed25519(receipt.public_key);
    let root_signing = SigningKey::from_bytes(&released_authority_seed(&restored, &vault_id, 0));
    assert_eq!(key_of(&root_signing), root_key, "the released key is R");
    let host_root = issuer.public_key();
    assert!(live(&vault, &root_key) && live(&vault, &host_root));
    Fixture {
        _dir: dir,
        vault,
        issuer,
        vault_id,
        root_key,
        root_signing,
    }
}

impl Fixture {
    fn history(&self) -> Vec<AuthorityLogEntry> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|row| decode_authority_log_entry_body(row).expect("a row"))
            .collect()
    }

    /// The stored history's heads, which a new main-log entry names.
    fn heads(&self) -> Vec<AuthorityEntryHash> {
        let rows = self.history();
        let parents: BTreeSet<AuthorityEntryHash> = rows
            .iter()
            .flat_map(|row| row.parent_hashes.iter().copied())
            .collect();
        let mut heads: Vec<AuthorityEntryHash> = rows
            .iter()
            .map(|row| authority_entry_hash(row).expect("a hash"))
            .filter(|row| !parents.contains(row))
            .collect();
        heads.sort_unstable();
        heads.dedup();
        heads
    }

    /// `signer`'s next sequence in the stored history.
    fn next_seq(&self, signer: &AuthorityKey) -> u64 {
        self.history()
            .iter()
            .filter(|row| row.signer_key() == signer)
            .map(|row| row.seq + 1)
            .max()
            .unwrap_or(0)
            .max(1)
    }

    /// A ReRoot on `heads` to the owner-role key of `successor`'s seed,
    /// signed by `signing` at `seq`.
    fn re_root_row(
        &self,
        signing: &SigningKey,
        seq: u64,
        heads: &[AuthorityEntryHash],
        successor: u8,
    ) -> AuthorityLogEntry {
        let signer = key_of(signing);
        let mut row = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(self.vault_id),
            seq,
            parent_hashes: heads.to_vec(),
            op: AuthorityOp::ReRoot {
                new_device: owner_device(successor),
            },
            signer: AuthoritySignature {
                suite: signer.suite(),
                public_key: signer,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock after 1970")
                .as_secs(),
        };
        let transcript = authority_transcript(&row).expect("the transcript");
        row.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
        row
    }
}

/// Asserts `refusal` is the hosted ReRoot refusal: the writer's kind and words.
fn assert_hosted_refused(refusal: &oneiron::Error) {
    assert_eq!(refusal.kind(), ErrorKind::AuthorityRefused, "{refusal}");
    assert!(
        refusal.to_string().contains("the host does not hold"),
        "the refusal names the host's root and the root's door: {refusal}"
    );
}

#[test]
fn a_hosted_vault_refuses_an_imported_reroot_by_the_roots_key() {
    let fixture = fixture();
    let stored = fixture.history().len();
    let heads = fixture.heads();
    let seq = fixture.next_seq(&fixture.root_key);
    let row = fixture.re_root_row(&fixture.root_signing, seq, &heads, RE_ROOT_SEED);
    let bytes = encode_authority_log_entry_body(&row).expect("the signed bytes");

    let refusal = fixture
        .vault
        .import_signed_authority_history(&[bytes])
        .expect_err("an imported ReRoot by the root's key is refused");
    assert_hosted_refused(&refusal);
    assert_eq!(
        fixture.history().len(),
        stored,
        "the refusal writes nothing"
    );
    let host_root = fixture.issuer.public_key();
    assert!(
        live(&fixture.vault, &host_root),
        "the custodial root stays live"
    );
    assert!(
        live(&fixture.vault, &fixture.root_key),
        "the root's authority key stays live"
    );
}

#[test]
fn a_hosted_vault_refuses_a_put_reroot_by_the_roots_key() {
    let fixture = fixture();
    let stored = fixture.history().len();
    let heads = fixture.heads();
    let seq = fixture.next_seq(&fixture.root_key);
    let row = fixture.re_root_row(&fixture.root_signing, seq, &heads, RE_ROOT_SEED);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs();

    let refusal = fixture
        .vault
        .put_authority_log_entry(
            &row,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect_err("a put ReRoot by the root's key is refused");
    assert_hosted_refused(&refusal);
    assert_eq!(
        fixture.history().len(),
        stored,
        "the refusal writes nothing"
    );
    let host_root = fixture.issuer.public_key();
    assert!(
        live(&fixture.vault, &host_root),
        "the custodial root stays live"
    );
    assert!(
        live(&fixture.vault, &fixture.root_key),
        "the root's authority key stays live"
    );
}

#[test]
fn the_hosts_own_reroot_still_imports() {
    // The host signs its own move through the path that signs as the host,
    // as `owner_root_recovery` does. A fresh hosted replica then imports the
    // whole history, so the import door judges that ReRoot against the fold
    // of the rows staged before it: the host's root is live there, and the
    // signer is that root.
    let fixture = fixture();
    let next = HostSlipIssuer::from_seed(&[NEXT_HOST_ROOT_SEED; HOST_ISSUER_SEED_BYTES])
        .expect("the host's next root");
    re_root_authority_as_host(&fixture.vault, &fixture.issuer, &next)
        .expect("the host's own move is not an owner key's");
    let history = fixture
        .vault
        .export_signed_authority_history()
        .expect("the signed history");

    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let replica = Vault::open(dir.path(), config).expect("the hosted replica");
    replica.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    replica
        .import_signed_authority_history(&history)
        .expect("the host's own ReRoot imports");

    assert!(
        live(&replica, &next.public_key()),
        "the host's next root is live on the replica"
    );
    let host_root = fixture.issuer.public_key();
    assert!(
        !live(&replica, &host_root),
        "the host's old root is retired on the replica"
    );
}
