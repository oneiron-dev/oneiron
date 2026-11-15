//! A key's revocation survives a confirmation collision below it (root
//! FIX-LIST [CONFIRM-COLLISION-SUBTREE-ROLLBACK], Engine RULING 16 Nov 02:37,
//! SEQ-FLOOR-SHAPE-S = B: RevokeDevice joins the restrictive facts proved on
//! their own signed branch).
//!
//! A host-rooted vault, as a host starts one. The owner enrols two owner
//! signing keys, O2 and K, through the owner key enrollment door. K signs a
//! federation confirmation C. O2 revokes K on C. Later K's holder signs B,
//! another confirmation with C's confirm id and its own nonce, on C's
//! parents, at K's next sequence, and picks B's nonce so that B's hash is
//! below C's. Two valid confirmations that share an id collide: the fold
//! keeps the lower hash, B, and settlement removes C with every row after
//! it, the revocation among them. K must stay revoked: the revocation is
//! proved on its own signed branch, which B does not touch.
//!
//! This test pins only the revocation. The rest of C's subtree still goes
//! with C (the FIX row stays open for that).
//!
//! Expected (estimate, not run yet): red on main, where K is live again
//! once B arrives; green on this branch.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test revocation_survives_confirm_collision`.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityConfirmAction,
    AuthorityConfirmKind, AuthorityEntryHash, AuthorityFold, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerKeyEnrollment,
    authority_entry_hash, authority_transcript, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// A rooted vault as a host starts one: the owner bound under the host root
/// and this install profiled, so it carries the owner's answers.
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
}

fn rooted() -> Rooted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Rooted {
        _dir: dir,
        vault,
        issuer,
        proof,
        vault_id,
    }
}

/// A machine the owner admitted, whose keystore holds the owner keys the
/// test enrols.
fn admit_machine(rooted: &Rooted) -> EntityId {
    let signing = SigningKey::from_bytes(&[0xA1; 32]);
    let machine = EntityId::now();
    let machine_key = signing.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = signing
        .sign(&machine_profile_proof_transcript(
            &rooted.vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    let request = MachineEnrolmentRequest {
        vault_id: rooted.vault_id,
        machine,
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        machine_proof,
    };
    let folded = rooted
        .vault
        .enroll_machine(
            &rooted.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner admits the machine");
    assert!(folded.is_mine(None), "the admitted machine is the owner's");
    machine
}

/// The owner enrols `signing` as an owner key held on `machine`, through
/// the public owner key enrollment door; returns the enrollment's entry.
fn enrol_owner_key(rooted: &Rooted, machine: EntityId, signing: &SigningKey) -> AuthorityEntryHash {
    let authority = ActAuthority::Owner(rooted.proof.clone(), ActSurface::ThisInstall);
    let public_key = signing.verifying_key().to_bytes();
    let challenge = rooted
        .vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("the enrollment's challenge");
    rooted
        .vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: signing.sign(&challenge).to_bytes().to_vec(),
            },
            &rooted.issuer,
        )
        .expect("the owner enrols the key")
        .entry
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// `op` signed by `signing` at `seq` on `parents`.
fn row_signed_by(
    rooted: &Rooted,
    signing: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    let key = key_of(signing);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: parents,
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

fn hash_of(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("row hash")
}

fn is_live(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    fold.roster
        .get(key)
        .is_some_and(|device| !device.revoked && device.roles != 0)
}

/// The put door's outcome for `row`, as text for the assertion messages.
fn put(rooted: &Rooted, row: &AuthorityLogEntry) -> String {
    match rooted.vault.put_authority_log_entry(row, AT, 1) {
        Ok(_) => "stored".to_owned(),
        Err(error) => format!("refused: {:?}", error.kind()),
    }
}

/// A federation confirmation with `confirm_id` and `nonce`.
fn confirmation(confirm_id: [u8; 32], nonce: [u8; 16]) -> AuthorityOp {
    AuthorityOp::FederationConfirm(AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id,
        peer_vault_id: [0x77; 32],
        epoch: 1,
        nonce,
    })
}

/// O2 and K enrolled (K's enrollment is the head P); C = K's confirmation
/// at K's sequence 1 on P; the revocation = O2's RevokeDevice of K at O2's
/// sequence 1 on C; B = K's confirmation with C's id and another nonce at
/// K's sequence 2 on P, with a hash below C's. The install holds C and the
/// revocation before B arrives.
#[test]
fn a_revocation_below_a_losing_confirmation_keeps_the_key_revoked() {
    let rooted = rooted();
    let machine = admit_machine(&rooted);
    let second_owner = SigningKey::from_bytes(&[0x52; 32]);
    let colliding = SigningKey::from_bytes(&[0x4B; 32]);
    enrol_owner_key(&rooted, machine, &second_owner);
    let enrolled = enrol_owner_key(&rooted, machine, &colliding);
    let confirm_id = [0x31; 32];
    let confirmed = row_signed_by(
        &rooted,
        &colliding,
        1,
        vec![enrolled],
        confirmation(confirm_id, [0x01; 16]),
    );
    let revocation = row_signed_by(
        &rooted,
        &second_owner,
        1,
        vec![hash_of(&confirmed)],
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&colliding),
        },
    );
    // About one try in two lands below C's hash.
    let collision = (2..=u8::MAX)
        .map(|nonce| {
            row_signed_by(
                &rooted,
                &colliding,
                2,
                vec![enrolled],
                confirmation(confirm_id, [nonce; 16]),
            )
        })
        .find(|row| hash_of(row) < hash_of(&confirmed))
        .expect("a nonce whose confirmation hashes below C's");

    // The setup alone: before the collision, C and the revocation are
    // valid and K is revoked. A failure here is the test's setup, not the
    // finding.
    let puts = [put(&rooted, &confirmed), put(&rooted, &revocation)];
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        fold.valid_entries.contains(&hash_of(&confirmed))
            && fold.valid_entries.contains(&hash_of(&revocation)),
        "setup: before the collision C and the revocation are valid; puts {puts:?}, issues {:?}",
        fold.issues
    );
    assert!(
        !is_live(&fold, &key_of(&colliding)),
        "setup: before the collision K is revoked; issues {:?}",
        fold.issues
    );

    let arrival = put(&rooted, &collision);
    let fold = rooted.vault.authority_fold().expect("the fold");
    // The collision reached the fold and won it: a revoked key keeps its
    // standing at the door, so the assertion below is not met by a refused
    // put or a lost collision.
    assert_eq!(
        arrival, "stored",
        "the colliding confirmation is stored; issues {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&hash_of(&collision))
            && !fold.valid_entries.contains(&hash_of(&confirmed)),
        "setup: the lower-hash confirmation wins the collision; issues {:?}",
        fold.issues
    );
    assert!(
        !is_live(&fold, &key_of(&colliding)),
        "K's colliding confirmation must not make K live again; issues {:?}",
        fold.issues
    );
}
