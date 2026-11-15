//! A revoked key's later fork never undoes its revocation, on any install
//! (OPUS-SECREAD-A's cold read of #8449, N1 P1; Engine RULING 16 Nov 01:37,
//! SEQ-FLOOR-FORK-ROLLBACK = C).
//!
//! A host-rooted vault, as a host starts one. The owner enrols two owner
//! signing keys, O2 and K, through the owner key enrollment door: an owner
//! root signs each enrollment and the carrier's install key cosigns it. K
//! signs a granting row X, a binding of O2's key to an actor. O2 revokes K
//! on X, as a client that parents on its heads does. Later K's holder signs
//! Y: K's next sequence, a binding of its own key, on X's parent, so Y does
//! not descend from X. Y arrives after the install already holds X and the
//! revocation. K must stay revoked, and X and the revocation must stay
//! valid: a fork of a key never takes back what an install already counted,
//! and never undoes the owner's revocation of that key.
//!
//! Expected (estimate, not run yet): green on main, where X's arrival floor
//! was set before Y arrived; red at 69a0283b, where Y's higher sequence
//! floors X, X is refused, and the revocation goes with it as
//! InvalidAncestry, so K is live again.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test revocation_survives_signer_fork`.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityFold,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId,
    HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineRole, OwnerKeyEnrollment, authority_entry_hash, authority_transcript,
    machine_profile_proof_transcript,
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

/// A binding of `bound` to a fresh actor: a granting row.
fn binding_of(bound: &SigningKey) -> AuthorityOp {
    AuthorityOp::BindActor {
        authority_key: key_of(bound),
        actor_ref: EntityId::now(),
        actor_class: "agent".to_owned(),
        epoch: 1,
    }
}

fn hash_of(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("row hash")
}

fn applied(fold: &AuthorityFold) -> BTreeSet<AuthorityEntryHash> {
    fold.valid_entries.iter().copied().collect()
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

/// O2 and K enrolled (K's enrollment is the head P); X = K's binding of O2
/// at K's sequence 1 on P; the revocation = O2's RevokeDevice of K at O2's
/// sequence 1 on X; Y = K's binding of its own key at K's sequence 2 on P.
/// The install holds X and the revocation before Y arrives.
#[test]
fn a_revoked_keys_later_fork_never_undoes_its_revocation() {
    let rooted = rooted();
    let machine = admit_machine(&rooted);
    let second_owner = SigningKey::from_bytes(&[0x52; 32]);
    let forked = SigningKey::from_bytes(&[0x4B; 32]);
    enrol_owner_key(&rooted, machine, &second_owner);
    let enrolled = enrol_owner_key(&rooted, machine, &forked);
    let binding = row_signed_by(
        &rooted,
        &forked,
        1,
        vec![enrolled],
        binding_of(&second_owner),
    );
    let revocation = row_signed_by(
        &rooted,
        &second_owner,
        1,
        vec![hash_of(&binding)],
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&forked),
        },
    );
    let fork = row_signed_by(&rooted, &forked, 2, vec![enrolled], binding_of(&forked));
    let kept = [&binding, &revocation]
        .into_iter()
        .map(hash_of)
        .collect::<BTreeSet<_>>();

    // The setup alone: before the fork, the binding and the revocation are
    // valid and K is revoked. A failure here is the test's setup, not the
    // finding.
    let puts = [put(&rooted, &binding), put(&rooted, &revocation)];
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        kept.is_subset(&applied(&fold)),
        "setup: before the fork the binding and the revocation are valid; puts {puts:?}, \
         issues {:?}",
        fold.issues
    );
    assert!(
        !is_live(&fold, &key_of(&forked)),
        "setup: before the fork K is revoked; issues {:?}",
        fold.issues
    );

    let arrival = put(&rooted, &fork);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        !is_live(&fold, &key_of(&forked)),
        "K's fork after its revocation must not make K live again; the fork's put \
         {arrival}, issues {:?}",
        fold.issues
    );
    assert!(
        kept.is_subset(&applied(&fold)),
        "the binding and the revocation the install already counted stay valid after K's \
         fork; the fork's put {arrival}, issues {:?}",
        fold.issues
    );
    // The fork reached the fold: a revoked key keeps its standing at the
    // door, so the assertions above are not met by a refused put.
    assert_eq!(
        arrival, "stored",
        "the fork is stored; issues {:?}",
        fold.issues
    );
}
