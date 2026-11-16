//! A federation confirmation that collides with another drops no row of any
//! other signer (root FIX-LIST [CONFIRM-COLLISION-SUBTREE-ROLLBACK], Engine
//! RULING COLLISION-SETTLEMENT-SHAPE = A, 16 Nov 04:39: every otherwise
//! valid concurrent FederationConfirm stays valid as spent evidence; no
//! loser, no descendant removal).
//!
//! A host-rooted vault, as a host starts one. The owner enrols three owner
//! signing keys through the owner key enrollment door: S, H and A; the last
//! enrollment is the head P. S signs a confirmation C on P. H signs its own
//! confirmation D on C and revokes A in R on D. The owner then admits a
//! second machine through the door, which names R as its parent. A signs B,
//! a confirmation that collides with C, with a hash below C's. On main the
//! fold keeps the lower hash, B, and settlement removes C with every row
//! after it: H's D and R and the owner's admission, and A, whose revocation
//! R was, is live again unless another proof holds it.
//!
//! Three collisions, each in both delivery orders (B last, or B first):
//! B with C's confirm id; B with C's nonce and its own id (the nonce-only
//! variant); and B with C's id on other parents, above a harmless row Z of
//! A's (the other-parents variant). Each case also checks that the spent
//! evidence still spends: a later confirmation on a frontier that holds B
//! and R, reusing C's id, is refused and takes no row with it.
//!
//! Expected (estimate, not run yet): every test red on main (B wins, C and
//! its descendants go), green on this branch.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test confirm_collision_keeps_other_signers_rows`.

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

/// C's confirm id and nonce. No other row here shares a byte pattern with
/// them, except the colliding confirmation of each case.
const CONFIRM_ID: [u8; 32] = [0x31; 32];
const CONFIRM_NONCE: [u8; 16] = [0x01; 16];

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

/// A machine the owner admits through the door, its key from `seed`.
fn admit_machine(rooted: &Rooted, seed: u8) -> EntityId {
    let signing = SigningKey::from_bytes(&[seed; 32]);
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

fn is_mine(fold: &AuthorityFold, machine: EntityId) -> bool {
    fold.machines
        .get(&machine)
        .is_some_and(|folded| folded.is_mine(None))
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

/// Bytes that start with `prefix` and end with `counter`.
fn counted<const N: usize>(prefix: u8, counter: u64) -> [u8; N] {
    let mut bytes = [prefix; N];
    bytes[N - 8..].copy_from_slice(&counter.to_be_bytes());
    bytes
}

/// How B collides with C.
#[derive(Clone, Copy, Debug)]
enum Collision {
    /// B has C's confirm id and its own nonce, on C's parents.
    SameId,
    /// B has C's nonce and its own confirm id, on C's parents.
    NonceOnly,
    /// B has C's confirm id and its own nonce, on A's harmless row Z on P.
    OtherParents,
}

/// When B reaches the install.
#[derive(Clone, Copy, Debug)]
enum Arrival {
    /// After C, D, R and the second machine's admission.
    Last,
    /// Before C.
    First,
}

/// A's rows for `collision`: Z (the other-parents variant only), then B,
/// the first of A's confirmations that collides with C and hashes below it.
/// About one try in two lands below.
fn colliding_rows(
    rooted: &Rooted,
    attacker: &SigningKey,
    head: AuthorityEntryHash,
    collision: Collision,
    below: AuthorityEntryHash,
) -> (Option<AuthorityLogEntry>, AuthorityLogEntry) {
    let harmless = matches!(collision, Collision::OtherParents).then(|| {
        row_signed_by(
            rooted,
            attacker,
            1,
            vec![head],
            confirmation([0x5A; 32], [0x5A; 16]),
        )
    });
    let (seq, parents) = match &harmless {
        Some(row) => (2, vec![hash_of(row)]),
        None => (1, vec![head]),
    };
    let collision_row = (0..=u64::MAX)
        .map(|counter| {
            let op = match collision {
                Collision::SameId | Collision::OtherParents => {
                    confirmation(CONFIRM_ID, counted(0xC0, counter))
                }
                Collision::NonceOnly => confirmation(counted(0xC1, counter), CONFIRM_NONCE),
            };
            row_signed_by(rooted, attacker, seq, parents.clone(), op)
        })
        .find(|row| hash_of(row) < below)
        .expect("a confirmation that collides with C and hashes below it");
    (harmless, collision_row)
}

/// One case: the rows, both arrival orders' puts, and the assertions.
fn collision_keeps_the_other_signers_rows(collision: Collision, arrival: Arrival) {
    let label = format!("{collision:?} {arrival:?}");
    let rooted = rooted();
    let machine = admit_machine(&rooted, 0xA1);
    let confirmer = SigningKey::from_bytes(&[0x53; 32]);
    let other = SigningKey::from_bytes(&[0x48; 32]);
    let attacker = SigningKey::from_bytes(&[0x41; 32]);
    enrol_owner_key(&rooted, machine, &confirmer);
    enrol_owner_key(&rooted, machine, &other);
    let head = enrol_owner_key(&rooted, machine, &attacker);

    let confirmed = row_signed_by(
        &rooted,
        &confirmer,
        1,
        vec![head],
        confirmation(CONFIRM_ID, CONFIRM_NONCE),
    );
    let others_confirmation = row_signed_by(
        &rooted,
        &other,
        1,
        vec![hash_of(&confirmed)],
        confirmation([0x44; 32], [0x44; 16]),
    );
    let revocation = row_signed_by(
        &rooted,
        &other,
        2,
        vec![hash_of(&others_confirmation)],
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&attacker),
        },
    );
    let (harmless, collision_row) =
        colliding_rows(&rooted, &attacker, head, collision, hash_of(&confirmed));

    let mut puts = Vec::new();
    let put_attackers_rows = |puts: &mut Vec<String>| {
        if let Some(row) = &harmless {
            puts.push(put(&rooted, row));
        }
        puts.push(put(&rooted, &collision_row));
    };
    if matches!(arrival, Arrival::First) {
        put_attackers_rows(&mut puts);
    }
    for row in [&confirmed, &others_confirmation, &revocation] {
        puts.push(put(&rooted, row));
    }
    // The door names the main-log heads, R among them, so the admission
    // descends from C.
    let second_machine = admit_machine(&rooted, 0xA2);
    if matches!(arrival, Arrival::Last) {
        let fold = rooted.vault.authority_fold().expect("the fold");
        // The setup alone, before B: a failure here is the test's setup,
        // not the finding.
        assert!(
            [&confirmed, &others_confirmation, &revocation]
                .iter()
                .all(|row| fold.valid_entries.contains(&hash_of(row))),
            "{label} setup: before B, C, D and R are valid; puts {puts:?}, issues {:?}",
            fold.issues
        );
        assert!(
            !is_live(&fold, &key_of(&attacker)) && is_mine(&fold, second_machine),
            "{label} setup: before B, A is revoked and the second machine is the owner's; issues {:?}",
            fold.issues
        );
        put_attackers_rows(&mut puts);
    }
    assert!(
        puts.iter().all(|outcome| outcome == "stored"),
        "{label} setup: every signed row is stored; puts {puts:?}"
    );

    let fold = rooted.vault.authority_fold().expect("the fold");
    let kept = [
        ("B", &collision_row),
        ("C", &confirmed),
        ("D", &others_confirmation),
        ("R", &revocation),
    ];
    let dropped: Vec<_> = kept
        .iter()
        .filter(|(_, row)| !fold.valid_entries.contains(&hash_of(row)))
        .map(|(name, _)| *name)
        .collect();
    assert!(
        dropped.is_empty(),
        "{label}: a collision drops no row, of A's or any other signer's; dropped {dropped:?}, issues {:?}",
        fold.issues
    );
    assert!(
        harmless
            .iter()
            .all(|row| fold.valid_entries.contains(&hash_of(row))),
        "{label}: A's harmless row Z stays valid; issues {:?}",
        fold.issues
    );
    assert!(
        is_mine(&fold, second_machine),
        "{label}: the owner's admission above R stands; issues {:?}",
        fold.issues
    );
    assert!(
        !is_live(&fold, &key_of(&attacker)),
        "{label}: R, a valid row, keeps A revoked; issues {:?}",
        fold.issues
    );
    assert!(
        fold.federation_confirms.contains_key(&hash_of(&confirmed))
            && fold
                .federation_confirms
                .contains_key(&hash_of(&collision_row)),
        "{label}: B and C both stay spent evidence; issues {:?}",
        fold.issues
    );

    // The spent evidence still spends: H's confirmation on B and R, with
    // C's id, is refused, and takes no row with it.
    let mut joined = vec![hash_of(&collision_row), hash_of(&revocation)];
    joined.sort();
    let reuse = row_signed_by(
        &rooted,
        &other,
        3,
        joined,
        confirmation(CONFIRM_ID, [0x45; 16]),
    );
    let reuse_put = put(&rooted, &reuse);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        !fold.valid_entries.contains(&hash_of(&reuse)),
        "{label}: a confirmation that reuses C's id above B and C is refused; put {reuse_put}, issues {:?}",
        fold.issues
    );
    assert!(
        kept.iter()
            .all(|(_, row)| fold.valid_entries.contains(&hash_of(row)))
            && is_mine(&fold, second_machine),
        "{label}: the refused reuse takes no row with it; issues {:?}",
        fold.issues
    );
}

#[test]
fn a_same_id_collision_keeps_the_other_signers_rows_in_either_order() {
    for arrival in [Arrival::Last, Arrival::First] {
        collision_keeps_the_other_signers_rows(Collision::SameId, arrival);
    }
}

#[test]
fn a_nonce_only_collision_keeps_the_other_signers_rows_in_either_order() {
    for arrival in [Arrival::Last, Arrival::First] {
        collision_keeps_the_other_signers_rows(Collision::NonceOnly, arrival);
    }
}

#[test]
fn a_collision_on_other_parents_keeps_the_other_signers_rows_in_either_order() {
    for arrival in [Arrival::Last, Arrival::First] {
        collision_keeps_the_other_signers_rows(Collision::OtherParents, arrival);
    }
}
