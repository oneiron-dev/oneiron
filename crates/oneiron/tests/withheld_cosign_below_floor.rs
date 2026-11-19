//! A withheld row whose cosigner the owner has revoked grants nothing
//! (row [SEQ-FLOOR-S-WITHHELD-COSIGN], case C6; Engine RULING
//! SEQ-FLOOR-S-WITHHELD-COSIGN-SHAPE = A, 19 Nov 13:01, inside the
//! owner-ratified ONE-REVOKE-DURABILITY: "revocations project onto concurrent
//! history, while a grant authorizes only its causal descendants").
//!
//! A host-rooted vault, as a host starts one. The owner enrols two owner
//! signing keys, O and O2, through the owner key enrollment door. O enrols
//! two agent keys, K and T: an agent key lends no consent, so every row K
//! signs needs an owner key's cosign. While O is live, O cosigns two rows K
//! signs on the same parents P: C at K's sequence 10, which K publishes, and
//! B at K's sequence 5, which K withholds and then delivers. B's sequence is
//! below K's floor of 10, so the fold counts B and records it as a
//! SequenceFork (shape S). O2 sees the fork and revokes O on C and B. Because
//! B is a fork and its cosigner O is revoked in the final fold, B expires at
//! once: it binds nothing, is no handover evidence and lists no directive.
//!
//! R names B. A B that K delivers only after a revocation that never saw it
//! is refused outright: the revocation fences every row O signed or cosigned
//! outside R and its ancestry (`retired_signers`,
//! REVOKED-OWNER-ROOT-SIBLING-ENROL), so it grants nothing on any head
//! (REVIEW-9609 round 2).
//!
//! Expected (estimate, not run yet): red on main, where B binds T until the
//! 24 h stale-roster window ends and the handover and the directive stay
//! valid for ever; green on the head of the fork-expiry PR.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test withheld_cosign_below_floor`.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityFold, AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, AuthorityVaultId, DeviceAuthority,
    HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineRole, OwnerHandover, OwnerHandoverCause, OwnerKeyEnrollment, ROLE_AGENT, ResidenceAct,
    ResidenceDirective, actor_binding_is_active, authority_entry_hash, authority_transcript,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// A rooted vault as a host starts one: the owner bound under the host root,
/// this install profiled, and the handle holding the host's root as a
/// serving host does (fixture of `revocation_survives_signer_fork.rs`).
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    owner: EntityId,
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
    vault.hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
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
        owner,
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
        restored_from: None,
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
        .expect("the owner admits the machine")
        .into_standing()
        .expect("the owner's admission stands");
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

fn signature_slot(key: AuthorityKey) -> AuthoritySignature {
    AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    }
}

/// `op` signed by `signer` at `seq` on `parents`, with one cosign by each of
/// `cosigners`. Every key is in the row before any signs, so each signs the
/// transcript that names the sequence, the parents and the cosign keys.
fn row_signed_by(
    rooted: &Rooted,
    signer: &SigningKey,
    cosigners: &[&SigningKey],
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    let mut cosigners = cosigners.to_vec();
    cosigners.sort_by_key(|cosigner| key_of(cosigner));
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: parents,
        op,
        signer: signature_slot(key_of(signer)),
        cosigns: cosigners
            .iter()
            .map(|cosigner| signature_slot(key_of(cosigner)))
            .collect(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for (slot, cosigner) in entry.cosigns.iter_mut().zip(&cosigners) {
        slot.signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

/// An agent-only enrollment of `enrolled`: a key that lends no consent.
fn agent_enrollment(enrolled: &SigningKey) -> AuthorityOp {
    AuthorityOp::EnrollDevice {
        device: DeviceAuthority {
            key: key_of(enrolled),
            transport_key_binding: [7; 32],
            attestation: AuthorityAttestation {
                kind: "SoftwareArgon2id".to_owned(),
                evidence: vec![1, 2, 3],
            },
            tier: AuthorityTier::Software,
            roles: ROLE_AGENT,
        },
    }
}

/// A binding of `bound` to `actor` as an agent: a granting row.
fn binding_of(bound: &SigningKey, actor: EntityId) -> AuthorityOp {
    AuthorityOp::BindActor {
        authority_key: key_of(bound),
        actor_ref: actor,
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

/// C6 after O2 revokes O on the fork B.
struct Delivered {
    _rooted: Rooted,
    withheld: AuthorityEntryHash,
    fold: AuthorityFold,
}

/// Builds C6 with `withheld_op` as B's op (given the owner, the admitted
/// machine and T's key): C, then B, then R on both.
fn deliver_withheld(
    withheld_op: impl FnOnce(EntityId, EntityId, &SigningKey) -> AuthorityOp,
) -> Delivered {
    let rooted = rooted();
    let machine = admit_machine(&rooted);
    let revoked_owner = SigningKey::from_bytes(&[0x4F; 32]);
    let revoking_owner = SigningKey::from_bytes(&[0x52; 32]);
    let agent = SigningKey::from_bytes(&[0x4B; 32]);
    let bound_agent = SigningKey::from_bytes(&[0x54; 32]);
    enrol_owner_key(&rooted, machine, &revoked_owner);
    let enrolled = enrol_owner_key(&rooted, machine, &revoking_owner);
    let agent_enrolled = row_signed_by(
        &rooted,
        &revoked_owner,
        &[],
        1,
        vec![enrolled],
        agent_enrollment(&agent),
    );
    let bound_agent_enrolled = row_signed_by(
        &rooted,
        &revoked_owner,
        &[],
        2,
        vec![hash_of(&agent_enrolled)],
        agent_enrollment(&bound_agent),
    );
    let parents = vec![hash_of(&bound_agent_enrolled)];
    let published = row_signed_by(
        &rooted,
        &agent,
        &[&revoked_owner],
        10,
        parents.clone(),
        binding_of(&agent, EntityId::now()),
    );
    let withheld = row_signed_by(
        &rooted,
        &agent,
        &[&revoked_owner],
        5,
        parents,
        withheld_op(rooted.owner, machine, &bound_agent),
    );
    // R names B: a revocation fences every row its key signed or cosigned
    // outside R and its ancestry, so a B delivered only after a revocation
    // that never saw it is refused outright and grants nothing on any head.
    let revocation = row_signed_by(
        &rooted,
        &revoking_owner,
        &[],
        1,
        vec![hash_of(&published), hash_of(&withheld)],
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&revoked_owner),
        },
    );
    let setup = [&agent_enrolled, &bound_agent_enrolled, &published];
    let kept = setup.into_iter().map(hash_of).collect::<BTreeSet<_>>();

    // The setup alone: before B arrives, every row is valid and O, K and T
    // are live. A failure here is the test's setup, not the finding.
    let puts = setup.map(|row| put(&rooted, row));
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        kept.is_subset(&applied(&fold)),
        "setup: before B every row is valid; puts {puts:?}, issues {:?}",
        fold.issues
    );
    assert!(
        is_live(&fold, &key_of(&revoked_owner))
            && is_live(&fold, &key_of(&agent))
            && is_live(&fold, &key_of(&bound_agent)),
        "setup: before B, O, K and T are live; issues {:?}",
        fold.issues
    );

    let arrival = put(&rooted, &withheld);
    let withheld = hash_of(&withheld);
    let fold = rooted.vault.authority_fold().expect("the fold");
    // B reached the fold and the fold counted it as K's fork (shape S): a
    // refused B would meet the assertions below without the finding.
    assert_eq!(
        arrival, "stored",
        "setup: B is stored; issues {:?}",
        fold.issues
    );
    assert!(
        fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::SequenceFork(forked) if *forked == withheld
        )) && applied(&fold).contains(&withheld),
        "setup: the fold counts B while its cosigner O is live and records its fork as \
         SequenceFork; issues {:?}",
        fold.issues
    );

    let arrival = put(&rooted, &revocation);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        kept.is_subset(&applied(&fold))
            && applied(&fold).contains(&hash_of(&revocation))
            && !is_live(&fold, &key_of(&revoked_owner))
            && is_live(&fold, &key_of(&agent))
            && is_live(&fold, &key_of(&bound_agent)),
        "setup: R is valid, O revoked and K and T live; put {arrival}, issues {:?}",
        fold.issues
    );
    assert!(
        fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::SequenceFork(forked) if *forked == withheld
        )),
        "setup: after R the fold still counts B as K's fork; issues {:?}",
        fold.issues
    );
    Delivered {
        _rooted: rooted,
        withheld,
        fold,
    }
}

/// B binds T to an agent actor.
#[test]
fn a_withheld_binding_cosigned_by_a_revoked_owner_key_binds_nothing() {
    let actor = EntityId::now();
    let delivered = deliver_withheld(|_, _, bound_agent| binding_of(bound_agent, actor));
    assert!(
        !actor_binding_is_active(&delivered.fold, &actor, "agent"),
        "a forked binding whose cosigner is revoked must not bind T, not even for the \
         stale-roster window; issues {:?}",
        delivered.fold.issues
    );
    assert!(
        !applied(&delivered.fold).contains(&delivered.withheld),
        "the forked binding leaves the valid rows at once; issues {:?}",
        delivered.fold.issues
    );
}

/// B is an owner handover: restore evidence for the shared vault.
#[test]
fn a_withheld_handover_cosigned_by_a_revoked_owner_key_is_no_evidence() {
    let delivered = deliver_withheld(|owner, _, _| {
        AuthorityOp::OwnerHandover(OwnerHandover {
            shared_vault: 1,
            cause: OwnerHandoverCause::Transfer,
            from: owner,
            to: Some(EntityId::now()),
            from_keeps: None,
            act: None,
            proof: None,
            authorizer: None,
            receipt: "withheld-handover".to_owned(),
            affected_grants: Vec::new(),
            retired_own_device_grants: Vec::new(),
        })
    });
    // The handover evidence reader takes only valid rows.
    assert!(
        !applied(&delivered.fold).contains(&delivered.withheld),
        "a forked handover whose cosigner is revoked must leave the valid rows at once, so \
         it is no handover evidence; issues {:?}",
        delivered.fold.issues
    );
}

/// B is a residence directive to the admitted machine.
#[test]
fn a_withheld_directive_cosigned_by_a_revoked_owner_key_is_not_listed() {
    let delivered = deliver_withheld(|owner, machine, _| {
        AuthorityOp::ResidenceDirective(ResidenceDirective {
            id: EntityId::now(),
            machine,
            owner,
            issued_at: 1,
            act: ResidenceAct::SyncAll,
        })
    });
    // The directive listing takes only valid rows.
    assert!(
        !applied(&delivered.fold).contains(&delivered.withheld),
        "a forked directive whose cosigner is revoked must leave the valid rows at once, so \
         no machine lists or runs it; issues {:?}",
        delivered.fold.issues
    );
}
