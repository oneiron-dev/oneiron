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
//! REVOKED-OWNER-ROOT-SIBLING-ENROL), so it grants nothing on any head; a
//! Connect so refused binds no grant, and a Connect guest grant no Active
//! pact binds is inert (REVIEW-9609 round 2).
//!
//! B may also be a federation pact's Connect, with the peer's gesture. Then
//! the pact B set up is held suspended: it confers nothing, its grant stays
//! bound to it, so the grant never reads as unpacted (legacy allow), and an
//! owner key still live ends it with a Disconnect (PR 2 of the row).
//!
//! Expected (estimate, not run yet): red on main, where B binds T until the
//! 24 h stale-roster window ends and the handover and the directive stay
//! valid for ever; green on the head of the fork-expiry PR. The pact
//! variants, on that PR's head (red) and the lifecycle PR's head (green):
//! - B's Connect holds its pact suspended: red, where B's pact stays active.
//! - A live Connect A, concurrent with B, that agrees with B on the ceiling
//!   but pins another peer key than B's lesser one never renews the pact:
//!   red, where nothing holds the pact.
//! - The owner's narrowing door refuses the held pact: red, where the pact
//!   stays active and the narrowing folds (REVIEW-9609 round 2).
//! - Guards that pass on both heads: an owner's Disconnect and the
//!   Disconnect door end the pact (an ended pact stays ended), and a live
//!   Connect pinning the same peer renews it.
//!
//! The review tests of the fix (row SEQ-FLOOR-S-WITHHELD-COSIGN-REVIEW-TESTS)
//! each pass on main and fail with one hunk of the fix reverted:
//! 1. A cold install that adopted an image past the compaction trigger,
//!    which dropped B's body, folds R past it. Only B's body names O, so the
//!    fold asks for the whole history (red: without the
//!    `dropped_body_fork_may_expire` check in `fold_adopted_checkpoint_tail`).
//! 2. A prune directive to this install that it read as pending before R and
//!    runs after R records no result and prunes nothing (red: without the
//!    recheck in `finish_residence_directive_in_txn`).
//! 3. An open directive so read and run stamps no touch on its cached copy
//!    and records no result (red: the connection's Open arm recording its
//!    result in a second transaction after the open, as before 3f874d25).
//! 4. A re-pact whose gesture another key of the peer's admitted roster
//!    signs moves the ceiling on but backs no pin, so the pact whose pin only
//!    B backs stays held (red: `suspend_pacts_of_expired_rows` without its
//!    pin arm, as before 1c359efe).
//! 5. The Disconnect door ends a held pact with 33 expired Connects that no
//!    head holds, through a frontier join (red: `prepare_hashed_slip_op_in_txn`
//!    leaving the heads `MAX_PARENTS` less those rows, as before 1c359efe).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test withheld_cosign_below_floor`.

#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityFold, AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, AuthorityVaultId, DeviceAuthority,
    FederationGrantActivation, FederationLifecycleAction, FederationLifecycleKind,
    FederationPactStatus, GenesisRecoveryStep, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerHandover, OwnerHandoverCause,
    OwnerKeyEnrollment, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER, ResidenceAct, ResidenceDirective,
    actor_binding_is_active, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body, federation_grant_activation,
    federation_scope_digest, genesis_vault_id, machine_profile_proof_transcript,
    sign_federation_pact_gesture,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationDirectionScope, FederationPactScope, ScopeAxis, admit_peer_authority_log_entry,
    encode_federation_pact_scope,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::ResidenceDirectiveState;
use oneiron::test_doors::authority_adopted_fold::fold_past_overflow_prefix_image;
use oneiron::test_doors::residence_directive_run::{
    apply_residence_directive, pending_residence_directives,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// A rooted vault as a host starts one: the owner bound under the host root,
/// this install profiled, and the handle holding the host's root as a
/// serving host does (fixture of `revocation_survives_signer_fork.rs`). The
/// handle is shared, as a sync connection takes it.
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    owner: EntityId,
    vault_id: AuthorityVaultId,
}

fn rooted() -> Rooted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("the install"));
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
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: parents,
        op,
        overlay_seed,
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
    published: AuthorityEntryHash,
    revocation: AuthorityEntryHash,
    rooted: Rooted,
    withheld: AuthorityEntryHash,
    fold: AuthorityFold,
}

/// C6 before R arrives: C published, B delivered and counted as K's fork
/// while O is live, and R, O2's revocation of O on both, signed and held.
struct Withheld {
    published: AuthorityEntryHash,
    revocation: AuthorityLogEntry,
    rooted: Rooted,
    withheld: AuthorityEntryHash,
    /// P, the parents C and B share.
    forked_on: AuthorityEntryHash,
    /// The setup rows and C, valid throughout.
    kept: BTreeSet<AuthorityEntryHash>,
}

/// Builds C6 with `withheld_op` as B's op (given the owner, the admitted
/// machine and T's key, and this vault's id): C, then B, then R on both.
fn deliver_withheld(
    withheld_op: impl FnOnce(EntityId, EntityId, &SigningKey, AuthorityVaultId) -> AuthorityOp,
) -> Delivered {
    let rooted = rooted();
    let machine = admit_machine(&rooted);
    deliver_revocation(withhold(rooted, machine, withheld_op))
}

/// C6 on `rooted`, whose owner admitted `machine`, up to R: C, then B, with
/// R signed and held back.
fn withhold(
    rooted: Rooted,
    machine: EntityId,
    withheld_op: impl FnOnce(EntityId, EntityId, &SigningKey, AuthorityVaultId) -> AuthorityOp,
) -> Withheld {
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
    let forked_on = hash_of(&bound_agent_enrolled);
    let parents = vec![forked_on];
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
        withheld_op(rooted.owner, machine, &bound_agent, rooted.vault_id),
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
    Withheld {
        published: hash_of(&published),
        revocation,
        rooted,
        withheld,
        forked_on,
        kept,
    }
}

/// R arrives on `withheld`: O2 revokes O on C and B.
fn deliver_revocation(withheld: Withheld) -> Delivered {
    let Withheld {
        published,
        revocation,
        rooted,
        withheld,
        kept,
        ..
    } = withheld;
    let revoked_owner = SigningKey::from_bytes(&[0x4F; 32]);
    let agent = SigningKey::from_bytes(&[0x4B; 32]);
    let bound_agent = SigningKey::from_bytes(&[0x54; 32]);
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
        published,
        revocation: hash_of(&revocation),
        rooted,
        withheld,
        fold,
    }
}

/// B binds T to an agent actor.
#[test]
fn a_withheld_binding_cosigned_by_a_revoked_owner_key_binds_nothing() {
    let actor = EntityId::now();
    let delivered = deliver_withheld(|_, _, bound_agent, _| binding_of(bound_agent, actor));
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
    let delivered = deliver_withheld(|owner, _, _, _| {
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
    let delivered = deliver_withheld(|owner, machine, _, _| {
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

/// Every stored authority row's hash: the log so far, ancestor-closed.
fn stored_hashes(vault: &Vault) -> BTreeSet<AuthorityEntryHash> {
    vault
        .export_signed_authority_history()
        .expect("the stored authority rows")
        .iter()
        .map(|bytes| hash_of(&decode_authority_log_entry_body(bytes).expect("a stored row")))
        .collect()
}

/// B is a directive, and a cold install adopted an image of every row before
/// R, one that dropped its residence bodies as an image past the compaction
/// trigger does (FIX 11400): B's body, the one row that names B's cosigner
/// O, is not in it. R arrives past the image. Without B's body the fold past
/// the image cannot expire B, so once a key is revoked it asks for the whole
/// history, whose fold expires B (review test 1).
#[test]
fn an_overflow_image_adopter_folds_the_whole_history_for_a_forked_directive() {
    let rooted = rooted();
    let machine = admit_machine(&rooted);
    let withheld = withhold(rooted, machine, |owner, machine, _, _| {
        AuthorityOp::ResidenceDirective(ResidenceDirective {
            id: EntityId::now(),
            machine,
            owner,
            issued_at: 1,
            act: ResidenceAct::SyncAll,
        })
    });
    let covered = stored_hashes(&withheld.rooted.vault);
    let before = fold_past_overflow_prefix_image(&withheld.rooted.vault, &covered)
        .expect("the fold past the overflow image before R");
    let revoked = before.whole.roster.values().any(|device| device.revoked);
    let adopted = before.adopted.unwrap_or_else(|missing| {
        panic!(
            "setup: before R the fold past the overflow image answers, not asks for {} \
             covered rows; a key revoked before R: {revoked}",
            missing.len()
        )
    });
    assert!(
        covered.contains(&withheld.withheld) && applied(&adopted).contains(&withheld.withheld),
        "setup: the image covers B, and the fold past it counts B while O is live; issues {:?}",
        adopted.issues
    );

    let delivered = deliver_revocation(withheld);
    let after = fold_past_overflow_prefix_image(&delivered.rooted.vault, &covered)
        .expect("the fold past the overflow image after R");
    assert!(
        !applied(&after.whole).contains(&delivered.withheld),
        "setup: the whole fold expires B once O is revoked; issues {:?}",
        after.whole.issues
    );
    match after.adopted {
        Err(missing) => assert!(
            missing.contains(&delivered.withheld),
            "the fold past the image asks for the whole history, B among it; it asks for {} \
             rows",
            missing.len()
        ),
        Ok(adopted) => panic!(
            "the fold past an image that dropped B's body cannot read B's cosigner, so once a \
             key is revoked it must ask for the whole history, not answer; it counts B: {}, \
             issues {:?}",
            applied(&adopted).contains(&delivered.withheld),
            adopted.issues
        ),
    }
}

/// Runs `test` on a current-thread runtime with room for the engine's deep
/// stacks (fixture of `it_sync/device_predicted_level.rs`).
fn run_async<F>(name: &str, test: impl FnOnce() -> F + Send + 'static)
where
    F: Future<Output = ()>,
{
    let run = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(test());
        })
        .expect("test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

/// The owner answers this install's machine as the owner's own, so the
/// owner's residence directives run here: only the key of a machine whose
/// answered roster head names it signs a result that stands (FIX 8888).
fn answer_this_install(rooted: &Rooted) -> EntityId {
    let local = rooted
        .vault
        .local_machine()
        .expect("this install's machine")
        .expect("a profiled machine")
        .id;
    let landing = rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            local,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner answers this install's machine");
    assert!(
        landing.held().is_none(),
        "setup: the host's root this handle holds proves the owner's answer, so it stands"
    );
    local
}

/// C6 with B a directive of `act` to this install, which reads B as pending
/// before R arrives, as an upkeep round reads it.
fn withhold_directive_here(
    directive: EntityId,
    act: ResidenceAct,
) -> (Withheld, ResidenceDirectiveState) {
    let rooted = rooted();
    let local = answer_this_install(&rooted);
    let machine = admit_machine(&rooted);
    let withheld = withhold(rooted, machine, |owner, _, _, _| {
        AuthorityOp::ResidenceDirective(ResidenceDirective {
            id: directive,
            machine: local,
            owner,
            issued_at: 1,
            act,
        })
    });
    let pending =
        pending_residence_directives(&withheld.rooted.vault).expect("the pending directives");
    let [pending] = <[ResidenceDirectiveState; 1]>::try_from(pending).unwrap_or_else(|pending| {
        panic!("setup: before R this install reads B alone as pending; it reads {pending:?}")
    });
    assert_eq!(
        pending.entry, withheld.withheld,
        "setup: the pending directive is B"
    );
    (withheld, pending)
}

/// The window the cached copy was opened in.
const WINDOW: &str = "2026-09";

/// The touch the cached copy was last stamped with.
const CACHED_TOUCH: u64 = 1;

/// Leaves a read cache of `item` in WINDOW as a touch at the home leaves it,
/// an ordinary row, its document and the window it was opened in, last
/// touched at CACHED_TOUCH (fixture of `residence_custody_cache.rs`).
fn cache_thin_item(vault: &Vault, item: EntityId) {
    let id = item.to_hex();
    let mut row = vec![ENTITY_TYPE_PERSON];
    for field in [1_788_300_000_u64, 1_788_300_000, 1_788_300_000, 0] {
        row.extend_from_slice(&field.to_be_bytes());
    }
    row.extend_from_slice(b"a cached row");
    for (key, value) in [
        (format!("ri:b:{id}"), row),
        (format!("ri:d:{id}"), b"cached document".to_vec()),
        (format!("ro:e:{id}"), WINDOW.as_bytes().to_vec()),
        (format!("rt:e:{id}"), CACHED_TOUCH.to_be_bytes().to_vec()),
    ] {
        vault
            .sync_state_put(&key, &value)
            .expect("a read cache row");
    }
}

/// `item`'s read cache row of `family` (`ro:e:` the window, `rt:e:` the
/// touch), if held.
fn cache_row(vault: &Vault, family: &str, item: EntityId) -> Option<Vec<u8>> {
    vault
        .sync_state_get(&format!("{family}{}", item.to_hex()))
        .expect("a read cache row reads")
}

/// Whether this vault stores a result row for the directive at `entry`.
fn stores_result_for(vault: &Vault, entry: AuthorityEntryHash) -> bool {
    vault
        .export_signed_authority_history()
        .expect("the stored authority rows")
        .iter()
        .any(|bytes| {
            matches!(
                decode_authority_log_entry_body(bytes).expect("a stored row").op,
                AuthorityOp::ResidenceResult(result) if result.directive_entry == entry
            )
        })
}

/// This install's own-device connection; the tests' acts dial no home.
fn connection(vault: &Arc<Vault>) -> SyncConnection {
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "withheld-cosign-below-floor",
    ));
    SyncConnection::new(manager, ConnectionConfig::default()).expect("this install's connection")
}

/// B is a prune directive to this install, which read it as pending before R.
/// It runs after R: the fold took B out, so its result is refused and the
/// prune beside it commits nothing (review test 2).
#[test]
fn a_prune_directive_run_after_its_cosigner_is_revoked_records_no_result_and_prunes_nothing() {
    run_async("withheld-prune-directive", || async {
        let item = EntityId::now();
        let (withheld, pending) =
            withhold_directive_here(EntityId::now(), ResidenceAct::Prune { before: u64::MAX });
        cache_thin_item(&withheld.rooted.vault, item);
        let delivered = deliver_revocation(withheld);
        let vault = &delivered.rooted.vault;
        let ran = apply_residence_directive(&connection(vault), &pending).await;
        assert!(
            format!("{ran:?}").contains("no longer counts"),
            "a directive the fold took out since it was read as pending must record no result: \
             it ran {ran:?}"
        );
        assert!(
            cache_row(vault, "ro:e:", item).is_some(),
            "the prune beside a refused result commits nothing: the cached copy stays"
        );
        assert!(
            !stores_result_for(vault, delivered.withheld),
            "no result row is stored for a directive that no longer counts"
        );
    });
}

/// B is an open directive to this install, of an item it holds a cached copy
/// of, read as pending before R. It runs after R: the fold took B out, so its
/// result is refused and the open beside it commits nothing, not even the
/// touch it stamps on the cached copy (review test 3).
#[test]
fn an_open_directive_run_after_its_cosigner_is_revoked_stamps_nothing_and_records_no_result() {
    run_async("withheld-open-directive", || async {
        let item = EntityId::now();
        let open = ResidenceAct::Open {
            window: WINDOW.to_owned(),
            item,
        };
        let (withheld, pending) = withhold_directive_here(EntityId::now(), open);
        cache_thin_item(&withheld.rooted.vault, item);
        let delivered = deliver_revocation(withheld);
        let vault = &delivered.rooted.vault;
        let ran = apply_residence_directive(&connection(vault), &pending).await;
        assert!(
            format!("{ran:?}").contains("no longer counts"),
            "a directive the fold took out since it was read as pending must record no result: \
             it ran {ran:?}"
        );
        assert_eq!(
            cache_row(vault, "rt:e:", item),
            Some(CACHED_TOUCH.to_be_bytes().to_vec()),
            "the open beside a refused result commits nothing: the cached copy's touch stays"
        );
        assert!(
            !stores_result_for(vault, delivered.withheld),
            "no result row is stored for a directive that no longer counts"
        );
    });
}

/// The peer vault of the pact variants.
const PEER_VAULT_ID: AuthorityVaultId = [0x56; 32];

/// A Connect of pact `pact_id` over `grant`, sharing everything both ways,
/// with the gesture of the peer's owner key (outside this vault's roster)
/// over the side-symmetric transcript.
fn connect_of(vault_id: AuthorityVaultId, pact_id: [u8; 32], grant: EntityId) -> AuthorityOp {
    connect_gestured_by(
        vault_id,
        pact_id,
        grant,
        &SigningKey::from_bytes(&[0x50; 32]),
    )
}

/// [`connect_of`] with `peer` as the peer owner key that signs the gesture:
/// the key the pact pins.
fn connect_gestured_by(
    vault_id: AuthorityVaultId,
    pact_id: [u8; 32],
    grant: EntityId,
    peer: &SigningKey,
) -> AuthorityOp {
    pact_row(
        (FederationLifecycleKind::Connect, 1),
        (vault_id, PEER_VAULT_ID),
        pact_id,
        grant,
        peer,
    )
}

/// A dual-signed row of pact `pact_id` over `grant` between this vault and
/// the peer vault, of `kind` at `epoch`: a Connect at epoch 1, or a re-pact
/// (a Rescope with no effective scope) past it. Each shares everything both
/// ways under one commitment and nonce, with the gesture of `peer`, a key
/// outside this vault's roster, over the side-symmetric transcript.
fn pact_row(
    (kind, epoch): (FederationLifecycleKind, u64),
    (vault_id, peer_vault_id): (AuthorityVaultId, AuthorityVaultId),
    pact_id: [u8; 32],
    grant: EntityId,
    peer: &SigningKey,
) -> AuthorityOp {
    let pact_nonce = [0x4E; 16];
    let open = FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    };
    let scope = FederationPactScope {
        lo_to_hi: open.clone(),
        hi_to_lo: open,
    };
    // The fold takes the signed commitment as it stands, without the
    // opening key, so any key keys it here.
    let scope_digest = federation_scope_digest(
        &[0x68; 32],
        &pact_nonce,
        &encode_federation_pact_scope(&scope).expect("a canonical scope"),
    );
    let gesture = sign_federation_pact_gesture(
        kind,
        &pact_id,
        &vault_id,
        &peer_vault_id,
        epoch,
        &scope_digest,
        None,
        &pact_nonce,
        key_of(peer),
        |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
    )
    .expect("the peer's gesture");
    AuthorityOp::FederationLifecycle(FederationLifecycleAction {
        kind,
        pact_id,
        grant_ref: grant,
        peer_vault_id,
        pact_epoch: epoch,
        pact_scope: Some(scope),
        effective_scope: None,
        scope_digest: Some(scope_digest),
        gesture: Some(gesture),
        successor_vault_id: None,
        pact_nonce,
    })
}

/// B is a Connect with the peer's gesture: a federation pact over a grant.
#[test]
fn a_withheld_connect_cosigned_by_a_revoked_owner_key_holds_its_pact_suspended() {
    let pact_id = [0x70; 32];
    let grant = EntityId::now();
    let delivered = deliver_withheld(|_, _, _, vault_id| connect_of(vault_id, pact_id, grant));
    let fold = &delivered.fold;
    let activation = federation_grant_activation(fold, &grant);
    assert!(
        matches!(
            activation,
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        ),
        "the pact a forked Connect set up, whose cosigner is revoked, must confer nothing \
         and stay open to an honest Disconnect or re-pact: the grant reads {activation:?}; \
         issues {:?}",
        fold.issues
    );
    assert!(
        fold.federation_grant_bindings
            .get(&grant)
            .is_some_and(|pacts| pacts.contains(&pact_id)),
        "the grant stays bound to the held pact, so it never reads as unpacted; issues {:?}",
        fold.issues
    );
    assert!(
        !applied(fold).contains(&delivered.withheld),
        "the forked Connect leaves the valid rows at once; issues {:?}",
        fold.issues
    );
}

/// After R, a live owner key ends the held pact: its Disconnect at the
/// pact's epoch, on R, which holds B, folds, and the pact ends rather than
/// stays held.
#[test]
fn an_owner_disconnect_still_ends_the_pact_a_withheld_connect_set_up() {
    let pact_id = [0x71; 32];
    let grant = EntityId::now();
    let delivered = deliver_withheld(|_, _, _, vault_id| connect_of(vault_id, pact_id, grant));
    let revoking_owner = SigningKey::from_bytes(&[0x52; 32]);
    let disconnect = row_signed_by(
        &delivered.rooted,
        &revoking_owner,
        &[],
        2,
        vec![delivered.revocation],
        AuthorityOp::FederationLifecycle(FederationLifecycleAction {
            kind: FederationLifecycleKind::Disconnect,
            pact_id,
            grant_ref: grant,
            peer_vault_id: PEER_VAULT_ID,
            pact_epoch: 1,
            pact_scope: None,
            effective_scope: None,
            scope_digest: None,
            gesture: None,
            successor_vault_id: None,
            pact_nonce: [0x44; 16],
        }),
    );
    let arrival = put(&delivered.rooted, &disconnect);
    let fold = delivered.rooted.vault.authority_fold().expect("the fold");
    assert!(
        applied(&fold).contains(&hash_of(&disconnect)),
        "the owner's Disconnect folds; put {arrival}, issues {:?}",
        fold.issues
    );
    let activation = federation_grant_activation(&fold, &grant);
    assert!(
        matches!(
            activation,
            FederationGrantActivation::Inactive(FederationPactStatus::Disconnected)
        ),
        "the Disconnect ends the pact: the grant reads {activation:?}; issues {:?}",
        fold.issues
    );
}

/// After R, the owner ends the held pact through the Disconnect door. The
/// door names the heads, and an expired row of the pact that no head holds
/// beside them, so its Disconnect finds the pact (REVIEW-9609 rounds 1 and
/// 2); here R holds B.
#[test]
fn the_owner_disconnect_door_ends_the_pact_a_withheld_connect_set_up() {
    let pact_id = [0x72; 32];
    let grant = EntityId::now();
    let delivered = deliver_withheld(|_, _, _, vault_id| connect_of(vault_id, pact_id, grant));
    let rooted = &delivered.rooted;
    let ended = rooted
        .vault
        .disconnect_connect_as(&rooted.proof, &rooted.issuer, pact_id);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        ended
            .as_ref()
            .is_ok_and(|pact| pact.status == FederationPactStatus::Disconnected),
        "the owner's Disconnect door ends the held pact: it answered {ended:?}; issues {:?}",
        fold.issues
    );
    let activation = federation_grant_activation(&fold, &grant);
    assert!(
        matches!(
            activation,
            FederationGrantActivation::Inactive(FederationPactStatus::Disconnected)
        ),
        "the fold ends the pact: the grant reads {activation:?}; issues {:?}",
        fold.issues
    );
    assert!(
        !applied(&fold).contains(&delivered.withheld),
        "B stays out of the valid rows; issues {:?}",
        fold.issues
    );
}

/// After R, the owner's narrowing door refuses the held pact: a narrowing
/// keeps the ceiling only the expired B set, and the fold refuses it on a
/// pact a merge suspended (REVIEW-9609 round 2).
#[test]
fn the_owner_narrowing_door_refuses_the_pact_a_withheld_connect_set_up() {
    let pact_id = [0x75; 32];
    let grant = EntityId::now();
    let delivered = deliver_withheld(|_, _, _, vault_id| connect_of(vault_id, pact_id, grant));
    let rooted = &delivered.rooted;
    let narrowest = FederationDirectionScope {
        worlds: ScopeAxis::Bottom,
        facets: ScopeAxis::Bottom,
        bands: ScopeAxis::Bottom,
    };
    let narrowed =
        rooted
            .vault
            .narrow_connect_as(&rooted.proof, &rooted.issuer, pact_id, 1, narrowest);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        narrowed
            .as_ref()
            .is_err_and(|refusal| refusal.to_string().contains("held suspended")),
        "the narrowing door refuses the held pact for its status: it answered {narrowed:?}; \
         issues {:?}",
        fold.issues
    );
    let activation = federation_grant_activation(&fold, &grant);
    assert!(
        matches!(
            activation,
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        ),
        "the pact stays held: the grant reads {activation:?}; issues {:?}",
        fold.issues
    );
}

/// The two peer owner keys of the pin variants, the lesser first: the merge
/// of two agreeing Connects pins the lesser.
fn peer_keys_lesser_first() -> (SigningKey, SigningKey) {
    let one = SigningKey::from_bytes(&[0x61; 32]);
    let two = SigningKey::from_bytes(&[0x62; 32]);
    if key_of(&one) < key_of(&two) {
        (one, two)
    } else {
        (two, one)
    }
}

/// O2 signs a live Connect A of the same pact on C, concurrent with B (on R
/// it would find B's pact and fold as a duplicate Connect), agreeing with B
/// on the ceiling, with the gesture of `live_peer`; the fold after A.
fn deliver_live_twin(
    pact_id: [u8; 32],
    grant: EntityId,
    withheld_peer: SigningKey,
    live_peer: &SigningKey,
) -> (Delivered, AuthorityFold) {
    let delivered = deliver_withheld(move |_, _, _, vault_id| {
        connect_gestured_by(vault_id, pact_id, grant, &withheld_peer)
    });
    let revoking_owner = SigningKey::from_bytes(&[0x52; 32]);
    let live = row_signed_by(
        &delivered.rooted,
        &revoking_owner,
        &[],
        2,
        vec![delivered.published],
        connect_gestured_by(delivered.rooted.vault_id, pact_id, grant, live_peer),
    );
    let arrival = put(&delivered.rooted, &live);
    let fold = delivered.rooted.vault.authority_fold().expect("the fold");
    assert!(
        applied(&fold).contains(&hash_of(&live)),
        "setup: the live Connect A folds; put {arrival}, issues {:?}",
        fold.issues
    );
    (delivered, fold)
}

/// B pins the lesser peer key, and a live Connect A agrees with B on the
/// ceiling but pins the other. The merge keeps B's key, which only the
/// expired B backs, so A renews nothing and the pact stays held
/// (REVIEW-9609 round 1).
#[test]
fn a_live_connect_pinning_another_peer_never_renews_the_pact_a_withheld_connect_pinned() {
    let pact_id = [0x73; 32];
    let grant = EntityId::now();
    let (lesser, greater) = peer_keys_lesser_first();
    let (_delivered, fold) = deliver_live_twin(pact_id, grant, lesser, &greater);
    let activation = federation_grant_activation(&fold, &grant);
    assert!(
        matches!(
            activation,
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        ),
        "the pact pins the peer key only the expired B gave, so it must confer nothing: the \
         grant reads {activation:?}; issues {:?}",
        fold.issues
    );
}

/// A live Connect A that agrees with B on the ceiling and pins the same peer
/// key renews the pact, as a live row renews a binding's tuple.
#[test]
fn a_live_connect_pinning_the_same_peer_renews_the_pact_a_withheld_connect_set_up() {
    let pact_id = [0x74; 32];
    let grant = EntityId::now();
    let (lesser, _) = peer_keys_lesser_first();
    let live_peer = lesser.clone();
    let (_delivered, fold) = deliver_live_twin(pact_id, grant, lesser, &live_peer);
    let activation = federation_grant_activation(&fold, &grant);
    assert!(
        matches!(activation, FederationGrantActivation::Active),
        "a live Connect backing the same ceiling and pin renews the pact: the grant reads \
         {activation:?}; issues {:?}",
        fold.issues
    );
}

/// A peer vault's genesis, its host device `host` an owner and admin: the
/// peer's admitted log makes `host` a consent root, whose gesture verifies
/// for a pact pinned to another key of that peer (FED-03). The peer vault's
/// id is the genesis row's own hash.
fn peer_genesis(host: &SigningKey) -> AuthorityLogEntry {
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key_of(host),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [0x47; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        signer: signature_slot(key_of(host)),
        cosigns: Vec::new(),
        ts: 1,
        overlay_seed: None,
    };
    entry.overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&entry.op)
        .expect("authority overlay seed");
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = host.sign(&transcript).to_bytes().to_vec();
    entry
}

/// B is a Connect pinning the lesser peer key. After R this vault admits the
/// peer's log, whose owner key is the greater one, and O2 signs a re-pact on
/// R with that key's gesture: it verifies, moves the pact's ceiling on to
/// epoch 2 and keeps the pin it found. No live row backs that pin, only the
/// expired B, so the pact stays held (review test 4).
#[test]
fn a_re_pact_another_peer_roster_key_gestures_leaves_the_pact_a_withheld_connect_pinned_held() {
    let pact_id = [0x76; 32];
    let grant = EntityId::now();
    let (pinned, roster_key) = peer_keys_lesser_first();
    let genesis = peer_genesis(&roster_key);
    let peer_vault_id = genesis_vault_id(&genesis).expect("the peer vault's id");
    let delivered = deliver_withheld(|_, _, _, vault_id| {
        pact_row(
            (FederationLifecycleKind::Connect, 1),
            (vault_id, peer_vault_id),
            pact_id,
            grant,
            &pinned,
        )
    });
    let rooted = &delivered.rooted;
    admit_peer_authority_log_entry(
        &rooted.vault,
        &peer_vault_id,
        &encode_authority_log_entry_body(&genesis).expect("the peer genesis's body"),
    )
    .expect("this vault admits the peer's genesis");
    let revoking_owner = SigningKey::from_bytes(&[0x52; 32]);
    let repact = row_signed_by(
        rooted,
        &revoking_owner,
        &[],
        2,
        vec![delivered.revocation],
        pact_row(
            (FederationLifecycleKind::Rescope, 2),
            (rooted.vault_id, peer_vault_id),
            pact_id,
            grant,
            &roster_key,
        ),
    );
    let arrival = put(rooted, &repact);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        applied(&fold).contains(&hash_of(&repact)),
        "setup: the re-pact the peer's roster key gestures folds; put {arrival}, issues {:?}",
        fold.issues
    );
    let pact = &fold.federation_pacts[&pact_id];
    assert!(
        pact.pact_epoch == 2 && pact.peer_owner_key == key_of(&pinned),
        "setup: the re-pact moved the ceiling on to epoch 2 and kept B's pin; pact {pact:?}"
    );
    let activation = federation_grant_activation(&fold, &grant);
    assert!(
        matches!(
            activation,
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        ),
        "a re-pact another key of the peer's roster gestures backs no pin, so the pact whose \
         pin only the expired B backs must confer nothing: the grant reads {activation:?}; \
         issues {:?}",
        fold.issues
    );
}

/// How many more expired Connects of the pact than B the next test makes:
/// with R, the one head, they are one more than `MAX_PARENTS` (32).
const EXPIRED_BESIDE: u8 = 33;

/// B is a Connect, and K withholds 33 more Connects of the same pact below
/// its floor, each cosigned by O and each with another peer's gesture, on
/// P. All 34 expire at R, which names only C and B, so no head holds the 33.
/// The owner's Disconnect door names them beside R, past what one row names,
/// so it joins them with R first and its Disconnect lands on the join
/// (review test 5).
#[test]
fn the_owner_disconnect_door_ends_a_held_pact_past_max_parents_expired_rows() {
    let pact_id = [0x77; 32];
    let grant = EntityId::now();
    let rooted = rooted();
    let machine = admit_machine(&rooted);
    let withheld = withhold(rooted, machine, |_, _, _, vault_id| {
        connect_of(vault_id, pact_id, grant)
    });
    let agent = SigningKey::from_bytes(&[0x4B; 32]);
    let revoked_owner = SigningKey::from_bytes(&[0x4F; 32]);
    let beside: Vec<AuthorityEntryHash> = (0..EXPIRED_BESIDE)
        .map(|index| {
            let peer = SigningKey::from_bytes(&[0x80 + index; 32]);
            let row = row_signed_by(
                &withheld.rooted,
                &agent,
                &[&revoked_owner],
                5,
                vec![withheld.forked_on],
                connect_gestured_by(withheld.rooted.vault_id, pact_id, grant, &peer),
            );
            let arrival = put(&withheld.rooted, &row);
            assert_eq!(arrival, "stored", "setup: K's Connect {index} is stored");
            hash_of(&row)
        })
        .collect();
    let fold = withheld.rooted.vault.authority_fold().expect("the fold");
    let activation = federation_grant_activation(&fold, &grant);
    assert!(
        beside.iter().all(|hash| applied(&fold).contains(hash))
            && matches!(activation, FederationGrantActivation::Active),
        "setup: before R the fold counts every Connect and they agree on the pact, which \
         confers: the grant reads {activation:?}; issues {:?}",
        fold.issues
    );

    let delivered = deliver_revocation(withheld);
    let fold = &delivered.fold;
    let activation = federation_grant_activation(fold, &grant);
    assert!(
        beside.iter().all(|hash| {
            !applied(fold).contains(hash)
                && fold
                    .issues
                    .contains(&AuthorityFoldIssue::StaleRosterApproval(*hash))
        }) && matches!(
            activation,
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        ),
        "setup: after R every forked Connect expires and the pact is held: the grant reads \
         {activation:?}; issues {:?}",
        fold.issues
    );

    let rooted = &delivered.rooted;
    let ended = rooted
        .vault
        .disconnect_connect_as(&rooted.proof, &rooted.issuer, pact_id);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        ended
            .as_ref()
            .is_ok_and(|pact| pact.status == FederationPactStatus::Disconnected),
        "the owner's Disconnect door ends a held pact whose expired rows no head holds are \
         more than one row names: it answered {ended:?}; issues {:?}",
        fold.issues
    );
    let activation = federation_grant_activation(&fold, &grant);
    assert!(
        matches!(
            activation,
            FederationGrantActivation::Inactive(FederationPactStatus::Disconnected)
        ) && beside.iter().all(|hash| !applied(&fold).contains(hash)),
        "the fold ends the pact, and no expired Connect returns to the valid rows: the grant \
         reads {activation:?}; issues {:?}",
        fold.issues
    );
}
