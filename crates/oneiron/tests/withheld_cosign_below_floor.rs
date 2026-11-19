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
//! B at K's sequence 5, which K withholds. O2 revokes O on C. Then K, still
//! live, delivers B. B's sequence is below K's floor of 10, so the fold
//! counts B and records it as a SequenceFork (shape S). Because B is a fork
//! and its cosigner O is revoked in the final fold, B expires at once: it
//! binds nothing, is no handover evidence and lists no directive.
//!
//! B may also be a federation pact's Connect, with the peer's gesture. Then
//! the pact B set up is held suspended: it confers nothing, its grant stays
//! bound to it, so the grant never reads as unpacted (legacy allow), and an
//! owner key still live ends it with a Disconnect (PR 2 of the row).
//!
//! Expected (estimate, not run yet): red on main 64fa6f07, where B binds T
//! until the 24 h stale-roster window ends and the handover and the directive
//! stay valid for ever; green on the head of the fork-expiry PR. The pact
//! variant: red on that PR's head a04e1ddd, where B's pact stays active;
//! green on the head of the lifecycle PR. The Disconnect variant guards the
//! fix (an ended pact stays ended) and passes on both heads.
//!
//! Review round 1 of the lifecycle PR adds three. The owner's Disconnect door
//! on the held pact: red on a686d5db, where the door names only the heads,
//! which B left, and its Disconnect finds no pact. A live Connect A that
//! agrees with B on the ceiling but pins another peer key than B's lesser
//! one: red on a686d5db, where A renews the pact on the pin only B gave. A
//! live Connect pinning the same peer renews the pact and passes on both.
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
    FederationGrantActivation, FederationLifecycleAction, FederationLifecycleKind,
    FederationPactStatus, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerHandover, OwnerHandoverCause,
    OwnerKeyEnrollment, ROLE_AGENT, ResidenceAct, ResidenceDirective, actor_binding_is_active,
    authority_entry_hash, authority_transcript, federation_grant_activation,
    federation_scope_digest, machine_profile_proof_transcript, sign_federation_pact_gesture,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationDirectionScope, FederationPactScope, ScopeAxis, encode_federation_pact_scope,
};
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
    revocation: AuthorityEntryHash,
    rooted: Rooted,
    withheld: AuthorityEntryHash,
    fold: AuthorityFold,
}

/// Builds C6 with `withheld_op` as B's op (given the owner, the admitted
/// machine and T's key, and this vault's id): C, then B, then R on both.
fn deliver_withheld(
    withheld_op: impl FnOnce(EntityId, EntityId, &SigningKey, AuthorityVaultId) -> AuthorityOp,
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
        FederationLifecycleKind::Connect,
        &pact_id,
        &vault_id,
        &PEER_VAULT_ID,
        1,
        &scope_digest,
        None,
        &pact_nonce,
        key_of(peer),
        |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
    )
    .expect("the peer's gesture");
    AuthorityOp::FederationLifecycle(FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id,
        grant_ref: grant,
        peer_vault_id: PEER_VAULT_ID,
        pact_epoch: 1,
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

/// After B, a live owner key ends the held pact: its Disconnect at the
/// pact's epoch, on B and R, folds, and the pact ends rather than stays held.
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
        vec![delivered.withheld, delivered.revocation],
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

/// After B, the owner ends the held pact through the Disconnect door. The
/// expiry took B out of the heads, so the door names B beside them: without
/// B in its ancestry the Disconnect would find no pact (REVIEW-9609 round 1).
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

/// After B, O2 signs a live Connect A of the same pact on R, agreeing with B
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
        vec![delivered.revocation],
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
