//! A roster key's rows fold to the same roster on every install, whatever
//! order they arrive in ([ARRIVAL-FLOOR-SIBLING-DIVERGENCE], root FIX-LIST).
//!
//! Each stored row keeps the highest sequence its signer had reached on this
//! install before the row arrived, and a row below that mark is refused. When
//! one key signs two sibling rows, neither names the other, so an install
//! that receives the higher one first refused the lower one: two installs
//! that hold the same rows held different rosters. An agent enrolment then
//! counted on one install and not on the other, and a revocation beside a
//! later enrolment left the revoked key live on the install that received
//! the revocation last. Now a roster row is judged on its signer's causal
//! order alone, so both installs hold the same roster. A roster row also
//! vouches for its own signer's rows below it in its ancestry, so a
//! revocation on a withdrawal that reached the install past the floor lands
//! there too (Sol review F1). It vouches for nothing that grants: a machine
//! mark that reached an install past the floor stays held there, though a
//! handoff names it (Astra review F2). A row that its own ancestry already shows its
//! signer past is still refused on every install (the control). A parent of
//! another signer that this install's floor refuses still holds a roster row
//! back (root FIX-LIST [ROSTER-ROW-CROSS-SIGNER-FLOORED-PARENT]).

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityEntryHash, AuthorityFold,
    AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineOwnership, MachineProfile, MachineRole, ROLE_ADMIN, ROLE_AGENT,
    ROLE_OWNER, authority_entry_hash, authority_transcript, genesis_vault_id,
    machine_profile_proof_transcript,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent: Option<&AuthorityLogEntry>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parent
            .map(|parent| vec![authority_entry_hash(parent).expect("parent hash")])
            .unwrap_or_default(),
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
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

/// The owner's genesis and the vault it founds.
fn genesis(owner: &SigningKey, nonce: u8) -> (AuthorityLogEntry, AuthorityVaultId) {
    let genesis = signed(
        None,
        0,
        None,
        AuthorityOp::Genesis {
            device: device(key_of(owner), ROLE_OWNER | ROLE_ADMIN),
            genesis_nonce: [nonce; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        owner,
    );
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    (genesis, vault_id)
}

/// `signer` enrols the agent key `enrolled` on `parent` at `seq`.
fn enrolment(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    enrolled: &SigningKey,
) -> AuthorityLogEntry {
    signed(
        Some(vault_id),
        seq,
        Some(parent),
        AuthorityOp::EnrollDevice {
            device: device(key_of(enrolled), ROLE_AGENT),
        },
        signer,
    )
}

/// The owner's "yours" mark of `machine`, whose install key is
/// `machine_key`: its first revision, signed by an owner roster key with no
/// carrier, as a roster revision is.
fn yours_mark(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    machine_key: &SigningKey,
) -> AuthorityOp {
    let machine_key_bytes = machine_key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = machine_key
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key_bytes,
            device_class,
            &encryption_key,
        ))
        .to_bytes();
    AuthorityOp::MachineProfile(MachineProfile {
        machine,
        owner: EntityId::now(),
        machine_key: machine_key_bytes,
        device_class,
        encryption_key,
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    })
}

fn hash_of(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("row hash")
}

/// One install: a fresh vault that receives `rows` one at a time, in the
/// order given, each through the authority write door on its own, as rows
/// that sync delivers in that order arrive. Returns each put's outcome and
/// the install's fold.
struct Install {
    _dir: tempfile::TempDir,
    puts: Vec<String>,
    fold: AuthorityFold,
}

fn install_receiving(rows: &[&AuthorityLogEntry]) -> Install {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let puts = rows
        .iter()
        .map(|row| match vault.put_authority_log_entry(row, AT, 2) {
            Ok(_) => "stored".to_owned(),
            Err(error) => format!("refused: {:?}", error.kind()),
        })
        .collect();
    let fold = vault.authority_fold().expect("the install folds its log");
    Install {
        _dir: dir,
        puts,
        fold,
    }
}

fn applied(fold: &AuthorityFold) -> BTreeSet<AuthorityEntryHash> {
    fold.valid_entries.iter().copied().collect()
}

fn is_live(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    fold.roster
        .get(key)
        .is_some_and(|device| !device.revoked && device.roles != 0)
}

/// The finding's case: one roster key signs two agent enrolments on the
/// same parent, at sequences 1 and 2. Install I receives them in that order,
/// install J in the other. Both must hold both agents, and apply the same
/// rows.
#[test]
fn sibling_enrolments_hold_the_same_roster_in_either_arrival_order() {
    let owner = SigningKey::from_bytes(&[211; 32]);
    let first_agent = SigningKey::from_bytes(&[212; 32]);
    let second_agent = SigningKey::from_bytes(&[213; 32]);
    let (genesis, vault_id) = genesis(&owner, 214);
    let lower = enrolment(vault_id, &genesis, &owner, 1, &first_agent);
    let higher = enrolment(vault_id, &genesis, &owner, 2, &second_agent);

    let in_order = install_receiving(&[&genesis, &lower, &higher]);
    let reversed = install_receiving(&[&genesis, &higher, &lower]);

    for (name, install) in [("I (1 then 2)", &in_order), ("J (2 then 1)", &reversed)] {
        assert!(
            is_live(&install.fold, &key_of(&first_agent))
                && is_live(&install.fold, &key_of(&second_agent)),
            "install {name} must hold both agents the owner enrolled; puts {:?}, issues {:?}",
            install.puts,
            install.fold.issues
        );
    }
    let all = [&genesis, &lower, &higher]
        .into_iter()
        .map(hash_of)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        applied(&in_order.fold),
        all,
        "install I applies all three rows"
    );
    assert_eq!(
        applied(&reversed.fold),
        all,
        "install J applies the same rows as install I; puts {:?}, issues {:?}",
        reversed.puts,
        reversed.fold.issues
    );
}

/// A revocation beside a later enrolment of the same key: the owner enrols
/// agent U (sequence 1), then on that row revokes U (2) and, as a sibling of
/// the revocation, enrols agent W (3). The install that receives the
/// enrolment of W before the revocation must still hold U revoked: a
/// revocation lost to arrival order leaves a revoked key live there.
#[test]
fn a_revocation_beside_a_later_enrolment_holds_in_either_arrival_order() {
    let owner = SigningKey::from_bytes(&[221; 32]);
    let revoked_agent = SigningKey::from_bytes(&[222; 32]);
    let later_agent = SigningKey::from_bytes(&[223; 32]);
    let (genesis, vault_id) = genesis(&owner, 224);
    let enrol_revoked = enrolment(vault_id, &genesis, &owner, 1, &revoked_agent);
    let revocation = signed(
        Some(vault_id),
        2,
        Some(&enrol_revoked),
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&revoked_agent),
        },
        &owner,
    );
    let enrol_later = enrolment(vault_id, &enrol_revoked, &owner, 3, &later_agent);

    let in_order = install_receiving(&[&genesis, &enrol_revoked, &revocation, &enrol_later]);
    let reversed = install_receiving(&[&genesis, &enrol_revoked, &enrol_later, &revocation]);

    for (name, install) in [
        ("I (revocation first)", &in_order),
        ("J (revocation last)", &reversed),
    ] {
        assert!(
            !is_live(&install.fold, &key_of(&revoked_agent)),
            "install {name} must hold the revoked agent revoked; puts {:?}, issues {:?}",
            install.puts,
            install.fold.issues
        );
        assert!(
            is_live(&install.fold, &key_of(&later_agent)),
            "install {name} holds the later agent; issues {:?}",
            install.fold.issues
        );
        assert!(
            applied(&install.fold).contains(&hash_of(&revocation)),
            "install {name} applies the revocation; puts {:?}, issues {:?}",
            install.puts,
            install.fold.issues
        );
    }
    assert_eq!(
        applied(&in_order.fold),
        applied(&reversed.fold),
        "both installs apply the same rows"
    );
}

/// A revocation on a row of its own signer that the floor refuses (Sol
/// review F1): the owner enrols agent U (sequence 1), on that row withdraws
/// a slip (2), and on the withdrawal revokes U (3); as a sibling of the
/// withdrawal it enrols agent W (4). Install J receives W's enrolment first,
/// so the withdrawal and the revocation both reach it below the owner's
/// floor. The revocation names the withdrawal, its own signer's row below
/// it, so it vouches for it: U must stay revoked on both installs.
#[test]
fn a_revocation_on_a_withdrawal_past_the_floor_holds_in_either_arrival_order() {
    let owner = SigningKey::from_bytes(&[241; 32]);
    let revoked_agent = SigningKey::from_bytes(&[242; 32]);
    let later_agent = SigningKey::from_bytes(&[243; 32]);
    let (genesis, vault_id) = genesis(&owner, 244);
    let enrol_revoked = enrolment(vault_id, &genesis, &owner, 1, &revoked_agent);
    let withdrawal = signed(
        Some(vault_id),
        2,
        Some(&enrol_revoked),
        AuthorityOp::SlipRevoke { slip_id: [245; 32] },
        &owner,
    );
    let revocation = signed(
        Some(vault_id),
        3,
        Some(&withdrawal),
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&revoked_agent),
        },
        &owner,
    );
    let enrol_later = enrolment(vault_id, &enrol_revoked, &owner, 4, &later_agent);

    let in_order = install_receiving(&[
        &genesis,
        &enrol_revoked,
        &withdrawal,
        &revocation,
        &enrol_later,
    ]);
    let reversed = install_receiving(&[
        &genesis,
        &enrol_revoked,
        &enrol_later,
        &withdrawal,
        &revocation,
    ]);

    for (name, install) in [
        ("I (withdrawal and revocation first)", &in_order),
        ("J (withdrawal and revocation last)", &reversed),
    ] {
        assert!(
            !is_live(&install.fold, &key_of(&revoked_agent)),
            "install {name} must hold the revoked agent revoked; puts {:?}, issues {:?}",
            install.puts,
            install.fold.issues
        );
        assert!(
            is_live(&install.fold, &key_of(&later_agent)),
            "install {name} holds the later agent; issues {:?}",
            install.fold.issues
        );
    }
    let all = [
        &genesis,
        &enrol_revoked,
        &withdrawal,
        &revocation,
        &enrol_later,
    ]
    .into_iter()
    .map(hash_of)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        applied(&in_order.fold),
        all,
        "install I applies all five rows"
    );
    assert_eq!(
        applied(&reversed.fold),
        all,
        "install J applies the same rows as install I; puts {:?}, issues {:?}",
        reversed.puts,
        reversed.fold.issues
    );
}

/// A roster row vouches for nothing that grants (Astra review F2): the
/// owner marks machine M "yours" (sequence 1), on the mark hands the vault
/// to a fresh owner key (2), and as a sibling of the mark enrols agent U
/// (3). Install J receives U's enrolment first, so the mark reaches it below
/// the owner's floor and lands restriction only: J must not count M as the
/// owner's, though the handoff names the mark. Install I, which received the
/// mark before the owner's later row, counts M. Both settle the handoff.
#[test]
fn a_handoff_on_a_mark_past_the_floor_leaves_the_machine_held() {
    let owner = SigningKey::from_bytes(&[251; 32]);
    let successor = SigningKey::from_bytes(&[252; 32]);
    let agent = SigningKey::from_bytes(&[253; 32]);
    let machine_key = SigningKey::from_bytes(&[254; 32]);
    let machine = EntityId::now();
    let (genesis, vault_id) = genesis(&owner, 255);
    let mark = signed(
        Some(vault_id),
        1,
        Some(&genesis),
        yours_mark(vault_id, machine, &machine_key),
        &owner,
    );
    let handoff = signed(
        Some(vault_id),
        2,
        Some(&mark),
        AuthorityOp::ReRoot {
            new_device: device(key_of(&successor), ROLE_OWNER | ROLE_ADMIN),
        },
        &owner,
    );
    let enrol_agent = enrolment(vault_id, &genesis, &owner, 3, &agent);

    let in_order = install_receiving(&[&genesis, &mark, &enrol_agent, &handoff]);
    let reversed = install_receiving(&[&genesis, &enrol_agent, &mark, &handoff]);

    for (name, install) in [("I (mark first)", &in_order), ("J (mark late)", &reversed)] {
        assert!(
            applied(&install.fold).contains(&hash_of(&handoff))
                && is_live(&install.fold, &key_of(&successor)),
            "install {name} settles the handoff to the successor; puts {:?}, issues {:?}",
            install.puts,
            install.fold.issues
        );
    }
    assert!(
        in_order.fold.trusted_machine(machine).is_some(),
        "install I received the mark before the owner's later row and counts the machine as \
         the owner's; puts {:?}, issues {:?}",
        in_order.puts,
        in_order.fold.issues
    );
    assert!(
        reversed.fold.trusted_machine(machine).is_none(),
        "install J received the mark past the owner's floor: the handoff on it must not make \
         J count the machine as the owner's; puts {:?}, issues {:?}",
        reversed.puts,
        reversed.fold.issues
    );
}

/// The control: a row that names, among its own ancestors, a row of its
/// signer at a higher sequence goes back on its signer's own order, which
/// every install can see from the rows alone. Every install refuses it, the
/// same way, before and after the fix.
#[test]
fn a_row_below_its_signers_sequence_in_its_own_ancestry_stays_refused() {
    let owner = SigningKey::from_bytes(&[231; 32]);
    let first_agent = SigningKey::from_bytes(&[232; 32]);
    let second_agent = SigningKey::from_bytes(&[233; 32]);
    let (genesis, vault_id) = genesis(&owner, 234);
    let higher = enrolment(vault_id, &genesis, &owner, 2, &first_agent);
    let backward = enrolment(vault_id, &higher, &owner, 1, &second_agent);

    let install = install_receiving(&[&genesis, &higher, &backward]);

    assert!(
        is_live(&install.fold, &key_of(&first_agent)),
        "the forward enrolment lands; issues {:?}",
        install.fold.issues
    );
    assert!(
        !is_live(&install.fold, &key_of(&second_agent))
            && !applied(&install.fold).contains(&hash_of(&backward)),
        "a row below its signer's own sequence in its ancestry is refused; puts {:?}, issues {:?}",
        install.puts,
        install.fold.issues
    );
    assert!(
        install.fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::NonMonotonicSeq(hash) if *hash == hash_of(&backward)
        )),
        "the refusal names the backward row as non-monotonic; issues {:?}",
        install.fold.issues
    );
}
