//! The floor probe folds a voucher's ancestry once, in the ancestor index's
//! id order, on the fold's own signature verdicts (row [ROSTER-KEY-LOG-FLOOD],
//! PR 3; Engine RULINGs 16 Nov 13:32 and 13:44 = A). It must answer every
//! probe as the rounds in hash order it replaced, each transition verifying
//! its row's signatures again.
//!
//! The test builds vault logs from the vault's own doors (the host root,
//! this install, two worlds, admitted machines) and folds, through
//! `test_doors::authority_floor_probe`, each row's probe both ways under no
//! floors, the rows' own floors, the floors the fold applies, and the rows'
//! own floors less each floored row in turn:
//! - a log of single-chain signers, with one more well-signed row the fold
//!   refuses and a row on top of it;
//! - a machine's forked chain: two branches of its rows from its admission,
//!   joined by a later row of the machine, so rows of each branch sit below
//!   their floors and the join vouches for them; and a row claiming a parent
//!   the log lacks.
//!
//! Each log prints one `PROBE-EQUIV` line. Green on the head only: the door
//! is new (the probe it tests is a rewrite, exact by construction).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test floor_probe_equivalence`.

#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerAct, OwnerActKind, ReadLocation,
    WorldPrivacy, WorldPrivacyEdit, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::authority_floor_probe::{ProbeEquivalence, probe_both_ways};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
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
        owner,
        proof,
        vault_id,
    }
}

/// The owner admits a machine whose install key the test holds, and returns
/// its id, its key and the entry that carried the admission.
fn admit_machine(rooted: &Rooted, seed: u8) -> (EntityId, SigningKey, AuthorityEntryHash) {
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
        .expect("the owner admits the machine")
        .into_standing()
        .expect("the owner's admission stands");
    let admission = folded
        .chains()
        .map(|(_, head)| head)
        .max_by_key(|head| head.profile.revision)
        .expect("the admission's revision")
        .entry;
    (machine, signing, admission)
}

/// The admitted machine's own world edit to `settings` at `seq` on
/// `parents`, signed by its install key.
fn machine_row(
    rooted: &Rooted,
    machine: EntityId,
    signing: &SigningKey,
    (world, settings): (EntityId, WorldPrivacy),
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
) -> AuthorityLogEntry {
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: parents,
        op: AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
            world,
            act: OwnerAct::by_owner(
                rooted.owner,
                OwnerActKind::WorldPrivacy,
                world,
                ActSurface::ThisInstall,
                [0; 32],
            ),
            machine,
            settings,
        }),
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

fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("hash")
}

/// The vault's own history: every row its doors wrote.
fn history(rooted: &Rooted) -> Vec<AuthorityLogEntry> {
    rooted
        .vault
        .export_signed_authority_history()
        .expect("the vault's history")
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a stored row"))
        .collect()
}

/// A world kept on no machine the vault admits: an edit that sets it is
/// well signed, and every fold refuses it.
fn nowhere() -> WorldPrivacy {
    WorldPrivacy {
        read: ReadLocation::OneMachine(EntityId::now()),
        ..WorldPrivacy::default()
    }
}

/// One vault's log from its own doors: the host root and the engine's
/// machines, this install marked the owner's, two worlds kept here, an
/// admitted machine and its own three-row chain; then a fourth row on that
/// chain that every fold refuses, and a fifth row on the fourth.
fn log_of_single_chain_signers() -> Vec<AuthorityLogEntry> {
    let rooted = rooted();
    let here = rooted
        .vault
        .local_machine()
        .expect("this install")
        .expect("this install's machine")
        .id;
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            here,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner marks this install yours");
    for name in ["Kept here", "Also kept here"] {
        let world = rooted
            .vault
            .create_world(&rooted.proof, name, rooted.vault.now_recorded_at())
            .expect("the owner's world");
        rooted
            .vault
            .set_world_privacy_as(
                &rooted.proof,
                ActSurface::ThisInstall,
                world,
                WorldPrivacy {
                    read: ReadLocation::OneMachine(here),
                    ..WorldPrivacy::default()
                },
                None,
            )
            .expect("the owner keeps the world on this install");
    }
    let (machine, signing, admission) = admit_machine(&rooted, 0xB1);
    let world = EntityId::now();
    let mut parent = admission;
    for seq in 1..=3 {
        let row = machine_row(
            &rooted,
            machine,
            &signing,
            (world, WorldPrivacy::default()),
            seq,
            vec![parent],
        );
        rooted
            .vault
            .put_authority_log_entry(&row, AT, 1)
            .expect("the admitted machine's row lands");
        parent = hash(&row);
    }
    let mut entries = history(&rooted);
    let refused = machine_row(
        &rooted,
        machine,
        &signing,
        (world, nowhere()),
        4,
        vec![parent],
    );
    let above_refused = machine_row(
        &rooted,
        machine,
        &signing,
        (world, WorldPrivacy::default()),
        5,
        vec![hash(&refused)],
    );
    entries.push(refused);
    entries.push(above_refused);
    entries
}

/// One vault's log in which an admitted machine forks its chain: rows 1 to 3
/// on one branch from its admission and rows 1 and 2 on another, so rows of
/// each branch sit below their floors, then row 4 joining both branches,
/// which vouches for them; and a row 5 on the join that also claims a
/// parent the log lacks.
fn log_of_a_forked_chain() -> Vec<AuthorityLogEntry> {
    let rooted = rooted();
    let (machine, signing, admission) = admit_machine(&rooted, 0xB2);
    let world = EntityId::now();
    let mut entries = history(&rooted);
    let mut heads = Vec::new();
    for (branch, length) in [(0_u8, 3_u64), (1, 2)] {
        let settings = WorldPrivacy {
            read: if branch == 0 {
                ReadLocation::Everywhere
            } else {
                ReadLocation::MyMachines
            },
            ..WorldPrivacy::default()
        };
        let mut parent = admission;
        for seq in 1..=length {
            let row = machine_row(
                &rooted,
                machine,
                &signing,
                (world, settings.clone()),
                seq,
                vec![parent],
            );
            parent = hash(&row);
            entries.push(row);
        }
        heads.push(parent);
    }
    let join = machine_row(
        &rooted,
        machine,
        &signing,
        (world, WorldPrivacy::default()),
        4,
        heads,
    );
    let past_the_log = machine_row(
        &rooted,
        machine,
        &signing,
        (world, WorldPrivacy::default()),
        5,
        vec![hash(&join), [0xEE; 32]],
    );
    entries.push(join);
    entries.push(past_the_log);
    entries
}

fn assert_probes_agree(name: &str, entries: &[AuthorityLogEntry]) -> ProbeEquivalence {
    let equivalence = probe_both_ways(entries);
    println!(
        "PROBE-EQUIV log={name} rows={} floor_maps={} asked={} folded={} disagreements={}",
        entries.len(),
        equivalence.floor_maps,
        equivalence.asked,
        equivalence.folded,
        equivalence.disagreements.len(),
    );
    assert!(
        equivalence.disagreements.is_empty(),
        "{name}: the probe in id order and the rounds disagree (row, floor map, rounds' \
         answer): {:?}",
        equivalence.disagreements
    );
    assert!(
        equivalence.folded > 0 && equivalence.folded < equivalence.asked,
        "{name}: some probes fold and some do not: {} of {}",
        equivalence.folded,
        equivalence.asked
    );
    equivalence
}

#[test]
fn the_probe_in_id_order_answers_a_log_of_single_chain_signers_as_the_rounds_did() {
    assert_probes_agree("single-chain", &log_of_single_chain_signers());
}

#[test]
fn the_probe_in_id_order_answers_a_forked_chain_as_the_rounds_did() {
    let equivalence = assert_probes_agree("forked-chain", &log_of_a_forked_chain());
    assert!(
        equivalence.floor_maps > 3,
        "the fork puts rows below their floors, so the rows' own floors are not empty: {} floor \
         maps",
        equivalence.floor_maps
    );
}
