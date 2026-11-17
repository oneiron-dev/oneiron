//! FIX OWNER-RESTORE-REFUSES-TASK-AUTHORITY-FACTS (Engine ruling TASK-FACT-ARCHIVE-CROSSING
//! = A, 17 Nov 00:02): "archives keep the facts (one true archive), and the import refuses a
//! foreign chain's facts as built". A TASK carries its authority facts (the Owner fact the
//! task door writes beside it, role 6), and a whole-vault archive carries them (ARCH-0027:339
//! #export-complete). The owner's restore lands each through the engine's fact restore door,
//! at its archived id and body, and counts it like a local write (ASK
//! OWNER-RESTORE-TASK-FACT-COUNT, option A): it enters this install's written-here index, and
//! with a signer loaded the import twins it under this install's signature. Every other
//! import refuses the fact at the raw put, as built.
//!
//! The first two tests are OPUS-UNBUILT3-B5's probe (branch
//! opus-unbuilt3-b5/archive-task-fact-probe e76f4e1bc0), the second extended to read the
//! restored owner.
//!
//! - `a_foreign_archives_task_authority_facts_are_refused_at_import`: guard, passes on the
//!   base and on the head.
//! - `an_owners_archive_with_a_task_restores_its_authority_facts`: red on the base (the
//!   import fails whole: "reserved task role is written only by its engine door").
//! - `a_cancelled_task_stays_cancelled_after_the_owners_restore`: red on the base, as above.
//! - `the_owners_restore_of_a_foreign_chains_archive_refuses_its_task_facts`: guard.
//! - `an_import_with_no_owner_refuses_the_owners_task_facts`: guard.
//! - `a_restored_fact_counts_on_a_second_device_of_a_rooted_vault`: red on the base, as
//!   above; on the head the restored facts' signed twins prove themselves on a device that
//!   holds no index entry for them.
//! - `the_owners_restore_counts_a_fact_the_vault_held_from_sync` (blind review P1,
//!   REVIEW-9365): red at 1d4c09536b55 (the import meets the fact held unchanged, skips it,
//!   and the task reads no owner); green on the head.
//! - `a_restored_fact_naming_this_machine_under_another_key_is_twinned` (blind review round 2
//!   P1, REVIEW-9365): red at dc76908e14 (the adoption takes a carrier that only names this
//!   install's machine for its own signature and writes no twin: 3 facts, and the second
//!   device reads the task open); green on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_task_authority_facts`.
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, LocalOpenProfile, MachineOwnership, MachineRole,
};
use oneiron::batch::export::VaultImportClassification;
use oneiron::consent::AuthenticatedOwner;
use oneiron::habit::TaskRole;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, TASK_AUTHORITY_FACT_SCHEMA_VERSION,
    TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind, TimeRange, Vault, VaultConfig,
};
use oneiron_authority::authority::carrier_transcript;
use oneiron_contracts::record_layout::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use oneiron_keystore::MemoryKeystore;
use rmpv::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 2026-03-15 00:00 UTC.
const T0: u64 = 1_773_532_800;

/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

/// The carrier transcript domain of a TASK fact (`task_authority::fact_proof`).
const TASK_FACT_CARRIER_DOMAIN: &[u8] = b"oneiron/task-fact/v2";

/// A personal vault rooted under its host, with a device keystore, and this
/// install profiled as the owner's own device: the machine whose key signs
/// its archive (as `signed_archive_provenance.rs` builds one).
fn profiled_vault(
    directory: &Path,
    host_secret: &[u8],
) -> Result<Vault, Box<dyn std::error::Error>> {
    let vault = Vault::open_owned(directory, VaultConfig::default())?;
    vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(host_secret)?;
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))?;
    Ok(vault)
}

/// A fresh destination, opened at least one wall-clock second after its
/// source, as `archive_restore_owner_settle.rs` opens one: its engine-seed
/// seconds differ from the source's.
fn open_later_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::default())?;
    Ok((directory, vault))
}

/// The owner of `vault`, as his session proves him.
fn owner_proof(vault: &Vault) -> Result<AuthenticatedOwner, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// One TASK the owner creates through the task door, which writes its Owner
/// fact beside it: the TASK and that fact.
fn owned_task(vault: &Vault) -> Result<(EntityId, EntityId), Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::from("file the quarterly report"),
            None,
            Some(owner),
            Some(T0),
        ))?
        .task_ref
        .expect("the TASK creation took effect");
    let facts = authority_facts(vault, task)?;
    assert_eq!(
        facts.len(),
        1,
        "the task door writes exactly the Owner fact beside the TASK"
    );
    Ok((task, facts[0]))
}

/// The TASK rows scoped to `task`: the authority facts about it.
fn authority_facts(vault: &Vault, task: EntityId) -> oneiron::Result<Vec<EntityId>> {
    let tasks = vault.entities_by_type(ENTITY_TYPE_TASK)?;
    Ok(vault
        .edges_in(&task)?
        .iter()
        .filter(|edge| edge.kind == EdgeKind::ScopedTo && tasks.contains(&edge.target))
        .map(|edge| edge.target)
        .collect())
}

fn holds_task_row(vault: &Vault, id: EntityId) -> oneiron::Result<bool> {
    Ok(vault.entities_by_type(ENTITY_TYPE_TASK)?.contains(&id))
}

/// Lands one fact row and its `ScopedTo` link to `task` as the vault's own machine sends
/// them to another device.
fn land_replicated_fact(vault: &Vault, row: EntityId, task: EntityId, body: &[u8]) {
    let now = vault.now_recorded_at();
    replay_entity(
        vault,
        ReplicatedEntity {
            id: row,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: 0,
            body,
        },
        ImportTier::OwnDevice,
    )
    .expect("the own-device replay door lands the row");
    vault
        .batch()
        .edge(&row, EdgeKind::ScopedTo, &task, SCOPED_TO_WEIGHT)
        .commit()
        .expect("the row's link to its task");
}

#[test]
fn a_foreign_archives_task_authority_facts_are_refused_at_import() -> TestResult {
    let (local_directory, other_directory) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let local = profiled_vault(local_directory.path(), b"archive task facts local")?;
    let other = profiled_vault(other_directory.path(), b"archive task facts other")?;
    let (task, fact) = owned_task(&other)?;
    let archive = other.export_whole_vault(true)?.bytes().to_vec();

    let receipt = local.classify_vault_archive(Cursor::new(archive.clone()), None)?;
    assert_eq!(
        receipt.classification,
        VaultImportClassification::ForeignAuthorityChain,
        "{receipt:?}"
    );
    let refused = local
        .import_whole_vault_archive(&archive)
        .expect_err("a foreign chain's task authority fact is refused at import");
    assert!(
        refused.to_string().contains("reserved task role"),
        "the import is refused at the task authority fact: {refused}"
    );
    assert!(
        !holds_task_row(&local, fact)?,
        "the foreign chain's fact does not land"
    );
    assert!(
        !holds_task_row(&local, task)?,
        "nothing of the refused import lands"
    );
    Ok(())
}

#[test]
fn an_owners_archive_with_a_task_restores_its_authority_facts() -> TestResult {
    let source_directory = tempfile::tempdir()?;
    let source = Vault::open(source_directory.path(), VaultConfig::default())?;
    let (task, fact) = owned_task(&source)?;
    let archive = source.export_whole_vault(true)?.bytes().to_vec();

    let (_dest_directory, dest) = open_later_vault()?;
    let owner = owner_proof(&dest)?;
    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
    {
        panic!("the owner's whole archive with a TASK must restore: {error:?}");
    }
    assert!(holds_task_row(&dest, task)?, "the TASK comes back");
    assert_eq!(
        authority_facts(&dest, task)?,
        vec![fact],
        "its Owner fact comes back with it, at its archived id"
    );
    let state = dest
        .task_authority_state(task)?
        .expect("the restored Owner fact counts on the restored vault");
    assert_eq!(state.owner_ref, dest.ensure_embedded_owner_actor()?);
    assert!(!state.cancelled);
    Ok(())
}

#[test]
fn a_cancelled_task_stays_cancelled_after_the_owners_restore() -> TestResult {
    let source_directory = tempfile::tempdir()?;
    let source = Vault::open(source_directory.path(), VaultConfig::default())?;
    let (task, _) = owned_task(&source)?;
    let owner = source.ensure_embedded_owner_actor()?;
    oneiron::test_doors::inquiry::cancel_task(&source, task, owner)?;
    assert!(
        source
            .task_authority_state(task)?
            .expect("the source counts its own Owner fact")
            .cancelled,
        "the source counts its own cancel"
    );
    let archive = source.export_whole_vault(true)?.bytes().to_vec();

    let (_dest_directory, dest) = open_later_vault()?;
    let proof = owner_proof(&dest)?;
    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &proof)
    {
        panic!("the owner's whole archive with a cancelled TASK must restore: {error:?}");
    }
    assert_eq!(
        authority_facts(&dest, task)?.len(),
        2,
        "the Owner fact and the Cancelled fact come back"
    );
    let state = dest
        .task_authority_state(task)?
        .expect("the restored Owner fact counts");
    assert_eq!(state.owner_ref, owner);
    assert!(state.cancelled, "the restored task stays cancelled");
    Ok(())
}

#[test]
fn the_owners_restore_of_a_foreign_chains_archive_refuses_its_task_facts() -> TestResult {
    let (local_directory, other_directory) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let local = profiled_vault(local_directory.path(), b"archive task facts owner local")?;
    let other = profiled_vault(other_directory.path(), b"archive task facts owner other")?;
    let (task, fact) = owned_task(&other)?;
    let archive = other.export_whole_vault(true)?.bytes().to_vec();
    assert_eq!(
        local
            .classify_vault_archive(Cursor::new(archive.clone()), None)?
            .classification,
        VaultImportClassification::ForeignAuthorityChain,
    );

    let owner = owner_proof(&local)?;
    let refused = local
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
        .expect_err("a foreign chain's archive is never a restore, so its fact is refused");
    assert!(
        refused.to_string().contains("reserved task role"),
        "the owner's import is refused at the task authority fact: {refused}"
    );
    assert!(!holds_task_row(&local, fact)?, "the fact does not land");
    assert!(
        !holds_task_row(&local, task)?,
        "nothing of the import lands"
    );
    Ok(())
}

#[test]
fn an_import_with_no_owner_refuses_the_owners_task_facts() -> TestResult {
    let source_directory = tempfile::tempdir()?;
    let source = Vault::open(source_directory.path(), VaultConfig::default())?;
    let (task, fact) = owned_task(&source)?;
    let archive = source.export_whole_vault(true)?.bytes().to_vec();

    let (_dest_directory, dest) = open_later_vault()?;
    let refused = dest
        .import_whole_vault_archive(&archive)
        .expect_err("only the owner's restore lands a task authority fact");
    assert!(
        refused.to_string().contains("reserved task role"),
        "the import is refused at the task authority fact: {refused}"
    );
    assert!(!holds_task_row(&dest, fact)?, "the fact does not land");
    assert!(!holds_task_row(&dest, task)?, "nothing of the import lands");
    Ok(())
}

#[test]
fn a_restored_fact_counts_on_a_second_device_of_a_rooted_vault() -> TestResult {
    let source_directory = tempfile::tempdir()?;
    let source = Vault::open(source_directory.path(), VaultConfig::default())?;
    let (task, fact) = owned_task(&source)?;
    let owner = source.ensure_embedded_owner_actor()?;
    oneiron::test_doors::inquiry::cancel_task(&source, task, owner)?;
    let archive = source.export_whole_vault(true)?.bytes().to_vec();

    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dest_directory = tempfile::tempdir()?;
    let dest = Vault::open_owned(dest_directory.path(), VaultConfig::device())?;
    dest.install_device_keystore(Arc::new(MemoryKeystore::default()));
    assert_eq!(
        dest.profile_local_open(Some(b"archive task facts rooted"), true)?,
        LocalOpenProfile::RootedAndProfiled,
    );
    let proof = owner_proof(&dest)?;
    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &proof)
    {
        panic!("the owner's whole archive must restore into a rooted vault: {error:?}");
    }
    let restored = authority_facts(&dest, task)?;
    assert!(
        restored.contains(&fact),
        "the Owner fact comes back at its archived id"
    );
    assert_eq!(
        restored.len(),
        4,
        "the two restored facts and a signed twin of each"
    );
    let here = dest
        .task_authority_state(task)?
        .expect("the restored Owner fact counts on the restored vault");
    assert_eq!(here.owner_ref, owner);
    assert!(here.cancelled, "the restored task stays cancelled");

    let vault_id = dest
        .authority_fold()?
        .vault_id
        .expect("the destination is rooted");
    let device_directory = tempfile::tempdir()?;
    let device = Vault::open(device_directory.path(), VaultConfig::device())?;
    device.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let key = device.machine_encryption_key(vault_id)?;
    let request = device.machine_enrolment_request(vault_id, key)?;
    dest.enroll_machine(
        &proof,
        ActSurface::ThisInstall,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )?;
    device.import_signed_authority_history(&dest.export_signed_authority_history()?)?;
    for row in restored {
        let raw = dest.get_raw(&row)?.expect("the fact row");
        land_replicated_fact(&device, row, task, &raw[ENTITY_METADATA_HEADER_LEN..]);
    }
    let there = device
        .task_authority_state(task)?
        .expect("the signed twin of the restored Owner fact counts on the device");
    assert_eq!(there.owner_ref, owner);
    assert!(
        there.cancelled,
        "the signed twin of the restored cancel counts on the device"
    );
    Ok(())
}

/// Blind review P1 (REVIEW-9365): a fact an own device sent here unsigned proves nothing
/// here. The owner's restore of the archive that holds it, byte for byte and at its own
/// times, meets the row unchanged; it counts the fact as one it lands, and twins it under
/// this install's signature.
#[test]
fn the_owners_restore_counts_a_fact_the_vault_held_from_sync() -> TestResult {
    let source_directory = tempfile::tempdir()?;
    let source = Vault::open(source_directory.path(), VaultConfig::default())?;
    let (task, fact) = owned_task(&source)?;
    let owner = source.ensure_embedded_owner_actor()?;
    let archive = source.export_whole_vault(true)?.bytes().to_vec();
    let raw = source.get_raw(&fact)?.expect("the source's Owner fact row");
    let header = EntityMetadataHeader::parse(&raw).expect("the fact row's header");

    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dest_directory = tempfile::tempdir()?;
    let dest = Vault::open_owned(dest_directory.path(), VaultConfig::device())?;
    dest.install_device_keystore(Arc::new(MemoryKeystore::default()));
    assert_eq!(
        dest.profile_local_open(Some(b"archive task facts held from sync"), true)?,
        LocalOpenProfile::RootedAndProfiled,
    );
    replay_entity(
        &dest,
        ReplicatedEntity {
            id: fact,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            row_version: 0,
            body: &raw[ENTITY_METADATA_HEADER_LEN..],
        },
        ImportTier::OwnDevice,
    )?;
    assert!(
        holds_task_row(&dest, fact)?,
        "the own-device replay door lands the source's unsigned Owner fact"
    );

    let proof = owner_proof(&dest)?;
    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &proof)
    {
        panic!("the owner's whole archive must restore over the held fact: {error:?}");
    }
    let state = dest
        .task_authority_state(task)?
        .expect("the owner's restore counts the fact the vault held from sync");
    assert_eq!(state.owner_ref, owner);
    let restored = authority_facts(&dest, task)?;
    assert!(restored.contains(&fact), "the held fact stays at its id");
    assert_eq!(restored.len(), 2, "the held fact and a signed twin of it");
    Ok(())
}

/// One current-schema fact of `kind` about `task` by `actor` at `at`, carried as machine
/// `machine` with a signature by `key` over the fact row `row` of the vault `vault_id`: the
/// signature verifies over the row, whoever holds the key (as `task_fact_carrier_proof.rs`
/// builds one).
fn carried_fact_body(
    vault_id: &[u8; 32],
    row: EntityId,
    machine: EntityId,
    key: &SigningKey,
    (task, kind, actor, at): (EntityId, TaskAuthorityFactKind, EntityId, u64),
) -> Vec<u8> {
    let encode = |entries: &[(Value, Value)]| {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(entries.to_vec()))
            .expect("encode fixture");
        bytes
    };
    let mut entries = vec![
        (
            Value::from("role"),
            Value::from(TaskRole::AuthorityFact.role_byte()),
        ),
        (
            Value::from("schema_version"),
            Value::from(TASK_AUTHORITY_FACT_SCHEMA_VERSION),
        ),
        (
            Value::from("subkind"),
            Value::from(TASK_AUTHORITY_FACT_SUBKIND),
        ),
        (Value::from("task_ref"), Value::from(task.to_hex())),
        (Value::from("kind"), Value::from(kind.as_byte())),
        (Value::from("actor_ref"), Value::from(actor.to_hex())),
        (Value::from("occurred_at"), Value::from(at)),
    ];
    let transcript = carrier_transcript(
        TASK_FACT_CARRIER_DOMAIN,
        vault_id,
        &row,
        &machine,
        &encode(&entries),
    );
    entries.extend([
        (
            Value::from("carrier_machine"),
            Value::from(machine.to_hex()),
        ),
        (
            Value::from("carrier_key"),
            Value::Binary(key.verifying_key().to_bytes().to_vec()),
        ),
        (
            Value::from("carrier_signature"),
            Value::Binary(key.sign(&transcript).to_bytes().to_vec()),
        ),
    ]);
    encode(&entries)
}

/// Blind review round 2 P1 (REVIEW-9365): an archived fact whose carrier names the restoring
/// install's machine, but under a key that install never held, is no signature of its own.
/// The owner's restore counts the fact here, and twins it under this install's signature, so
/// it counts on every device of the vault.
#[test]
fn a_restored_fact_naming_this_machine_under_another_key_is_twinned() -> TestResult {
    let source_directory = tempfile::tempdir()?;
    let source = Vault::open(source_directory.path(), VaultConfig::default())?;
    let (task, fact) = owned_task(&source)?;
    let owner = source.ensure_embedded_owner_actor()?;

    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dest_directory = tempfile::tempdir()?;
    let dest = Vault::open_owned(dest_directory.path(), VaultConfig::device())?;
    dest.install_device_keystore(Arc::new(MemoryKeystore::default()));
    assert_eq!(
        dest.profile_local_open(Some(b"archive task facts naming this machine"), true)?,
        LocalOpenProfile::RootedAndProfiled,
    );
    let fold = dest.authority_fold()?;
    let vault_id = fold.vault_id.expect("the destination is rooted");
    let machines: Vec<EntityId> = fold.machines.keys().copied().collect();
    assert_eq!(
        machines.len(),
        1,
        "the destination's fold holds its own machine only"
    );

    // A cancel that names the destination's machine as its carrier under a key it never
    // held, as a forger's row reaches the source by sync and enters its archive.
    let cancel = EntityId::now();
    let at = source.now_recorded_at();
    let body = carried_fact_body(
        &vault_id,
        cancel,
        machines[0],
        &SigningKey::from_bytes(&[0x5a; 32]),
        (task, TaskAuthorityFactKind::Cancelled, owner, at),
    );
    replay_entity(
        &source,
        ReplicatedEntity {
            id: cancel,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange { start: at, end: at },
            learned_at: at,
            row_version: 0,
            body: &body,
        },
        ImportTier::OwnDevice,
    )?;
    source
        .batch()
        .edge(&cancel, EdgeKind::ScopedTo, &task, SCOPED_TO_WEIGHT)
        .commit()?;
    let archive = source.export_whole_vault(true)?.bytes().to_vec();

    let proof = owner_proof(&dest)?;
    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &proof)
    {
        panic!("the owner's whole archive must restore into a rooted vault: {error:?}");
    }
    let here = dest
        .task_authority_state(task)?
        .expect("the restored Owner fact counts on the restored vault");
    assert!(here.cancelled, "the owner's restore counts the cancel here");
    let restored = authority_facts(&dest, task)?;
    assert!(
        restored.contains(&fact) && restored.contains(&cancel),
        "both facts come back at their archived ids"
    );
    assert_eq!(
        restored.len(),
        4,
        "the two restored facts and a signed twin of each: a carrier that only names this \
         install's machine is no signature of its own"
    );

    let device_directory = tempfile::tempdir()?;
    let device = Vault::open(device_directory.path(), VaultConfig::device())?;
    device.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let key = device.machine_encryption_key(vault_id)?;
    let request = device.machine_enrolment_request(vault_id, key)?;
    dest.enroll_machine(
        &proof,
        ActSurface::ThisInstall,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )?;
    device.import_signed_authority_history(&dest.export_signed_authority_history()?)?;
    for row in restored {
        let raw = dest.get_raw(&row)?.expect("the fact row");
        land_replicated_fact(&device, row, task, &raw[ENTITY_METADATA_HEADER_LEN..]);
    }
    let there = device
        .task_authority_state(task)?
        .expect("the signed twin of the restored Owner fact counts on the device");
    assert_eq!(there.owner_ref, owner);
    assert!(
        there.cancelled,
        "the signed twin of the restored cancel counts on the device"
    );
    Ok(())
}
