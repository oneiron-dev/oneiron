//! UNBUILT3-30 (FIX TASK-FACT-FOREIGN-ARCHIVE-EXPORT; Engine ruling
//! TASK-FACT-ARCHIVE-CROSSING = A, 17 Nov 00:02): "archives keep the facts
//! (one true archive), and the import refuses a foreign chain's facts as
//! built". A TASK carries its authority facts (the Owner fact the task door
//! writes beside it, role 6), and a sync window bound for another vault
//! withholds them; a whole-vault archive carries them (ARCH-0027:339
//! #export-complete: one true archive).
//!
//! - `a_foreign_archives_task_authority_facts_are_refused_at_import`: another
//!   vault's signed archive of a vault with a TASK reads
//!   `ForeignAuthorityChain` here, and its import is refused at the TASK's
//!   authority fact: no TASK and no fact of it lands. Guard: passes on main.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_task_authority_facts`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::batch::export::VaultImportClassification;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use rmpv::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 2026-03-15 00:00 UTC.
const T0: u64 = 1_773_532_800;

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
