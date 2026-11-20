//! FIX 1370: a live observer that imports a file before the custody
//! transition in the same import reuses the origin's record, never mints a
//! duplicate. A and B are two machines of one owner. A writes a file ASSET
//! holding a key span (its write door mints one custody record), seals the
//! record to both machines with the owner's rewrap, and mirrors both into
//! its base window. B imports A's window update in ONE import while B's
//! window is open, so the live entity and custody observers race. On main
//! the entity pass can run first and mint B's own record of A's value; with
//! the fix the entity pass folds the window's unheld custody rows first,
//! the value is known, and the mark names A's record.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test sync_live_file_custody_reuse`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::ExportMode;
use oneiron::authority::{ActSurface, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron::secret_custody::CustodyPlan;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, LoadedWindow};
use oneiron::test_doors::file_custody_marks;
use oneiron::world_keys::OwnerWorkStatus;
use oneiron::{EntityId, HnswConfig, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The base window both machines hold open.
const WINDOW: &str = "2026-03";

/// 2026-03-15 00:00 UTC, inside [`WINDOW`]: the file's learned month and the
/// rewrap's signing month, so both ride this window.
const T0: u64 = 1_773_532_800;

/// The sync-harness vault config (tests/it_sync/sync_harness/mod.rs
/// `test_config`): a device vault with no embedding model.
fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config
}

/// A's vault: an owner-carrier install (`test_doors::steward::
/// open_owner_carrier_vault`).
fn open_owner_vault(dir: &std::path::Path) -> TestResult<Vault> {
    let vault = Vault::open(dir, test_config())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.prepare_install_signing()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

fn owner_proof(vault: &Vault) -> TestResult<AuthenticatedOwner> {
    let person = vault.ensure_embedded_owner_actor()?;
    Ok(vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?)
}

/// B's vault: a second install enrolled as the owner's own
/// (tests/carried_pin_awaits_owner.rs `device`). B takes no engine profile:
/// a fresh vault has no genesis, so A's signed history imports whole.
fn enroll_second_machine(
    vault_a: &Vault,
    owner_a: &AuthenticatedOwner,
    vault_id: [u8; 32],
    vault_b: &Vault,
) -> TestResult<EntityId> {
    let key = vault_b.machine_encryption_key(vault_id)?;
    let request = vault_b.machine_enrolment_request(vault_id, key)?;
    vault_a.enroll_machine(
        owner_a,
        ActSurface::ThisInstall,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )?;
    vault_b.ensure_embedded_owner_actor()?;
    Ok(request.machine)
}

/// Imports the rows of A's history B does not hold yet
/// (tests/carried_pin_awaits_owner.rs `Device::take`).
fn take_history(vault_a: &Vault, vault_b: &Vault, held: &mut BTreeSet<Vec<u8>>) -> TestResult<()> {
    let new: Vec<Vec<u8>> = vault_a
        .export_signed_authority_history()?
        .into_iter()
        .filter(|row| !held.contains(row))
        .collect();
    vault_b.import_signed_authority_history(&new)?;
    held.extend(new);
    Ok(())
}

/// Opens [`WINDOW`] with live observers (tests/it_sync/sync_harness/mod.rs
/// `TestNode::open_window`): `LoadedWindow::from_doc` registers Observer B
/// and the custody observer (src/sync/window/mod.rs `from_doc_with_outbound`).
fn open_window(
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
    name: &str,
    peer_id: u64,
) -> TestResult<LoadedWindow> {
    let key = WindowKey::new(WINDOW);
    let doc = create_window_doc(name, &key);
    doc.set_peer_id(peer_id)?;
    window::apply_pending_window_updates(vault, &doc, &key)?;
    Ok(LoadedWindow::from_doc(doc, key, vault, materializer))
}

/// A GitHub token shape the write door mints for
/// (tests/native_raw_entity_body_release_scan.rs `raw_body_token`), joined
/// at run time so no token literal sits in the source.
fn file_token() -> String {
    ["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat()
}

#[test]
fn b_reuses_a_custody_record_for_a_live_file() -> TestResult<()> {
    // A and B: two machines of one owner.
    let dir_a = tempfile::tempdir()?;
    let vault_a = Arc::new(open_owner_vault(dir_a.path())?);
    let owner_a = owner_proof(&vault_a)?;
    let machine_a = vault_a
        .local_machine()?
        .ok_or("this install has no machine id")?
        .id;
    vault_a.set_machine_role(
        &owner_a,
        ActSurface::ThisInstall,
        machine_a,
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )?;
    let vault_id = vault_a
        .authority_fold()?
        .vault_id
        .ok_or("A has no authority genesis")?;

    let dir_b = tempfile::tempdir()?;
    let vault_b = Arc::new({
        let vault = Vault::open(dir_b.path(), test_config())?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault
    });
    let machine_b = enroll_second_machine(&vault_a, &owner_a, vault_id, &vault_b)?;
    let mut held_b = BTreeSet::new();
    take_history(&vault_a, &vault_b, &mut held_b)?;

    // A writes a file ASSET holding a key span: its write door mints exactly
    // one custody record and marks the file with it.
    let file_body = format!("deploy token {}\n", file_token()).into_bytes();
    let before_a = vault_a.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?;
    let asset = EntityId::now();
    vault_a.put_entity(
        &asset,
        ENTITY_TYPE_ASSET,
        TimeRange { start: T0, end: T0 },
        T0,
        &file_body,
    )?;
    assert_eq!(
        vault_a.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        before_a + 1,
        "A's write door mints exactly one custody record for the file's key"
    );
    let marked_a = file_custody_marks::file_mark_custody(&vault_a, &file_body)?;
    assert_eq!(marked_a.len(), 1, "A's mark names one record");
    let id_a = marked_a[0];
    let name = vault_a
        .found_keys(&owner_a, false, 16)?
        .into_iter()
        .find(|notice| notice.record == asset)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|card| card.name)
        .ok_or("A names the minted record in its found keys")?;

    // The owner seals A's record to both machines: a rewrap request A
    // enacts in the same commit, signing the transition that rides the base
    // window's custody map (sealed to B too, so B's fold stands it).
    let work = vault_a.rewrap_secret_as_owner(
        &owner_a,
        ActSurface::ThisInstall,
        &name,
        &CustodyPlan {
            holder: None,
            recipients: vec![machine_a, machine_b],
        },
        T0,
    )?;
    assert!(
        work.kept_here.is_none(),
        "the rewrap is recorded, not kept here"
    );
    let receipt = work.work.ok_or("the rewrap recorded no owner work")?;
    assert!(
        matches!(receipt.status, OwnerWorkStatus::Enacted),
        "A enacts the rewrap in the same commit"
    );
    // B's fold counts the rewrap request before the window import.
    take_history(&vault_a, &vault_b, &mut held_b)?;

    // Both hold the base window open with live observers.
    let materializer_a = Arc::new(Materializer::new());
    let materializer_b = Arc::new(Materializer::new());
    let window_a = open_window(&vault_a, &materializer_a, "node-a", 1)?;
    let window_b = open_window(&vault_b, &materializer_b, "node-b", 2)?;
    assert_eq!(
        vault_b.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        0,
        "B holds no custody record before the import"
    );

    // A mirrors its file and the transition into its window; the guards say
    // the import below carries both.
    window::reverse_rematerialize(&vault_a, &window_a.doc, &WindowKey::new(WINDOW))?;
    assert!(
        window_a
            .doc
            .get_map("entities")
            .get(&asset.to_hex())
            .is_some(),
        "A's window carries the file"
    );
    let mut custody_rows = 0u32;
    window_a.doc.get_map("custody").for_each(|_, _| {
        custody_rows += 1;
    });
    assert!(custody_rows > 0, "A's window carries the transition");

    // One import: entities and custody arrive together and the live
    // observers run (tests/it_sync/sync_harness/mod.rs `exchange_docs` raw
    // Loro form, single direction).
    let update = window_a
        .doc
        .export(ExportMode::updates(&window_b.doc.oplog_vv()))?;
    window_b.doc.import(&update)?;

    // B holds exactly one custody record for the value: A's, reused.
    assert_eq!(
        vault_b.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        1,
        "B holds one custody record for the value, not a duplicate of its own"
    );
    let stored_b = vault_b.get(&asset)?.ok_or("B holds the file")?;
    assert_eq!(stored_b, file_body, "B stores the file's bytes as written");
    assert_eq!(
        file_custody_marks::file_mark_custody(&vault_b, &stored_b)?,
        vec![id_a],
        "B's mark for the file names A's custody record"
    );
    Ok(())
}
