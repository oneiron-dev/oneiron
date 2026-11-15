//! FILE-CUSTODY-MERGE-AFTER-REWRAP (red): once A's custody opens on B, B
//! rebinds its file marks to A's record and retires its own.
//!
//! The row (owner ruling 15 Nov): A writes a file ASSET holding a key; A's
//! write door mints custody record id_a and marks the file with it. B is
//! another machine of the same owner. When B lands the file before A's
//! custody opens on B, B's own write door mints a second record id_b of the
//! same value and marks its copy with id_b. Once A's custody opens on B
//! (through A's rewrap to B, or through a late transition: one that did not
//! stand on B when it arrived and stands after B's authority fold catches
//! up), B rebinds its marks to id_a and retires id_b (Engine RULING
//! CUSTODY-MERGE-RETIRE-ACT = A, 15 Nov 20:51). Without the merge, B's mark
//! still names id_b after the open, so the two merge cases fail. A duplicate
//! the owner acted on (here: labelled) keeps both records
//! (FILE-CUSTODY-DUP-UNOPENED = A); the guard case holds with and without
//! the merge.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test file_custody_merge_after_rewrap`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::ExportMode;
use oneiron::authority::{ActSurface, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron::secret_custody::{CustodyPlan, SecretCustodyStatus};
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

/// The custody name the vault's found keys give the file's key: the card
/// name of the notice whose record is the file's ASSET.
fn found_name_for_record(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> TestResult<String> {
    Ok(vault
        .found_keys(owner, false, 16)?
        .into_iter()
        .find(|notice| notice.record == *record)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|card| card.name)
        .ok_or("the vault names no found key for the file")?)
}

/// The keys of the window's custody map now: a transition's first piece
/// rides under its record id in hex.
fn window_custody_keys(window: &LoadedWindow) -> Vec<String> {
    let mut keys = Vec::new();
    window.doc.get_map("custody").for_each(|key, _| {
        keys.push(key.to_owned());
    });
    keys
}

#[test]
fn b_merges_its_own_record_into_a_custody_opened_by_a_rewrap() -> TestResult<()> {
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
    let owner_b = owner_proof(&vault_b)?;
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
    let name_a = vault_a
        .found_keys(&owner_a, false, 16)?
        .into_iter()
        .find(|notice| notice.record == asset)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|card| card.name)
        .ok_or("A names the minted record in its found keys")?;

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

    // A mirrors its file BEFORE any rewrap: the window carries the file and
    // no transition of id_a.
    window::reverse_rematerialize(&vault_a, &window_a.doc, &WindowKey::new(WINDOW))?;
    assert!(
        window_a
            .doc
            .get_map("entities")
            .get(&asset.to_hex())
            .is_some(),
        "A's window carries the file"
    );
    let id_a_hex = id_a.to_hex();
    let id_a_piece_prefix = format!("{id_a_hex}.");
    assert!(
        window_custody_keys(&window_a)
            .iter()
            .all(|key| key != &id_a_hex && !key.starts_with(&id_a_piece_prefix)),
        "A's window carries no transition of id_a before the rewrap"
    );

    // B imports A's window update in one import. No transition stands, so
    // B's own write door mints a second record of the same value.
    let update = window_a
        .doc
        .export(ExportMode::updates(&window_b.doc.oplog_vv()))?;
    window_b.doc.import(&update)?;

    // Guards: B holds the file as written under its own record id_b.
    let stored_b = vault_b.get(&asset)?.ok_or("B holds the file")?;
    assert_eq!(stored_b, file_body, "B stores the file's bytes as written");
    let marked_b = file_custody_marks::file_mark_custody(&vault_b, &stored_b)?;
    assert_eq!(marked_b.len(), 1, "B's mark names one record");
    let id_b = marked_b[0];
    assert_ne!(
        id_b, id_a,
        "B minted its own record of the value: its mark names id_b, not id_a"
    );
    assert_eq!(
        vault_b.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        1,
        "B holds one custody record for the value: its own"
    );
    let name_b = found_name_for_record(&vault_b, &owner_b, &asset)?;
    assert_ne!(
        name_b, name_a,
        "B's found keys name its own record, not A's"
    );
    let view_a_before = vault_b.secret_custody_view(&owner_b, &name_a)?;
    assert!(
        !view_a_before.known,
        "B has not opened A's custody yet: no transition stood"
    );

    // The owner seals A's record to both machines: a rewrap request A
    // enacts in the same commit, signing the transition that rides the base
    // window's custody map (sealed to B too, so B's fold stands it).
    let work = vault_a.rewrap_secret_as_owner(
        &owner_a,
        ActSurface::ThisInstall,
        &name_a,
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
    // B's fold counts the rewrap request before the next window import.
    take_history(&vault_a, &vault_b, &mut held_b)?;

    // A mirrors again; the window now carries the transition of id_a.
    window::reverse_rematerialize(&vault_a, &window_a.doc, &WindowKey::new(WINDOW))?;
    assert!(
        window_custody_keys(&window_a)
            .iter()
            .any(|key| key == &id_a_hex),
        "A's window carries the transition of id_a after the rewrap"
    );

    // B imports the new update: the transition stands on B's fold and B
    // opens the value beside its own record.
    let update = window_a
        .doc
        .export(ExportMode::updates(&window_b.doc.oplog_vv()))?;
    window_b.doc.import(&update)?;
    let view_a_after = vault_b.secret_custody_view(&owner_b, &name_a)?;
    assert!(
        view_a_after.known && view_a_after.held_here,
        "B opened A's custody: A's record is known and held here"
    );

    // The merge: B rebinds its marks to id_a and retires id_b. Red on this
    // head: B's mark still names id_b.
    let stored_b_after = vault_b.get(&asset)?.ok_or("B holds the file")?;
    assert_eq!(
        file_custody_marks::file_mark_custody(&vault_b, &stored_b_after)?,
        vec![id_a],
        "B's mark for the file names A's custody record after the merge"
    );
    assert_eq!(
        found_name_for_record(&vault_b, &owner_b, &asset)?,
        name_a,
        "B's found keys for the file name A's record after the merge"
    );
    let view_b_after = vault_b.secret_custody_view(&owner_b, &name_b)?;
    assert!(
        view_b_after.status != Some(SecretCustodyStatus::Active),
        "B retired its own record: id_b is no longer a live record"
    );
    Ok(())
}

#[test]
fn b_merges_its_own_record_into_a_custody_opened_by_a_late_transition() -> TestResult<()> {
    // A and B: two machines of one owner. B takes its history BEFORE A's
    // rewrap below, so B's fold does not count the rewrap request when the
    // window update carrying its transition arrives.
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
    let owner_b = owner_proof(&vault_b)?;
    let mut held_b = BTreeSet::new();
    take_history(&vault_a, &vault_b, &mut held_b)?;

    // A writes a file ASSET holding a key span, then rewraps its record to
    // both machines at T0. B takes none of this history yet.
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
    let name_a = vault_a
        .found_keys(&owner_a, false, 16)?
        .into_iter()
        .find(|notice| notice.record == asset)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|card| card.name)
        .ok_or("A names the minted record in its found keys")?;
    let work = vault_a.rewrap_secret_as_owner(
        &owner_a,
        ActSurface::ThisInstall,
        &name_a,
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
    let id_a_hex = id_a.to_hex();
    assert!(
        window_custody_keys(&window_a)
            .iter()
            .any(|key| key == &id_a_hex),
        "A's window carries the transition of id_a"
    );

    // One import: the file and the transition arrive together, but B's fold
    // does not count the rewrap request, so the transition does not stand,
    // the value does not open, and B mints its own record id_b.
    let update = window_a
        .doc
        .export(ExportMode::updates(&window_b.doc.oplog_vv()))?;
    window_b.doc.import(&update)?;

    // Guards: B holds the file as written under its own record id_b.
    let stored_b = vault_b.get(&asset)?.ok_or("B holds the file")?;
    assert_eq!(stored_b, file_body, "B stores the file's bytes as written");
    let marked_b = file_custody_marks::file_mark_custody(&vault_b, &stored_b)?;
    assert_eq!(marked_b.len(), 1, "B's mark names one record");
    let id_b = marked_b[0];
    assert_ne!(
        id_b, id_a,
        "B minted its own record of the value: its mark names id_b, not id_a"
    );
    assert_eq!(
        vault_b.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        1,
        "B holds one custody record for the value: its own"
    );
    let name_b = found_name_for_record(&vault_b, &owner_b, &asset)?;
    assert_ne!(
        name_b, name_a,
        "B's found keys name its own record, not A's"
    );
    let view_a_before = vault_b.secret_custody_view(&owner_b, &name_a)?;
    assert!(
        !view_a_before.known,
        "B has not opened A's custody yet: the transition did not stand"
    );

    // B's authority fold catches up: it takes the rewrap's rows. The late
    // transition stands now, so judging the window's custody rows again
    // opens the value. The forward pass folds standing custody before its
    // entity pass, which judges the late transition again on B.
    take_history(&vault_a, &vault_b, &mut held_b)?;
    window::forward_rematerialize(
        &vault_b,
        &window_b.doc,
        &materializer_b,
        &WindowKey::new(WINDOW),
    )?;
    let view_a_after = vault_b.secret_custody_view(&owner_b, &name_a)?;
    assert!(
        view_a_after.known && view_a_after.held_here,
        "B opened A's custody: A's record is known and held here"
    );

    // The merge: B rebinds its marks to id_a and retires id_b. Red on this
    // head: B's mark still names id_b.
    let stored_b_after = vault_b.get(&asset)?.ok_or("B holds the file")?;
    assert_eq!(
        file_custody_marks::file_mark_custody(&vault_b, &stored_b_after)?,
        vec![id_a],
        "B's mark for the file names A's custody record after the merge"
    );
    assert_eq!(
        found_name_for_record(&vault_b, &owner_b, &asset)?,
        name_a,
        "B's found keys for the file name A's record after the merge"
    );
    let view_b_after = vault_b.secret_custody_view(&owner_b, &name_b)?;
    assert!(
        view_b_after.status != Some(SecretCustodyStatus::Active),
        "B retired its own record: id_b is no longer a live record"
    );
    Ok(())
}

/// A guard beside the two red cases: green on this head and after the fix.
#[test]
fn b_keeps_its_own_record_when_the_owner_labelled_it_before_the_open() -> TestResult<()> {
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
    let owner_b = owner_proof(&vault_b)?;
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
    let name_a = vault_a
        .found_keys(&owner_a, false, 16)?
        .into_iter()
        .find(|notice| notice.record == asset)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|card| card.name)
        .ok_or("A names the minted record in its found keys")?;

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

    // A mirrors its file BEFORE any rewrap: the window carries the file and
    // no transition of id_a.
    window::reverse_rematerialize(&vault_a, &window_a.doc, &WindowKey::new(WINDOW))?;
    assert!(
        window_a
            .doc
            .get_map("entities")
            .get(&asset.to_hex())
            .is_some(),
        "A's window carries the file"
    );
    let id_a_hex = id_a.to_hex();
    let id_a_piece_prefix = format!("{id_a_hex}.");
    assert!(
        window_custody_keys(&window_a)
            .iter()
            .all(|key| key != &id_a_hex && !key.starts_with(&id_a_piece_prefix)),
        "A's window carries no transition of id_a before the rewrap"
    );

    // B imports A's window update in one import. No transition stands, so
    // B's own write door mints a second record of the same value.
    let update = window_a
        .doc
        .export(ExportMode::updates(&window_b.doc.oplog_vv()))?;
    window_b.doc.import(&update)?;

    // Guards: B holds the file as written under its own record id_b.
    let stored_b = vault_b.get(&asset)?.ok_or("B holds the file")?;
    assert_eq!(stored_b, file_body, "B stores the file's bytes as written");
    let marked_b = file_custody_marks::file_mark_custody(&vault_b, &stored_b)?;
    assert_eq!(marked_b.len(), 1, "B's mark names one record");
    let id_b = marked_b[0];
    assert_ne!(
        id_b, id_a,
        "B minted its own record of the value: its mark names id_b, not id_a"
    );
    assert_eq!(
        vault_b.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?,
        1,
        "B holds one custody record for the value: its own"
    );
    let name_b = found_name_for_record(&vault_b, &owner_b, &asset)?;
    assert_ne!(
        name_b, name_a,
        "B's found keys name its own record, not A's"
    );
    let view_a_before = vault_b.secret_custody_view(&owner_b, &name_a)?;
    assert!(
        !view_a_before.known,
        "B has not opened A's custody yet: no transition stood"
    );

    // The owner labels B's own record before A's custody opens on B: an
    // owner act on it, so B keeps both records.
    let handle_b = vault_b
        .found_keys(&owner_b, false, 16)?
        .into_iter()
        .find(|notice| notice.record == asset)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|card| card.handle)
        .ok_or("B names its own record in its found keys")?;
    vault_b.set_secret_handle_label(&owner_b, &handle_b, Some("Deploy token"))?;

    // The owner seals A's record to both machines: a rewrap request A
    // enacts in the same commit, signing the transition that rides the base
    // window's custody map (sealed to B too, so B's fold stands it).
    let work = vault_a.rewrap_secret_as_owner(
        &owner_a,
        ActSurface::ThisInstall,
        &name_a,
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
    // B's fold counts the rewrap request before the next window import.
    take_history(&vault_a, &vault_b, &mut held_b)?;

    // A mirrors again; the window now carries the transition of id_a.
    window::reverse_rematerialize(&vault_a, &window_a.doc, &WindowKey::new(WINDOW))?;
    assert!(
        window_custody_keys(&window_a)
            .iter()
            .any(|key| key == &id_a_hex),
        "A's window carries the transition of id_a after the rewrap"
    );

    // B imports the new update: the transition stands on B's fold and B
    // opens the value beside its own record.
    let update = window_a
        .doc
        .export(ExportMode::updates(&window_b.doc.oplog_vv()))?;
    window_b.doc.import(&update)?;
    let view_a_after = vault_b.secret_custody_view(&owner_b, &name_a)?;
    assert!(
        view_a_after.known && view_a_after.held_here,
        "B opened A's custody: A's record is known and held here"
    );

    // A duplicate the owner acted on keeps both records
    // (FILE-CUSTODY-DUP-UNOPENED = A): B's mark still names its own record,
    // and that record stays live beside A's.
    let stored_b_after = vault_b.get(&asset)?.ok_or("B holds the file")?;
    assert_eq!(
        file_custody_marks::file_mark_custody(&vault_b, &stored_b_after)?,
        vec![id_b],
        "B's mark for the file still names its own labelled record"
    );
    let view_b_after = vault_b.secret_custody_view(&owner_b, &name_b)?;
    assert!(
        view_b_after.status == Some(SecretCustodyStatus::Active),
        "B keeps its own labelled record live beside A's"
    );
    Ok(())
}
