#![cfg(oneiron_test_support)]
//! Owner archive restores install legal hold rows and their ordered history,
//! never in-place protection (LEGAL-HOLD-USE = B). A restored standing hold
//! does not refuse a delete; its next widen writes a new sealed capture to
//! the destination's own external hold store. A lifted hold restores as
//! history and starts no erase. A hosted GDPR erase fully erases a held
//! record, and its archive carries no target, use-limit, erase-link or
//! pending-erase rows.
//!
//! Public doors only; neutral fixtures; vaults and separate hold stores in
//! tempdirs, with device keystores installed. Each destination opens at least
//! one wall-clock second after its source (sleep 1100 ms), as in
//! `archive_import_retained_side_rows.rs`. Restoring a hold's metadata does
//! not restore the source's external sealed capture files.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_legal_holds`

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;
use std::sync::Arc;

use oneiron::deletion::{LegalHoldEventKind, LegalHoldReason, LegalHoldTarget};
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use retained_side_rows::{export_whole, owner_proof, retained_rows, rows_for};

/// A vault with its own hold store outside the vault directory and its own
/// device keystore. Keep both tempdirs alive for the vault's lifetime.
fn open_hold_vault(
    config: VaultConfig,
    owned: bool,
) -> (tempfile::TempDir, tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the vault");
    let store_dir = tempfile::tempdir().expect("temp dir for the external hold store");
    let config = config.with_legal_hold_store(store_dir.path().to_path_buf());
    let vault = if owned {
        Vault::open_owned(dir.path(), config)
    } else {
        Vault::open(dir.path(), config)
    }
    .expect("open the vault with its external hold store");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("prepare the vault's install signing key");
    (dir, store_dir, vault)
}

/// A source opened as the owner's own, with an external hold store.
fn open_source_vault() -> (tempfile::TempDir, tempfile::TempDir, Vault) {
    open_hold_vault(VaultConfig::device(), true)
}

/// A fresh destination whose engine-seed seconds differ from the source's:
/// any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_hold_vault(VaultConfig::device(), false)
}

/// A fixed entity id from one repeated byte. The banned bytes (00, 11, 42,
/// 47, A1..A6, D7, E1, FF) belong to other fixtures.
fn fixed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a non-reserved repeated byte is a valid entity id")
}

/// The `field` count for `table` in a `retained_side_rows` JSON summary, when
/// the table entry and the field are both present.
fn table_count(summary: &serde_json::Value, table: &str, field: &str) -> Option<u64> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get(field)?
        .as_u64()
}

/// The two live tables a standing hold installs; no target index is written.
const STANDING_TABLES: [&str; 2] = ["LEGAL_HOLD_ROW", "LEGAL_HOLD_EVENT"];

/// The owner restore installs the standing hold and its log live, but its
/// record still deletes; a repeat import leaves the hold rows unchanged.
/// The actorless import retains the rows without installing a hold.
#[test]
fn the_owner_restore_installs_a_standing_hold_and_its_record_still_deletes() {
    let (_source_dir, _source_store_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let record = fixed_id(0x29);
    source
        .put_entity(
            &record,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"held record",
        )
        .expect("the source stores the held record");
    assert_eq!(
        source.get(&record).expect("read the source record"),
        Some(b"held record".to_vec()),
        "the source holds the record"
    );
    let matter = "matter-001".to_owned();
    let hold = source
        .place_legal_hold(
            &source_owner,
            vec![LegalHoldTarget::Record(record)],
            Some(matter.clone()),
            None,
        )
        .expect("the owner places the source hold");
    assert!(hold.stands(), "the source hold stands: {hold:?}");
    assert_eq!(
        hold.targets,
        vec![LegalHoldTarget::Record(record)],
        "the source hold names its record"
    );
    assert_eq!(
        hold.matter_ref,
        Some(matter.clone()),
        "the source hold carries its matter"
    );
    let source_holds = source
        .legal_holds(&source_owner)
        .expect("list the source holds");
    assert_eq!(
        source_holds,
        vec![hold.clone()],
        "the source lists its one hold"
    );
    let source_log = source
        .legal_hold_log(&source_owner)
        .expect("read the source log");
    assert_eq!(
        source_log.len(),
        1,
        "the source log holds its placement: {source_log:?}"
    );
    assert_eq!(
        source_log[0].event,
        LegalHoldEventKind::Placed,
        "the source log starts with its placement"
    );
    assert_eq!(
        source_log[0].reason,
        LegalHoldReason::OwnerPlaced,
        "the source placement names its reason"
    );
    let archive = export_whole(&source);
    assert!(
        rows_for(&retained_rows(&archive), "LEGAL_HOLD_TARGET").is_empty(),
        "the source archive carries no in-place target index"
    );

    let (_dest_dir, _dest_store_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.legal_holds(&dest_owner)
            .expect("list the restored holds"),
        source_holds,
        "the owner import installs the standing hold live"
    );
    assert_eq!(
        dest.legal_hold_log(&dest_owner)
            .expect("read the restored log"),
        source_log,
        "the owner import installs the hold log live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for table in STANDING_TABLES {
        assert_eq!(
            table_count(&summary, table, "installed_rows"),
            Some(1),
            "the owner import reports one installed {table} row; an absent field means it installed nothing: {summary}"
        );
    }
    assert!(
        dest.delete_entity(&record)
            .expect("the restored hold never refuses its record's delete"),
        "the restored held record deletes"
    );
    assert_eq!(
        dest.get(&record).expect("read the deleted restored record"),
        Some(Vec::new()),
        "the restored hold keeps no payload, only the ordinary tombstone shell"
    );
    assert_eq!(
        dest.legal_holds(&dest_owner)
            .expect("list the holds after deletion"),
        source_holds,
        "deleting the record does not lift its standing hold"
    );

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    for table in STANDING_TABLES {
        assert_eq!(
            table_count(&repeat_summary, table, "unchanged_live_rows"),
            Some(1),
            "the repeat owner import reports one unchanged live {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
        assert_eq!(
            table_count(&repeat_summary, table, "installed_rows"),
            Some(0),
            "the repeat owner import installs no {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
    }

    let (_bare_dir, _bare_store_dir, bare) = open_later_vault();
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    let bare_owner = owner_proof(&bare);
    assert!(
        bare.legal_holds(&bare_owner)
            .expect("list the actorless holds")
            .is_empty(),
        "the actorless import installs no hold"
    );
    assert!(
        bare.legal_hold_log(&bare_owner)
            .expect("read the actorless log")
            .is_empty(),
        "the actorless import installs no log"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    for table in STANDING_TABLES {
        assert!(
            matches!(
                table_count(&bare_summary, table, "installed_rows"),
                None | Some(0)
            ),
            "the actorless import installs no {table} row: {bare_summary}"
        );
    }
    assert!(
        bare.delete_entity(&record)
            .expect("the actorless delete succeeds"),
        "the actorless restored record deletes too"
    );
    assert_eq!(
        bare.get(&record).expect("read the deleted record"),
        Some(Vec::new()),
        "the actorless delete keeps only the empty tombstone shell"
    );
}

/// The next widen after a restore keeps the restored log prefix, appends its
/// scope change and new capture fingerprint, and permits its new record's delete.
#[test]
fn the_next_hold_act_after_a_restore_follows_the_restored_log() {
    let (_source_dir, _source_store_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let first = fixed_id(0x2E);
    let second = fixed_id(0x31);
    source
        .put_entity(
            &first,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"first record",
        )
        .expect("the source stores the first record");
    source
        .put_entity(
            &second,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 11, end: 11 },
            11,
            b"second record",
        )
        .expect("the source stores the second record");
    let hold = source
        .place_legal_hold(
            &source_owner,
            vec![LegalHoldTarget::Record(first)],
            Some("matter-002".to_owned()),
            None,
        )
        .expect("the owner places the source hold");
    let source_log = source
        .legal_hold_log(&source_owner)
        .expect("read the source log");
    assert_eq!(
        source_log.len(),
        1,
        "the source log holds its placement: {source_log:?}"
    );
    let archive = export_whole(&source);

    let (_dest_dir, _dest_store_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.legal_hold_log(&dest_owner)
            .expect("read the restored log"),
        source_log,
        "the owner import installs the log before the next act"
    );

    let widened = dest
        .widen_legal_hold(
            &dest_owner,
            hold.hold_id,
            vec![LegalHoldTarget::Record(second)],
        )
        .expect("the owner widens the restored hold");
    assert!(
        widened.targets.contains(&LegalHoldTarget::Record(first))
            && widened.targets.contains(&LegalHoldTarget::Record(second)),
        "the widened hold names both records: {widened:?}"
    );
    let dest_log = dest
        .legal_hold_log(&dest_owner)
        .expect("read the widened log");
    assert_eq!(
        dest_log.len(),
        source_log.len() + 1,
        "the widen appends one event: {dest_log:?}"
    );
    assert_eq!(
        &dest_log[..source_log.len()],
        &source_log[..],
        "the widen keeps the restored prefix"
    );
    let last = dest_log.last().expect("the widened log has its new event");
    assert_eq!(
        last.event,
        LegalHoldEventKind::ScopeChanged,
        "the widen logs a scope change"
    );
    assert_eq!(
        last.reason,
        LegalHoldReason::ScopeWidened,
        "the widen names its reason"
    );
    assert_eq!(
        last.targets,
        vec![LegalHoldTarget::Record(second)],
        "the widen logs its added record"
    );
    assert_eq!(
        widened.clone_captures.len(),
        hold.clone_captures.len() + 1,
        "the destination widen appends its own sealed capture"
    );
    let capture = widened
        .clone_captures
        .last()
        .expect("the widened hold names its new capture");
    assert!(
        !hold.clone_captures.contains(capture),
        "the widen names a new capture, not the source's archived capture"
    );
    assert_eq!(
        last.clone_fingerprint,
        Some(capture.fingerprint),
        "the scope change logs the destination capture's fingerprint"
    );
    assert!(
        dest.delete_entity(&second)
            .expect("the widened hold never refuses its new record's delete"),
        "the newly held record deletes"
    );
    assert_eq!(
        dest.get(&second).expect("read the deleted second record"),
        Some(Vec::new()),
        "the widened hold keeps no payload in the vault"
    );
}

/// A plain owner lift restores as history with placement, lift and copy
/// destruction in order. Neither the lift nor its restore erases the record.
#[test]
fn a_lifted_hold_restores_as_history() {
    let (_source_dir, _source_store_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let record = fixed_id(0x36);
    source
        .put_entity(
            &record,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"lifted record",
        )
        .expect("the source stores the lifted record");
    let hold = source
        .place_legal_hold(
            &source_owner,
            vec![LegalHoldTarget::Record(record)],
            Some("matter-003".to_owned()),
            None,
        )
        .expect("the owner places the source hold");
    let lifted = source
        .lift_legal_hold(&source_owner, hold.hold_id)
        .expect("the owner lifts the hold without erasing");
    assert!(!lifted.stands(), "the owner's lift releases the hold");
    assert!(
        lifted.lifted_at.is_some(),
        "the lifted hold names its release"
    );
    assert_eq!(
        lifted.targets,
        vec![LegalHoldTarget::Record(record)],
        "a lifted hold keeps its last scope"
    );
    let source_holds = source
        .legal_holds(&source_owner)
        .expect("list the source holds");
    assert_eq!(
        source_holds,
        vec![lifted],
        "the source lists its lifted hold as history"
    );
    assert_eq!(
        source.get(&record).expect("read the lifted source record"),
        Some(b"lifted record".to_vec()),
        "lifting the hold leaves the source record live and unchanged"
    );
    let source_log = source
        .legal_hold_log(&source_owner)
        .expect("read the source log");
    assert_eq!(
        source_log
            .iter()
            .map(|event| event.event)
            .collect::<Vec<_>>(),
        vec![
            LegalHoldEventKind::Placed,
            LegalHoldEventKind::Lifted,
            LegalHoldEventKind::CloneDestroyed,
        ],
        "the source logs placement, lift and sealed-copy destruction in order"
    );
    assert_eq!(
        source_log
            .iter()
            .map(|event| event.reason)
            .collect::<Vec<_>>(),
        vec![
            LegalHoldReason::OwnerPlaced,
            LegalHoldReason::OwnerLifted,
            LegalHoldReason::OwnerLifted,
        ],
        "the lift and copy destruction name the owner's release"
    );
    let archive = export_whole(&source);

    let (_dest_dir, _dest_store_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.legal_holds(&dest_owner)
            .expect("list the restored holds"),
        source_holds,
        "the owner import restores the lifted hold as history"
    );
    assert_eq!(
        dest.legal_hold_log(&dest_owner)
            .expect("read the restored log"),
        source_log,
        "the owner import restores the complete ordered hold history"
    );
    assert_eq!(
        dest.get(&record).expect("read the restored record"),
        Some(b"lifted record".to_vec()),
        "the restore starts no erase and preserves the record's payload"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_ROW", "installed_rows"),
        Some(1),
        "the owner import reports one installed hold row: {summary}"
    );
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_EVENT", "installed_rows"),
        Some(3),
        "the owner import reports all three installed history rows: {summary}"
    );
}

/// A hosted GDPR erase fully erases a held record without lifting its hold.
/// The archive carries the hold and its placement, not any in-place keep,
/// use-limit, erase-link or pending-erase row.
#[test]
fn a_hosted_privacy_erase_erases_a_held_record_without_in_place_hold_rows() {
    let mut source_config = VaultConfig::device();
    source_config.privacy.posture = HostingPrivacyPosture::Hosted;
    let (_source_dir, _source_store_dir, source) = open_hold_vault(source_config, true);
    let source_owner = owner_proof(&source);
    let record = fixed_id(0x3B);
    source
        .put_entity(
            &record,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"held privacy record",
        )
        .expect("the source stores the held privacy record");
    let hold = source
        .place_legal_hold(
            &source_owner,
            vec![LegalHoldTarget::Record(record)],
            Some("matter-004".to_owned()),
            None,
        )
        .expect("the owner places the source hold");
    assert!(hold.stands(), "the source hold stands: {hold:?}");
    let source_actor = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor");
    let source_memory = source.memory(source_actor, EdgeActorClass::Human);
    let preview = source_memory
        .preview_entity_delete(&record)
        .expect("preview the held privacy record");
    let outcome = source_memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("the hosted privacy erase runs fully despite the hold");
    assert_eq!(
        outcome.first.reason.as_str(),
        "gdpr_delete",
        "the receipt names the privacy erase, never a kept refusal: {outcome:?}"
    );
    assert!(
        outcome.first.receipt_ref.is_some(),
        "the privacy erase writes its receipt: {outcome:?}"
    );
    assert!(
        outcome.first_act.is_none(),
        "the privacy erase starts no waiting erase act: {outcome:?}"
    );
    assert!(
        outcome.same_bytes.is_empty(),
        "without the flag no other record is named: {outcome:?}"
    );
    assert_eq!(
        source.get(&record).expect("read the erased record"),
        None,
        "the held privacy record is fully erased, not kept or left as a shell"
    );
    assert_eq!(
        source
            .legal_holds(&source_owner)
            .expect("list the holds after erase"),
        vec![hold],
        "the privacy erase does not lift or change the hold"
    );
    let source_log = source
        .legal_hold_log(&source_owner)
        .expect("read the source log after erase");
    assert_eq!(
        source_log
            .iter()
            .map(|event| event.event)
            .collect::<Vec<_>>(),
        vec![LegalHoldEventKind::Placed],
        "the privacy erase appends no hold refusal or erase event"
    );
    let archive = export_whole(&source);
    let rows = retained_rows(&archive);
    assert_eq!(
        rows_for(&rows, "LEGAL_HOLD_ROW").len(),
        1,
        "the archive still carries the standing hold row"
    );
    assert_eq!(
        rows_for(&rows, "LEGAL_HOLD_EVENT").len(),
        1,
        "the archive still carries its placement event"
    );
    for table in [
        "LEGAL_HOLD_USE_LIMIT",
        "LEGAL_HOLD_ERASE_LINK",
        "LEGAL_HOLD_PENDING_ERASE",
        "LEGAL_HOLD_TARGET",
    ] {
        assert!(
            rows_for(&rows, table).is_empty(),
            "the privacy erase archive carries no {table} row"
        );
    }
}
