#![cfg(oneiron_test_support)]
//! The owner's archive restore brings back Setting rows
//! (ARCHIVE-SETTING-CATALOGUE-KEYS-NOT-CARRIED).
//!
//! Public API and `oneiron::test_doors` only; neutral fixtures; vaults in
//! tempdirs. Each destination opens at least one wall-clock second after its
//! source (sleep 1100 ms), as in `archive_import_retained_side_rows.rs`.
//! `test.owner_number` reads through its test door, `backup.policy` through
//! its kept reader, and the booking keys through the settings verb on owned
//! vaults, which hold the writer lease the verb needs.
//!
//! * `owner_restore_installs_absent_setting_rows_and_a_repeat_changes_nothing`:
//!   the owner import installs one vault value, one project pin, one backup
//!   policy and one project value, and reports four installed SETTING rows; a
//!   repeat reports four unchanged live rows and installs none; the actorless
//!   import of the same archive leaves every read at its default and installs
//!   nothing.
//! * `owner_restore_keeps_a_different_live_setting_row`: a destination that
//!   already holds another value keeps it, and the report counts one
//!   kept-live row.
//! * `owner_restore_holds_back_setting_rows_that_fail_their_key_checks`: a row
//!   at a scope naming an absent entity reports one held-back row with reason
//!   `missing_live_entity` and reads its default. Part (a), a row under an
//!   unknown key name, has no test door and is absent here.
//! * `owner_restore_installs_the_setting_change_history_and_never_lowers_its_counter`:
//!   three source changes install as three SETTING_CHANGE rows; the next
//!   destination change takes the highest restored sequence plus one, and the
//!   destination holds the source first change with its key and value.
//! * `owner_restore_passes_an_absent_row_through_its_keys_change_hook`: a
//!   count and a floor that agree both install whatever order the archive
//!   holds them in; a destination whose live count sits below the archived
//!   floor keeps its count and holds the floor back as `invalid_value`.
//!
//! Before the lander this file is red: the archive carries no setting rows
//! and no owner import installs any, so every installed count is absent and
//! every restored read stays at its default.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_setting_rows`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope, SettingSource,
};
use oneiron::settings::backup::BackupPolicy;
use oneiron::verbs::{
    SettingGetRequest, SettingListRequest, setting_get_embedded, setting_list_embedded,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use retained_side_rows::{export_whole, open_later_vault, open_source_vault, owner_proof};

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

/// The held-back list for `table` in a `retained_side_rows` JSON summary,
/// when the table entry and the list are both present.
fn held_back_for_table(summary: &serde_json::Value, table: &str) -> Option<serde_json::Value> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get("held_back")
        .cloned()
}

/// `test.owner_number` in force on `vault` at `known`: its value, which row
/// decided it, and the deciding row's revision. The door reads it two ways;
/// the vault's read is the one the test holds.
fn owner_number(vault: &Vault, known: &[SettingScope]) -> (u64, SettingSource, u64) {
    let (through_vault, _) =
        oneiron::test_doors::setting::owner_number_read_both_ways(vault, known)
            .expect("test.owner_number reads");
    (
        through_vault.value,
        through_vault.source,
        through_vault.revision,
    )
}

/// The value in force for `key` on `vault` at the vault scope: its JSON and
/// which row decided it. The vault holds the writer lease, so its embedded
/// owner reads through the settings verb.
fn setting_at_vault(vault: &Vault, key: &str) -> (serde_json::Value, SettingSource) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault names its embedded owner actor");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let view = setting_get_embedded(
        &memory,
        SettingGetRequest {
            key: key.to_owned(),
            item: None,
            at: Vec::new(),
        },
    )
    .expect("the settings verb reads the key");
    (view.value, view.source)
}

/// The time `vault`'s stored vault-scope value row of `key` was set at, as
/// the settings list verb shows it.
fn vault_row_set_at(vault: &Vault, key: &str) -> u64 {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault names its embedded owner actor");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let catalogue = setting_list_embedded(
        &memory,
        SettingListRequest {
            prefix: Some(key.to_owned()),
            ..SettingListRequest::default()
        },
    )
    .expect("the settings verb lists the key");
    catalogue
        .keys
        .iter()
        .find(|entry| entry.key == key)
        .and_then(|entry| {
            entry
                .rows
                .iter()
                .find(|row| row.mode == SettingMode::Value && row.scope == SettingScope::Vault)
        })
        .map(|row| row.set_at)
        .unwrap_or_else(|| panic!("{key} holds a stored vault value row"))
}

/// The sequence and revision of an applied change.
fn applied_in(outcome: &SetSettingOutcome) -> (u64, u64) {
    match outcome {
        SetSettingOutcome::Applied {
            sequence: Some(sequence),
            revision,
            ..
        } => (*sequence, *revision),
        other => panic!("an owner set applies with a sequence: {other:?}"),
    }
}

/// The owner restore installs absent setting rows; a repeat changes nothing;
/// the actorless import installs none.
#[test]
fn owner_restore_installs_absent_setting_rows_and_a_repeat_changes_nothing() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let pin_project =
        oneiron::test_doors::derive::witness_turn(&source, "a turn the pin scope names")
            .expect("the source witnesses the pin turn");
    let value_project =
        oneiron::test_doors::derive::witness_turn(&source, "a turn the value scope names")
            .expect("the source witnesses the value turn");
    assert_ne!(
        pin_project, value_project,
        "the two turns differ before the archive carries them"
    );

    let vault_outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value("test.owner_number", serde_json::json!(9)),
        )
        .expect("the owner sets the vault value");
    assert!(
        matches!(
            vault_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the vault value applies with a sequence: {vault_outcome:?}"
    );
    let pin_outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting {
                key: "test.owner_number".to_owned(),
                item: None,
                scope: SettingScope::Project(pin_project),
                mode: SettingMode::Pin,
                value: Some(serde_json::json!(11)),
                expected_revision: None,
                why: None,
                check_in_ref: None,
                weight_runs: None,
            },
        )
        .expect("the owner pins the project value");
    assert!(
        matches!(
            pin_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the pin applies with a sequence: {pin_outcome:?}"
    );
    let policy = BackupPolicy {
        enabled: true,
        every_hours: 6,
        keep: 3,
    };
    let backup_outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value(
                "backup.policy",
                serde_json::to_value(&policy).expect("the policy serializes"),
            ),
        )
        .expect("the owner sets the backup policy");
    assert!(
        matches!(
            backup_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the backup policy applies with a sequence: {backup_outcome:?}"
    );
    let narrow_outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting {
                key: "test.owner_number".to_owned(),
                item: None,
                scope: SettingScope::Project(value_project),
                mode: SettingMode::Value,
                value: Some(serde_json::json!(13)),
                expected_revision: None,
                why: None,
                check_in_ref: None,
                weight_runs: None,
            },
        )
        .expect("the owner sets the project value");
    assert!(
        matches!(
            narrow_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the project value applies with a sequence: {narrow_outcome:?}"
    );

    let (source_vault, source_vault_from, _) = owner_number(&source, &[]);
    assert_eq!(source_vault, 9, "the source holds the vault value");
    assert_eq!(
        source_vault_from,
        SettingSource::Row(SettingScope::Vault),
        "the vault value decides the vault read"
    );
    let (source_pin, source_pin_from, _) =
        owner_number(&source, &[SettingScope::Project(pin_project)]);
    assert_eq!(source_pin, 11, "the source holds the pin");
    assert_eq!(
        source_pin_from,
        SettingSource::Pin(SettingScope::Project(pin_project)),
        "the pin decides the pin read"
    );
    let (source_narrow, source_narrow_from, _) =
        owner_number(&source, &[SettingScope::Project(value_project)]);
    assert_eq!(source_narrow, 13, "the source holds the project value");
    assert_eq!(
        source_narrow_from,
        SettingSource::Row(SettingScope::Project(value_project)),
        "the project value decides the project read"
    );
    assert_eq!(
        source
            .backup_policy()
            .expect("read the source backup choice"),
        Some(policy),
        "the source holds the backup policy"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let (dest_vault, dest_vault_from, _) = owner_number(&dest, &[]);
    assert_eq!(
        dest_vault, source_vault,
        "the owner import installs the vault value"
    );
    assert_eq!(
        dest_vault_from, source_vault_from,
        "the restored vault read decides as the source read does"
    );
    let (dest_pin, dest_pin_from, _) = owner_number(&dest, &[SettingScope::Project(pin_project)]);
    assert_eq!(dest_pin, 11, "the owner import installs the pin");
    assert_eq!(
        dest_pin_from,
        SettingSource::Pin(SettingScope::Project(pin_project)),
        "the restored pin read decides from the pin"
    );
    let (dest_narrow, dest_narrow_from, _) =
        owner_number(&dest, &[SettingScope::Project(value_project)]);
    assert_eq!(
        dest_narrow, source_narrow,
        "the owner import installs the project value"
    );
    assert_eq!(
        dest_narrow_from, source_narrow_from,
        "the restored project read decides as the source read does"
    );
    assert_eq!(
        dest.backup_policy()
            .expect("read the restored backup choice"),
        Some(policy),
        "the owner import installs the backup policy"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "SETTING", "installed_rows"),
        Some(4),
        "the owner import reports four installed SETTING rows; an absent field means it installed nothing: {summary}"
    );

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    assert_eq!(
        table_count(&repeat_summary, "SETTING", "unchanged_live_rows"),
        Some(4),
        "the repeat owner import reports four unchanged live SETTING rows; an absent field means it counted no live outcome: {repeat_summary}"
    );
    assert_eq!(
        table_count(&repeat_summary, "SETTING", "installed_rows"),
        Some(0),
        "the repeat owner import installs no SETTING row; an absent field means it counted no live outcome: {repeat_summary}"
    );

    let (_bare_dir, bare) = open_later_vault();
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    let (bare_vault, bare_vault_from, _) = owner_number(&bare, &[]);
    assert_eq!(
        bare_vault, 7,
        "the actorless import leaves the vault value at its default"
    );
    assert_eq!(
        bare_vault_from,
        SettingSource::Default,
        "the actorless vault read decides from no row"
    );
    let (bare_pin, bare_pin_from, _) = owner_number(&bare, &[SettingScope::Project(pin_project)]);
    assert_eq!(
        bare_pin, 7,
        "the actorless import leaves the pin read at its default"
    );
    assert_eq!(
        bare_pin_from,
        SettingSource::Default,
        "the actorless pin read decides from no row"
    );
    let (bare_narrow, bare_narrow_from, _) =
        owner_number(&bare, &[SettingScope::Project(value_project)]);
    assert_eq!(
        bare_narrow, 7,
        "the actorless import leaves the project read at its default"
    );
    assert_eq!(
        bare_narrow_from,
        SettingSource::Default,
        "the actorless project read decides from no row"
    );
    assert_eq!(
        bare.backup_policy()
            .expect("read the actorless backup choice"),
        None,
        "the actorless import leaves the backup choice at none"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    assert!(
        matches!(
            table_count(&bare_summary, "SETTING", "installed_rows"),
            None | Some(0)
        ),
        "the actorless import installs no SETTING row: {bare_summary}"
    );
}

/// The destination keeps its own different value; the import counts it kept.
#[test]
fn owner_restore_keeps_a_different_live_setting_row() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let source_outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value("test.owner_number", serde_json::json!(9)),
        )
        .expect("the owner sets the source value");
    assert!(
        matches!(
            source_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the source value applies with a sequence: {source_outcome:?}"
    );
    let (source_value, _, _) = owner_number(&source, &[]);
    assert_eq!(source_value, 9, "the source holds its value");
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let dest_outcome = dest
        .set_setting(
            SettingCaller::Owner(&dest_owner),
            SetSetting::vault_value("test.owner_number", serde_json::json!(10)),
        )
        .expect("the owner sets the destination value");
    assert!(
        matches!(
            dest_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the destination value applies with a sequence: {dest_outcome:?}"
    );
    let (before, _, _) = owner_number(&dest, &[]);
    assert_eq!(
        before, 10,
        "the destination holds its own value before the import"
    );

    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let (after, after_from, _) = owner_number(&dest, &[]);
    assert_eq!(after, 10, "the owner import keeps the different live value");
    assert_eq!(
        after_from,
        SettingSource::Row(SettingScope::Vault),
        "the kept read still decides from the live row"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "SETTING", "kept_live_rows"),
        Some(1),
        "the owner import reports one kept-live SETTING row; an absent field means it counted no live outcome: {summary}"
    );
}

/// A row that names an absent scope entity stays out as `missing_live_entity`.
#[test]
fn owner_restore_holds_back_setting_rows_that_fail_their_key_checks() {
    // Part (a), a row under a catalogue-unknown key name, needs a door that
    // stores a well-formed setting row under an arbitrary name. The existing
    // door only plants undecodable bytes under a known key, so (a) is absent
    // here and the report names the missing door.
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let absent = fixed_id(0x5A);
    let outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting {
                key: "test.owner_number".to_owned(),
                item: None,
                scope: SettingScope::Project(absent),
                mode: SettingMode::Value,
                value: Some(serde_json::json!(9)),
                expected_revision: None,
                why: None,
                check_in_ref: None,
                weight_runs: None,
            },
        )
        .expect("the owner sets a project value naming an absent entity");
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the set applies without checking the scope entity: {outcome:?}"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    // The second row is the source root's birth row of `test.born_depth` (stage 7c-2): the
    // import maps the source root onto this vault's own root, so that row's scope is not live.
    assert_eq!(
        held_back_for_table(&summary, "SETTING"),
        Some(serde_json::json!([{ "reason": "missing_live_entity", "rows": 2 }])),
        "the owner import holds back the absent entity's SETTING row and the source root's birth row as missing_live_entity; an absent field means it counted no held-back outcome: {summary}"
    );
    let (value, from, _) = owner_number(&dest, &[SettingScope::Project(absent)]);
    assert_eq!(
        value, 7,
        "the held-back row leaves the project read at its default"
    );
    assert_eq!(
        from,
        SettingSource::Default,
        "the held-back read decides from no row"
    );
}

/// The change history installs, and the counter never goes back.
#[test]
fn owner_restore_installs_the_setting_change_history_and_never_lowers_its_counter() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let first = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value("test.owner_number", serde_json::json!(9)),
        )
        .expect("the owner sets the first value");
    let (first_sequence, _) = applied_in(&first);
    let second = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value("test.owner_number", serde_json::json!(10)),
        )
        .expect("the owner sets the second value");
    let (second_sequence, _) = applied_in(&second);
    assert_eq!(
        second_sequence,
        first_sequence + 1,
        "the second change follows the first"
    );
    let policy = BackupPolicy {
        enabled: true,
        every_hours: 6,
        keep: 3,
    };
    let third = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value(
                "backup.policy",
                serde_json::to_value(&policy).expect("the policy serializes"),
            ),
        )
        .expect("the owner sets the backup policy");
    let (third_sequence, _) = applied_in(&third);
    assert_eq!(
        third_sequence,
        second_sequence + 1,
        "the third change follows the second"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "SETTING_CHANGE", "installed_rows"),
        Some(3),
        "the owner import reports three installed SETTING_CHANGE rows; an absent field means it installed nothing: {summary}"
    );

    let source_first = oneiron::test_doors::setting::setting_change(&source, first_sequence)
        .expect("the source change reads")
        .expect("the source holds its first change");
    let dest_first = oneiron::test_doors::setting::setting_change(&dest, first_sequence)
        .expect("the destination change reads")
        .expect("the destination holds the source first change");
    assert_eq!(
        dest_first.key, source_first.key,
        "the restored change names the source key"
    );
    assert_eq!(
        dest_first.value, source_first.value,
        "the restored change holds the source value"
    );

    let fourth = dest
        .set_setting(
            SettingCaller::Owner(&dest_owner),
            SetSetting::vault_value("test.owner_number", serde_json::json!(11)),
        )
        .expect("the owner sets one more value on the destination");
    let (fourth_sequence, fourth_revision) = applied_in(&fourth);
    assert_eq!(
        fourth_sequence,
        third_sequence + 1,
        "the next change follows the restored history"
    );
    assert_eq!(
        fourth_revision, fourth_sequence,
        "the changed row names the new change as its revision"
    );
}

/// Absent rows of hooked keys install through the hook; a refused row stays out.
#[test]
fn owner_restore_passes_an_absent_row_through_its_keys_change_hook() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let count_outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value("booking.emergency.max_proposals", serde_json::json!(5)),
        )
        .expect("the owner sets the count above its default");
    assert!(
        matches!(
            count_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the count applies with a sequence: {count_outcome:?}"
    );
    let floor_outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value("booking.emergency.min_proposals", serde_json::json!(4)),
        )
        .expect("the owner sets the floor at or below the count");
    assert!(
        matches!(
            floor_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the floor applies with a sequence: {floor_outcome:?}"
    );
    let (source_count, _) = setting_at_vault(&source, "booking.emergency.max_proposals");
    assert_eq!(
        source_count,
        serde_json::json!(5),
        "the source holds the count"
    );
    let (source_floor, _) = setting_at_vault(&source, "booking.emergency.min_proposals");
    assert_eq!(
        source_floor,
        serde_json::json!(4),
        "the source holds the floor"
    );
    let archive = export_whole(&source);

    // Destinations that read through the settings verb hold the writer lease,
    // which `open_later_vault` does not take, so they open owned after the
    // same wall-clock sleep.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let (_first_dir, first) = open_source_vault();
    let first_owner = owner_proof(&first);
    let first_receipt = first
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &first_owner)
        .expect("the owner import succeeds");
    let first_summary =
        serde_json::to_value(&first_receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&first_summary, "SETTING", "installed_rows"),
        Some(2),
        "the owner import reports two installed SETTING rows; an absent field means it installed nothing: {first_summary}"
    );
    let (first_count, _) = setting_at_vault(&first, "booking.emergency.max_proposals");
    assert_eq!(
        first_count, source_count,
        "the owner import installs the count"
    );
    let (first_floor, _) = setting_at_vault(&first, "booking.emergency.min_proposals");
    assert_eq!(
        first_floor, source_floor,
        "the owner import installs the floor"
    );

    std::thread::sleep(std::time::Duration::from_millis(1100));
    let (_second_dir, second) = open_source_vault();
    let second_owner = owner_proof(&second);
    let low_outcome = second
        .set_setting(
            SettingCaller::Owner(&second_owner),
            SetSetting::vault_value("booking.emergency.max_proposals", serde_json::json!(2)),
        )
        .expect("the owner sets a count below the archived floor");
    assert!(
        matches!(
            low_outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the low count applies with a sequence: {low_outcome:?}"
    );
    let (before_floor, before_floor_from) =
        setting_at_vault(&second, "booking.emergency.min_proposals");
    assert_eq!(
        before_floor,
        serde_json::json!(2),
        "the floor reads its default before the import"
    );
    assert_eq!(
        before_floor_from,
        SettingSource::Default,
        "no floor row stands before the import"
    );

    let second_receipt = second
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &second_owner)
        .expect("the owner import succeeds");
    let second_summary =
        serde_json::to_value(&second_receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&second_summary, "SETTING", "kept_live_rows"),
        Some(1),
        "the owner import reports one kept-live SETTING row; an absent field means it counted no live outcome: {second_summary}"
    );
    // The missing_live_entity row is the source root's birth row of `test.born_depth` (stage
    // 7c-2): the import maps the source root onto this vault's own root.
    assert_eq!(
        held_back_for_table(&second_summary, "SETTING"),
        Some(serde_json::json!([
            { "reason": "invalid_value", "rows": 1 },
            { "reason": "missing_live_entity", "rows": 1 }
        ])),
        "the owner import holds back one SETTING row as invalid_value and the source root's birth row as missing_live_entity; an absent field means it counted no held-back outcome: {second_summary}"
    );
    let (after_count, _) = setting_at_vault(&second, "booking.emergency.max_proposals");
    assert_eq!(
        after_count,
        serde_json::json!(2),
        "the owner import keeps the live count"
    );
    let (after_floor, after_floor_from) =
        setting_at_vault(&second, "booking.emergency.min_proposals");
    assert_eq!(
        after_floor, before_floor,
        "the held-back floor reads as before the import"
    );
    assert_eq!(
        after_floor_from,
        SettingSource::Default,
        "no floor row stands after the held-back import"
    );
}

/// The owner restore runs an absent hooked row's change hook at the restore's
/// own time: the row keeps its archived set time, and the effect the hook
/// starts restarts from now (ARCHIVE-RESTORE-LIVE = B; review P1 of #9435: a
/// feed hook scheduled its first poll at the archived time).
#[test]
fn owner_restore_runs_a_change_hook_at_the_restore_time() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let outcome = source
        .set_setting(
            SettingCaller::Owner(&source_owner),
            SetSetting::vault_value("test.hooked", serde_json::json!(7)),
        )
        .expect("the owner sets the hooked key");
    applied_in(&outcome);
    let source_set_at = vault_row_set_at(&source, "test.hooked");
    let archive = export_whole(&source);

    // The destination reads through the settings verb, so it opens owned,
    // after the same wall-clock sleep as the other destinations.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let (_dest_dir, dest) = open_source_vault();
    let dest_owner = owner_proof(&dest);
    let hooked_before = oneiron::test_doors::setting_keys::hooked_changes();
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert!(
        oneiron::test_doors::setting_keys::hooked_changes() > hooked_before,
        "the owner restore runs the hooked key's change hook"
    );
    assert_eq!(
        vault_row_set_at(&dest, "test.hooked"),
        source_set_at,
        "the restored row keeps its archived set time"
    );
    let hook_at = oneiron::test_doors::setting_keys::hooked_last_at();
    assert!(
        hook_at > source_set_at,
        "the hook's change is stamped at the restore ({hook_at}), after the archived set time ({source_set_at})"
    );
}
