#![cfg(oneiron_test_support)]
//! The whole-vault import receipt's retained-rows summary (SIDE-2a).
//!
//! The owner import of the retained-rows fixture installs the snapshot bounds
//! and the standing grant live (2 installed rows) and keeps the grant's gate
//! receipt inert. The setting rows the source wrote when it opened (the
//! `engine` pack's default layer and its root's birth row of
//! `test.born_depth`, which lands at this vault's root) are kept live: this
//! vault holds its own (SETTING-ARCHIVE-SOURCE-ROOT-SCOPE-HELD-BACK). Each
//! kept row stays an inert copy, so the import reports one inserted row more
//! per open row, and it holds back no row. It names each table's counts and
//! the manifest's 22 omitted tables. A repeat import reports nothing inserted,
//! the same rows inert unchanged and kept live, and two unchanged live rows.
//! The fixture is shared from `archive_import_retained_side_rows.rs`, whose
//! tests also run in this binary.
//!
//! Live counts are read through `serde_json::to_value`; an absent field fails
//! its assertion. Before this change the test is red: the 21 Nov nightly at
//! main 0aedc807c526 fails it at the grant's inserted count (0, not 1), and
//! the lander held the open setting rows back.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_import_retained_side_receipt`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use retained_side_rows::{open_later_vault, open_setting_row_count, owner_proof, source_with_rows};

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

#[test]
fn the_import_receipt_counts_retained_rows_and_names_omitted_tables() {
    let source = source_with_rows();
    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&source.archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary = &receipt.retained_side_rows;
    let open_rows = open_setting_row_count(&source.archive);
    let open_inert = usize::try_from(open_rows).expect("a row count fits in usize");
    // Per-table inert counts: the snapshot bounds and the standing grant
    // install live, so of the fixture's rows only the gate receipt stays inert.
    for (table, inserted, unchanged) in [
        ("SNAPSHOT_READ_SETTINGS", 0, 0),
        ("CONSENT_STANDING_GRANT", 0, 0),
        ("GATE_DECISION_LEDGER", 1, 0),
    ] {
        let entry = summary
            .tables
            .iter()
            .find(|entry| entry.source_table == table)
            .unwrap_or_else(|| panic!("the summary counts {table}: {summary:?}"));
        assert_eq!(
            entry.inserted_rows, inserted,
            "the summary counts {table} inserted rows"
        );
        assert_eq!(
            entry.unchanged_rows, unchanged,
            "the summary counts {table} unchanged rows"
        );
    }
    // Full inert accounting: every admitted retained row, not just the two
    // targets. Beside the gate receipt, each open setting row stays an inert
    // copy of a row this vault kept live.
    assert_eq!(
        summary.inserted_rows,
        1 + open_inert,
        "the summary counts the gate receipt and {open_inert} open setting rows as inert inserted rows: {summary:?}"
    );
    assert_eq!(
        summary.unchanged_rows, 0,
        "the summary counts no inert unchanged rows: {summary:?}"
    );
    let summary_json =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for table in ["SNAPSHOT_READ_SETTINGS", "CONSENT_STANDING_GRANT"] {
        assert_eq!(
            table_count(&summary_json, table, "installed_rows"),
            Some(1),
            "the summary counts one installed {table} row; an absent field means it installed nothing: {summary_json}"
        );
    }
    assert_eq!(
        summary_json
            .get("installed_rows")
            .and_then(|count| count.as_u64()),
        Some(2),
        "the summary counts two installed rows in all; an absent field means it installed nothing: {summary_json}"
    );
    assert_eq!(
        table_count(&summary_json, "SETTING", "kept_live_rows"),
        Some(open_rows),
        "the summary counts every open setting row as kept live: this vault holds its own; an absent field means it counted no live outcome: {summary_json}"
    );
    let setting = summary
        .tables
        .iter()
        .find(|entry| entry.source_table == "SETTING")
        .unwrap_or_else(|| panic!("the summary counts SETTING: {summary:?}"));
    assert!(
        setting.held_back.is_empty(),
        "the summary holds back no SETTING row: {summary:?}"
    );
    // The receipt names the manifest's omissions.
    let document = dest
        .read_whole_vault_archive(&source.archive)
        .expect("the archive reads");
    assert_eq!(
        summary.omissions, document.manifest.side_table_omissions,
        "the receipt names the manifest's omissions"
    );
    assert_eq!(
        summary.omissions.len(),
        22,
        "the receipt names 22 omitted tables: {:?}",
        summary.omissions
    );
    let healer = summary
        .omissions
        .iter()
        .find(|omission| omission.table == "HEALER_OVERSIGHT_RECEIPT")
        .expect("the receipt names HEALER_OVERSIGHT_RECEIPT");
    assert_eq!(healer.rows, 3, "the healer omission counts three rows");
    assert_eq!(
        format!("{:?}", healer.reason),
        "EngineAttestationNotRestored",
        "the healer omission names its reason"
    );

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&source.archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    assert_eq!(
        repeat.retained_side_rows.inserted_rows, 0,
        "a repeat import inserts nothing: {:?}",
        repeat.retained_side_rows
    );
    assert_eq!(
        repeat.retained_side_rows.unchanged_rows,
        1 + open_inert,
        "a repeat import leaves the gate receipt and {open_inert} open setting rows inert and unchanged: {:?}",
        repeat.retained_side_rows
    );
    let repeat_json =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    assert_eq!(
        table_count(
            &repeat_json,
            "SNAPSHOT_READ_SETTINGS",
            "unchanged_live_rows"
        ),
        Some(1),
        "a repeat import leaves one SNAPSHOT_READ_SETTINGS row unchanged live; an absent field means it counted no live outcome: {repeat_json}"
    );
    assert_eq!(
        repeat_json
            .get("unchanged_live_rows")
            .and_then(|count| count.as_u64()),
        Some(2),
        "a repeat import leaves the snapshot bounds and the grant unchanged live; an absent field means it counted no live outcome: {repeat_json}"
    );
    assert_eq!(
        table_count(&repeat_json, "SETTING", "kept_live_rows"),
        Some(open_rows),
        "a repeat import keeps every open setting row live again; an absent field means it counted no live outcome: {repeat_json}"
    );
}
