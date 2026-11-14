#![cfg(oneiron_test_support)]
//! The whole-vault import receipt's retained-rows summary (SIDE-2a).
//!
//! The owner import of the retained-rows fixture installs the backup choice
//! live and reports two inert inserted rows (the standing grant and the
//! grant's gate receipt) plus one installed row; it names each table's counts
//! and the manifest's 23 omitted tables. A repeat import reports nothing
//! inserted, two inert unchanged rows and one unchanged live row. The fixture
//! is shared from `archive_import_retained_side_rows.rs`, whose tests also
//! run in this binary.
//!
//! New live counts are read through `serde_json::to_value`, so this file
//! still compiles on df2ecf9d4376; an absent field fails its assertion.
//! `cargo test --locked -p oneiron --all-features --test archive_import_retained_side_receipt`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use retained_side_rows::{open_later_vault, owner_proof, source_with_rows};

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
    // Per-table inert counts: the backup choice now installs live, so only the
    // standing grant and its gate receipt stay inert.
    for (table, inserted, unchanged) in [
        ("BACKUP_POLICY", 0, 0),
        ("CONSENT_STANDING_GRANT", 1, 0),
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
    // Full inert accounting: every admitted retained row, not just the two targets.
    assert_eq!(
        summary.inserted_rows, 2,
        "the summary counts two inert inserted rows: {summary:?}"
    );
    assert_eq!(
        summary.unchanged_rows, 0,
        "the summary counts no inert unchanged rows: {summary:?}"
    );
    // New live counts through JSON, so this still compiles on SIDE-1.
    let summary_json =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary_json, "BACKUP_POLICY", "installed_rows"),
        Some(1),
        "the summary counts one installed BACKUP_POLICY row; an absent field means it installed nothing: {summary_json}"
    );
    assert_eq!(
        summary_json
            .get("installed_rows")
            .and_then(|count| count.as_u64()),
        Some(1),
        "the summary counts one installed row in all; an absent field means it installed nothing: {summary_json}"
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
        23,
        "the receipt names 23 omitted tables: {:?}",
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
        repeat.retained_side_rows.unchanged_rows, 2,
        "a repeat import leaves two inert rows unchanged: {:?}",
        repeat.retained_side_rows
    );
    let repeat_json =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    assert_eq!(
        table_count(&repeat_json, "BACKUP_POLICY", "unchanged_live_rows"),
        Some(1),
        "a repeat import leaves one BACKUP_POLICY row unchanged live; an absent field means it counted no live outcome: {repeat_json}"
    );
    assert_eq!(
        repeat_json
            .get("unchanged_live_rows")
            .and_then(|count| count.as_u64()),
        Some(1),
        "a repeat import leaves one row unchanged live in all; an absent field means it counted no live outcome: {repeat_json}"
    );
}
