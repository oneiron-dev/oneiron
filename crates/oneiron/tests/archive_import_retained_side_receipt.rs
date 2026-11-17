#![cfg(oneiron_test_support)]
//! The whole-vault import receipt's retained-rows summary (SIDE-1, OF-222).
//!
//! The owner import of the retained-rows fixture reports three inserted rows
//! (the backup choice, the standing grant and the grant's gate receipt),
//! names each table's counts, and names the manifest's 23 omitted tables; a
//! repeat import reports nothing inserted and three unchanged. The fixture
//! is shared from `archive_import_retained_side_rows.rs`, whose tests also
//! run in this binary.
//!
//! Red on the base: this file names the new `retained_side_rows` receipt
//! field and the new `side_table_omissions` manifest field, so it fails to
//! compile there; that is its red.
//! `cargo test --locked -p oneiron --all-features --test archive_import_retained_side_receipt`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use retained_side_rows::{open_later_vault, owner_proof, source_with_rows};

#[test]
fn the_import_receipt_counts_retained_rows_and_names_omitted_tables() {
    let source = source_with_rows();
    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&source.archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary = &receipt.retained_side_rows;
    // Per-table counts: the brief's two targets plus the grant's gate receipt.
    for (table, inserted, unchanged) in [
        ("BACKUP_POLICY", 1, 0),
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
    // Full count accounting: every admitted retained row, not just the two targets.
    assert_eq!(
        summary.inserted_rows, 3,
        "the summary counts three inserted rows: {summary:?}"
    );
    assert_eq!(
        summary.unchanged_rows, 0,
        "the summary counts no unchanged rows: {summary:?}"
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
        repeat.retained_side_rows.unchanged_rows, 3,
        "a repeat import leaves three rows unchanged: {:?}",
        repeat.retained_side_rows
    );
}
