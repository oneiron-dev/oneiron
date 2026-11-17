//! The checkpoint adapter descriptor (UC-10 PR 2) captures, frames, checks
//! and restores as the getters it replaces do. The door restates the text
//! index's source text and the row births as descriptor rows; each test runs
//! the descriptor and the getter over the same real side-table rows.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::checkpoint_descriptor as doors;
use oneiron::{EntityId, Vault, VaultConfig};

/// The text-source rows and the row births each seeded vault holds.
const ROWS: usize = 3;

fn fresh_vault(directory: &tempfile::TempDir, name: &str) -> Vault {
    Vault::open(directory.path().join(name), VaultConfig::device())
        .expect("open a fresh device vault")
}

fn seeded_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let vault = fresh_vault(&directory, "source");
    let seeded = doors::seed_rows(&vault, ROWS).expect("seed text-source rows and row births");
    assert_eq!(seeded.documents.len(), ROWS);
    assert_eq!(seeded.born.len(), ROWS);
    (directory, vault)
}

#[test]
fn descriptor_captures_and_frames_as_the_getters_do() {
    let (_directory, vault) = seeded_vault();
    let comparisons = doors::compare_captures(&vault).expect("capture through both");
    assert_eq!(comparisons.len(), 3, "{comparisons:?}");
    for comparison in &comparisons {
        assert!(
            comparison.owners >= ROWS,
            "every seeded owner is captured: {comparison:?}"
        );
        assert!(comparison.same_capture, "{comparison:?}");
        assert!(comparison.same_frames, "{comparison:?}");
    }
    let births = comparisons
        .iter()
        .find(|comparison| comparison.adapter == "row births")
        .expect("the births comparison");
    assert!(
        births.actor_parts >= ROWS,
        "each seeded birth's process actor is split out: {births:?}"
    );
    assert!(
        births.dependencies >= ROWS,
        "each seeded born-from row holds only while its trigger does: {births:?}"
    );
}

#[test]
fn descriptor_restores_as_the_getters_do() {
    let (directory, vault) = seeded_vault();
    let descriptor_target = fresh_vault(&directory, "descriptor-target");
    let getter_target = fresh_vault(&directory, "getter-target");
    let comparisons = doors::compare_restores(&vault, &descriptor_target, &getter_target, true)
        .expect("restore through both");
    assert_eq!(comparisons.len(), 2, "{comparisons:?}");
    for comparison in &comparisons {
        assert!(comparison.written >= ROWS, "{comparison:?}");
        assert_eq!(comparison.dropped, 0, "every actor opened: {comparison:?}");
        assert!(comparison.same_restore, "{comparison:?}");
        assert!(comparison.kept_rows_back, "{comparison:?}");
    }
}

#[test]
fn descriptor_drops_a_split_row_whose_actor_did_not_open() {
    let (directory, vault) = seeded_vault();
    let descriptor_target = fresh_vault(&directory, "descriptor-target");
    let getter_target = fresh_vault(&directory, "getter-target");
    let comparisons = doors::compare_restores(&vault, &descriptor_target, &getter_target, false)
        .expect("restore through both");
    for comparison in &comparisons {
        assert!(comparison.same_restore, "{comparison:?}");
        assert!(comparison.kept_rows_back, "{comparison:?}");
    }
    let text = comparisons
        .iter()
        .find(|comparison| comparison.adapter == "text source by table")
        .expect("the text comparison");
    assert_eq!(text.dropped, 0, "a text row names no actor: {text:?}");
    let births = comparisons
        .iter()
        .find(|comparison| comparison.adapter == "row births")
        .expect("the births comparison");
    assert!(
        births.dropped >= ROWS,
        "each birth whose actor did not open is left out: {births:?}"
    );
    assert!(
        births.written >= ROWS,
        "each born-from row is written whole: {births:?}"
    );
}

#[test]
fn descriptor_refuses_the_parts_the_getters_refuse() {
    let (_directory, vault) = seeded_vault();
    let verdicts = doors::restore_verdicts(&vault, EntityId::now(), EntityId::now())
        .expect("restore each part");
    let expected: [(&str, bool, Option<bool>); 7] = [
        ("its own text row", true, Some(true)),
        ("an undecodable text value", false, Some(false)),
        (
            "a row of a table the adapter does not hold",
            false,
            Some(false),
        ),
        (
            "a no-one-form part where no actor splits out",
            false,
            Some(false),
        ),
        // The text getter has no owner gate; source audiences and blocked
        // reports do, and the descriptor's gate is theirs.
        (
            "another owner's text row behind the owner gate",
            false,
            Some(true),
        ),
        ("its own text row behind the owner gate", true, Some(true)),
        (
            "its own text row under an own check that refuses every part",
            false,
            None,
        ),
    ];
    assert_eq!(verdicts.len(), expected.len(), "{verdicts:?}");
    for (case, descriptor_admits, getter_admits) in expected {
        let verdict = verdicts
            .iter()
            .find(|verdict| verdict.case == case)
            .unwrap_or_else(|| panic!("no verdict for {case}: {verdicts:?}"));
        assert_eq!(
            (verdict.descriptor_admits, verdict.getter_admits),
            (descriptor_admits, getter_admits),
            "{case}"
        );
    }
}

#[test]
fn own_capture_stands_in_for_the_table_steps_and_a_mislisted_table_refuses() {
    let (_directory, vault) = seeded_vault();
    let comparisons = doors::compare_captures(&vault).expect("capture through both");
    let own = comparisons
        .iter()
        .find(|comparison| comparison.adapter == "text source by its own capture")
        .expect("the own-capture comparison");
    assert!(own.same_capture && own.same_frames, "{own:?}");
    assert!(
        doors::mislisted_capture_refuses(&vault).expect("read the vault"),
        "a by-table capture refuses a table its adapter's own capture places"
    );
}

#[test]
fn descriptor_owns_only_its_tables() {
    let ownership = doors::ownership(EntityId::now(), EntityId::now());
    assert!(ownership.births_own_a_birth, "{ownership:?}");
    assert!(ownership.births_own_a_born_from_row, "{ownership:?}");
    assert!(!ownership.births_own_a_text_row, "{ownership:?}");
    assert!(ownership.text_owns_a_text_row, "{ownership:?}");
    assert!(!ownership.text_owns_a_birth, "{ownership:?}");
}
