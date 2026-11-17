#![cfg(oneiron_test_support)]
//! The side-table catalogue guard (SIDE-1, OF-222): every canonical side
//! table has at most one archive class (`family`, `other_section`,
//! `retained`, `omitted`), and every table with none is listed in
//! `archive_side_catalogue_unclassified.txt`, one name per line, C-sorted.
//! A new canonical table fails this guard until production carries it,
//! retains it, declares it omitted, or covers it by another archive section.
//!
//! Red without the SIDE-1 production change: the door this test reads does
//! not exist there, so it fails to compile; that is its red.
//! `cargo test --locked -p oneiron --all-features --test archive_side_catalogue_coverage`.

use std::collections::BTreeSet;

use oneiron::test_doors::archive_side_catalogue::{
    archive_side_disposition_names, canonical_archive_side_coverage,
};

/// The canonical tables no archive class covers yet.
const UNCLASSIFIED: &str = include_str!("archive_side_catalogue_unclassified.txt");

fn unclassified_list() -> BTreeSet<&'static str> {
    UNCLASSIFIED
        .lines()
        .filter(|line| !line.is_empty())
        .collect()
}

#[test]
fn every_canonical_side_table_has_one_archive_class_or_is_listed_unclassified() {
    let coverage = canonical_archive_side_coverage();
    for (name, classes) in &coverage {
        for class in classes {
            assert!(
                ["family", "other_section", "retained", "omitted"].contains(class),
                "a known archive class for {name}: {class}"
            );
        }
        assert!(
            classes.len() <= 1,
            "one archive class at most for {name}: {classes:?}"
        );
    }
    let uncovered: BTreeSet<&str> = coverage
        .iter()
        .filter(|(_, classes)| classes.is_empty())
        .map(|(name, _)| *name)
        .collect();
    let listed = unclassified_list();
    let new: Vec<&&str> = uncovered.difference(&listed).collect();
    let stale: Vec<&&str> = listed.difference(&uncovered).collect();
    if !new.is_empty() || !stale.is_empty() {
        println!(
            "new canonical tables with no archive class (give each an archive class in batch/export/archive_side_dispositions.rs, or add it to tests/archive_side_catalogue_unclassified.txt): {new:?}"
        );
        println!(
            "stale list entries (covered, or no canonical table: remove each from tests/archive_side_catalogue_unclassified.txt): {stale:?}"
        );
    }
    assert!(
        new.is_empty() && stale.is_empty(),
        "the uncovered tables equal the unclassified list: {} uncovered, {} listed",
        uncovered.len(),
        listed.len()
    );
}

#[test]
fn the_archive_dispositions_name_existing_canonical_tables() {
    let coverage = canonical_archive_side_coverage();
    let canonical: BTreeSet<&str> = coverage.iter().map(|(name, _)| *name).collect();
    let dispositions = archive_side_disposition_names();
    assert_eq!(dispositions.len(), 131, "the dispositions name 131 tables");
    let count = |class: &str| {
        dispositions
            .iter()
            .filter(|(_, known)| *known == class)
            .count()
    };
    assert_eq!(count("retained"), 103, "the dispositions retain 103 tables");
    assert_eq!(count("omitted"), 23, "the dispositions omit 23 tables");
    assert_eq!(
        count("other_section"),
        5,
        "the dispositions name 5 other-section tables"
    );
    let mut seen = BTreeSet::new();
    for (name, class) in &dispositions {
        assert!(
            canonical.contains(name),
            "the {class} disposition names a canonical table: {name}"
        );
        assert!(seen.insert(*name), "no disposition name repeats: {name}");
    }
    for (name, classes) in &coverage {
        if classes.contains(&"family") {
            assert!(
                canonical.contains(name),
                "a family table is a canonical declaration: {name}"
            );
            assert!(
                seen.insert(*name),
                "a family table repeats no disposition name: {name}"
            );
        }
    }
}
