use super::super::{StorageTier, storage_tier};
use super::*;
use std::collections::BTreeMap;

/// A declaration, kind or database added without a restore class fails here,
/// so nothing new is ever restored from an image by default.
#[test]
fn every_canonical_family_and_kind_has_one_class() {
    let mut classed: BTreeMap<&str, usize> = BTreeMap::new();
    for (decl, _) in SIDE_TABLES.iter().copied().flatten() {
        *classed.entry(decl.name).or_default() += 1;
    }
    let mut missing = Vec::new();
    for decl in crate::side_table::declared() {
        let database = match decl.db {
            SideDb::VaultMeta => "vault_meta",
            SideDb::SyncState => "sync_state",
        };
        let canonical = storage_tier(database, decl.prefix) == StorageTier::Canonical;
        match (canonical, classed.remove(decl.name)) {
            (true, Some(1)) | (false, None) => {}
            (true, None) => missing.push(decl.name),
            (_, count) => panic!(
                "{} is classed {count:?} times; canonical: {canonical}",
                decl.name
            ),
        }
    }
    assert!(
        missing.is_empty(),
        "canonical families without a restore class: {missing:?}"
    );
    assert!(
        classed.is_empty(),
        "restore classes naming no canonical family: {classed:?}"
    );

    for entry in crate::registry::ENTITY_TYPE_REGISTRY {
        let classes = ENTITY_KINDS
            .iter()
            .filter(|(kind, _)| *kind == entry.type_byte)
            .count();
        assert_eq!(
            classes, 1,
            "entity kind {} has {classes} classes",
            entry.kind
        );
    }

    for entry in crate::store::DB_MANIFEST {
        let rows: Vec<_> = DATABASES
            .iter()
            .filter(|(name, _)| *name == entry.name)
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "database {} has {} classes",
            entry.name,
            rows.len()
        );
        if matches!(rows[0].1, Rows::Rebuilt) {
            assert_ne!(
                storage_tier(entry.name, b"any key"),
                StorageTier::Canonical,
                "database {} has canonical rows",
                entry.name
            );
        }
    }
}
