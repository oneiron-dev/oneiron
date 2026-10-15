use super::*;
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    encode_federation_grant_body,
};
use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use crate::sync::SyncSelectorWorld;
use crate::temporal::TimeRange;

#[test]
fn paged_index_is_metadata_only_and_first_touch_is_one_granted_item() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let actor = crate::test_util::entity(11);
    let grant_id = crate::test_util::entity(12);
    let visible = crate::test_util::entity(13);
    let hidden = crate::test_util::entity(14);
    let scope = FederationGrantScope::vault(7);
    let grant = FederationGrant::new(
        scope,
        actor,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    let title = rmp_serde::to_vec_named(
        &serde_json::json!({"title":"A current item", "body":"never in the index"}),
    )
    .unwrap();
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    for id in [visible, hidden] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &title,
            )
            .unwrap();
    }
    let window = WindowKey::new("1970-01");
    let source = create_window_doc("source", &window);
    for id in [grant_id, visible, hidden] {
        let raw = vault.get_raw(&id).unwrap().unwrap();
        map_insert_bytes(&source.get_map("entities"), &id.to_hex(), &raw).unwrap();
    }
    source.commit();
    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    let projection =
        window_index_projection(&vault, &source, &window, scope, &selector, 128, |id| {
            Ok(id == visible)
        })
        .unwrap();
    let index = window_index_page(
        &projection,
        IndexPage {
            after: None,
            limit: 256,
        },
    )
    .unwrap();
    assert_eq!(
        index,
        vec![WindowIndexEntry {
            entity_id: visible.to_hex(),
            title: Some("A current item".into()),
            learned_at: 1,
        }]
    );
    let blob = selected_item_blob(&vault, &source, &window, scope, &selector, visible)
        .unwrap()
        .unwrap();
    assert_eq!(Some(blob), vault.get_raw(&visible).unwrap());
    assert!(
        selected_item_blob(
            &vault,
            &source,
            &window,
            scope,
            &selector,
            crate::test_util::entity(99)
        )
        .unwrap()
        .is_none()
    );
    let impostor = SyncSelector::new(grant_id, hidden, SyncSelectorWorld::All, vec![], vec![]);
    assert!(selected_item_blob(&vault, &source, &window, scope, &impostor, visible).is_err());
}

#[test]
fn full_window_promotion_preserves_causality_and_concurrent_merges() {
    let window = WindowKey::new("2026-09");
    let source = create_window_doc("home", &window);
    let id = crate::test_util::entity(34).to_hex();
    map_insert_bytes(&source.get_map("entities"), &id, b"base").unwrap();
    source.commit();
    // The promotion carries the canonical frontier, with no full history.
    let snapshot = source
        .export(ExportMode::shallow_snapshot(&source.oplog_frontiers()))
        .unwrap();
    let device = create_window_doc("device", &window);
    device.import(&snapshot).unwrap();
    let before_device = device.oplog_vv();
    map_insert_bytes(&device.get_map("entities"), &id, b"device-only").unwrap();
    device.commit();
    let delta = device.export(ExportMode::updates(&before_device)).unwrap();
    source.import(&delta).unwrap();
    assert_eq!(
        map_get_bytes(&source.get_map("entities"), &id),
        Some(b"device-only".to_vec())
    );

    let home_before = source.oplog_vv();
    let device_before = device.oplog_vv();
    map_insert_bytes(&source.get_map("entities"), &id, b"home-concurrent").unwrap();
    source.commit();
    map_insert_bytes(&device.get_map("entities"), &id, b"device-concurrent").unwrap();
    device.commit();
    let home_delta = source.export(ExportMode::updates(&home_before)).unwrap();
    let device_delta = device.export(ExportMode::updates(&device_before)).unwrap();
    source.import(&device_delta).unwrap();
    device.import(&home_delta).unwrap();
    assert_eq!(source.oplog_vv(), device.oplog_vv());
    assert_eq!(
        map_get_bytes(&source.get_map("entities"), &id),
        map_get_bytes(&device.get_map("entities"), &id)
    );
}

/// Sol R5 F5: a promotion names every row of the window it admits through
/// `readable`, and its caller lists those as the rows the snapshot was
/// derived from (DEC-0005). A local write that lands on the window between
/// the walk and the export puts a row in the bytes that the walk never
/// named. The snapshot that leaves carries only rows a walk named.
#[test]
fn a_promotion_snapshot_carries_no_row_its_walk_did_not_name() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let actor = crate::test_util::entity(21);
    let grant_id = crate::test_util::entity(22);
    let (first, late) = (crate::test_util::entity(23), crate::test_util::entity(24));
    let scope = FederationGrantScope::vault(7);
    let grant = FederationGrant::new(
        scope,
        actor,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    let body = rmp_serde::to_vec_named(&serde_json::json!({"title":"A window row"})).unwrap();
    for id in [first, late] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .unwrap();
    }
    let window = WindowKey::new("1970-01");
    let source = create_window_doc("source", &window);
    let raw = vault.get_raw(&first).unwrap().unwrap();
    map_insert_bytes(&source.get_map("entities"), &first.to_hex(), &raw).unwrap();
    source.commit();
    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    // The rows a promotion's snapshot carries, and those its walks named.
    let promote = || {
        let mut named = Vec::new();
        let snapshot = promotion_snapshot(&vault, &source, &window, scope, &selector, |id| {
            named.push(id);
            Ok(true)
        })
        .unwrap()
        .expect("the window promotes whole");
        let carried = LoroDoc::new();
        carried.import(&snapshot).unwrap();
        let mut rows = Vec::new();
        map_for_each_value_bytes(&carried.get_map("entities"), |key, _| {
            rows.push(EntityId::from_hex(key).unwrap());
        });
        (rows, named)
    };
    let (rows, named) = promote();
    assert_eq!(rows, [first]);
    assert!(named.contains(&first), "{named:?}");

    let raw = vault.get_raw(&late).unwrap().unwrap();
    promotion_hook::arm(move |doc| {
        map_insert_bytes(&doc.get_map("entities"), &late.to_hex(), &raw).unwrap();
        doc.commit();
    });
    let (rows, named) = promote();
    assert!(rows.contains(&late), "the write landed: {rows:?}");
    assert!(
        rows.iter().all(|row| named.contains(row)),
        "{rows:?} carried, {named:?} named"
    );
}

/// Bug repro (SOL-S3-008, ASTRA-S3-004): a pinned window with two heads, one of which took a
/// diagnostic out, has no root its history check passes: Loro roots it before both heads, where
/// the diagnostic still sits. Persisting the window falls back to that root; a promotion must
/// never ship it.
#[test]
fn a_promotion_never_ships_a_root_the_history_check_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let actor = crate::test_util::entity(31);
    let grant_id = crate::test_util::entity(32);
    let (first, late) = (crate::test_util::entity(33), crate::test_util::entity(34));
    let scope = FederationGrantScope::vault(7);
    let grant = FederationGrant::new(
        scope,
        actor,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    let body = rmp_serde::to_vec_named(&serde_json::json!({"title":"A window row"})).unwrap();
    for id in [first, late] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .unwrap();
    }
    let window = WindowKey::new("1970-01");
    let source = create_window_doc("source", &window);
    let entities = source.get_map("entities");
    map_insert_bytes(
        &entities,
        &first.to_hex(),
        &vault.get_raw(&first).unwrap().unwrap(),
    )
    .unwrap();
    let mut diagnostic = vec![crate::registry::ENTITY_TYPE_DIAGNOSTIC];
    for _ in 0..3 {
        diagnostic.extend_from_slice(&1u64.to_be_bytes());
    }
    diagnostic.extend_from_slice(b"placeholder diagnostic");
    let carrier = crate::test_util::entity(35).to_hex();
    map_insert_bytes(&entities, &carrier, &diagnostic).unwrap();
    source.commit();
    // One head takes the diagnostic out, as the export scrub does; the other adds a row.
    let branch = source.fork();
    crate::sync::loro_support::map_delete(&branch.get_map("entities"), &carrier).unwrap();
    branch.commit();
    crate::sync::window::require_history_free_window(&vault, &window).unwrap();
    map_insert_bytes(
        &entities,
        &late.to_hex(),
        &vault.get_raw(&late).unwrap().unwrap(),
    )
    .unwrap();
    source.commit();
    source
        .import(&branch.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    assert_eq!(source.oplog_frontiers().len(), 2, "fixture: two heads");

    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    let promoted = promotion_snapshot(&vault, &source, &window, scope, &selector, |_| Ok(true));
    assert!(
        !matches!(promoted, Ok(Some(_))),
        "a promotion shipped a root that holds the diagnostic"
    );
}
