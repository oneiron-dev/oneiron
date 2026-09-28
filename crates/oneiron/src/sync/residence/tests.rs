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
