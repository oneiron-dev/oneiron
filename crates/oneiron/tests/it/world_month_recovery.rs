//! Featureless canonical world-month carry and retained-shell round trip.

use loro::LoroDoc;
use oneiron::recovery::{
    CanonicalSnapshot, capture_canonical_window, rebuild_vault_window_from_canonical,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeKind, EntityId,
    TimeRange, Vault, VaultConfig,
};

#[test]
fn soft_world_claim_round_trips_without_sync_feature() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let world = EntityId::now();
    let person = EntityId::now();
    let claim = EntityId::now();
    let at = 1_771_027_200;
    let occurred = TimeRange { start: at, end: at };
    vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            occurred,
            at,
            b"world",
        )
        .unwrap();
    vault
        .put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            occurred,
            at,
            b"person",
        )
        .unwrap();
    let mut body = ClaimBody::new(
        "test.featureless_world",
        ClaimSubject::Entity(person),
        rmpv::Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.world = Some(world);
    vault.put_claim(&claim, &body, occurred, at).unwrap();
    vault
        .batch()
        .edge(&claim, EdgeKind::About, &person, 1.0)
        .commit()
        .unwrap();
    vault
        .delete_entity_with_reason(&claim, oneiron::deletion::DeleteReason::UserDelete)
        .unwrap();
    let key = format!("2026-02@{}", world.to_hex());
    let snapshot = capture_canonical_window(&vault, &key, &LoroDoc::new()).unwrap();
    assert!(
        snapshot
            .entity_blobs
            .iter()
            .any(|row| row.id == *claim.as_bytes() && row.blob.len() == 25)
    );
    assert!(
        snapshot
            .base_edges
            .iter()
            .any(|row| row.source == *claim.as_bytes() && row.target == *person.as_bytes())
    );
    let bytes = snapshot.encode().unwrap();
    assert_eq!(CanonicalSnapshot::decode(&bytes).unwrap(), snapshot);
    let rebuilt = rebuild_vault_window_from_canonical(&snapshot).unwrap();
    assert!(rebuilt.get_map("entities").get(&claim.to_hex()).is_some());
    assert!(rebuilt.get_map("tombstones").get(&claim.to_hex()).is_some());
    let mut wrong_month = snapshot.clone();
    wrong_month.window = format!("2026-03@{}", world.to_hex());
    assert!(wrong_month.validate().is_err());
    assert!(wrong_month.encode().is_err());
    let mut wrong_world = snapshot;
    wrong_world.window = format!("2026-02@{}", EntityId::now().to_hex());
    assert!(wrong_world.validate().is_err());
}

#[test]
fn malformed_world_claim_domain_is_rejected_before_canonical_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let world = EntityId::now();
    let person = EntityId::now();
    let claim = EntityId::now();
    let at = 1_771_027_200;
    let occurred = TimeRange { start: at, end: at };
    vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            occurred,
            at,
            b"world",
        )
        .unwrap();
    vault
        .put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            occurred,
            at,
            b"person",
        )
        .unwrap();
    let mut body = ClaimBody::new(
        "test.canonical_domain",
        ClaimSubject::Entity(person),
        rmpv::Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.world = Some(world);
    vault.put_claim(&claim, &body, occurred, at).unwrap();
    let raw = vault.get_raw(&claim).unwrap().unwrap();
    let doc = LoroDoc::new();
    doc.get_map("entities")
        .insert(&claim.to_hex(), raw.as_slice())
        .unwrap();
    doc.commit();
    let window = format!("2026-02@{}", world.to_hex());
    let mut snapshot = capture_canonical_window(&vault, &window, &doc).unwrap();
    let carrier = snapshot
        .entity_blobs
        .iter_mut()
        .find(|row| row.id == *claim.as_bytes())
        .unwrap();
    let mut fields: rmpv::Value = rmpv::decode::read_value(&mut &carrier.blob[25..]).unwrap();
    let rmpv::Value::Map(entries) = &mut fields else {
        panic!("CLAIM body is a map")
    };
    for (key, value) in entries {
        if key.as_str() == Some("pred") {
            *value = rmpv::Value::from("edge.provenance");
        }
        if key.as_str() == Some("val") {
            *value = rmpv::Value::from("junk");
        }
    }
    carrier.blob.truncate(25);
    rmpv::encode::write_value(&mut carrier.blob, &fields).unwrap();
    assert!(snapshot.validate().is_err());
    assert!(snapshot.encode().is_err());
    assert!(rebuild_vault_window_from_canonical(&snapshot).is_err());
}
