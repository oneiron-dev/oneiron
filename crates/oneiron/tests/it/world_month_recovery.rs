//! Featureless canonical world-month carry and retained-shell round trip.

use loro::LoroDoc;
use oneiron::recovery::{capture_canonical_window, rebuild_vault_window_from_canonical};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};

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
    )
    .expect("fixture");
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
