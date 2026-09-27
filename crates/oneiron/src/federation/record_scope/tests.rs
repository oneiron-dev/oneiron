use super::*;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;

#[test]
fn opaque_edit_keeps_birth_scope_and_changed_facet_refuses_restamp() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let person = EntityId::now();
    let facet = EntityId::now();
    let at = crate::unix_seconds_now();
    let time = TimeRange { start: at, end: at };
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, time, at, b"original")
        .unwrap();
    let original = vault.record_scope(&person).unwrap().unwrap();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, time, at, b"edited")
        .unwrap();
    assert_eq!(vault.record_scope(&person).unwrap(), Some(original));
    let public = rmp_serde::to_vec_named(&serde_json::json!({"sensitivity":"public"})).unwrap();
    let private = rmp_serde::to_vec_named(&serde_json::json!({"sensitivity":"private"})).unwrap();
    vault
        .put_entity(&facet, ENTITY_TYPE_FACET, time, at, &public)
        .unwrap();
    let born = vault.record_scope(&facet).unwrap().unwrap();
    let err = vault
        .put_entity(&facet, ENTITY_TYPE_FACET, time, at, &private)
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidClaimBody("record scope restamp refused")
    ));
    assert_eq!(vault.record_scope(&facet).unwrap(), Some(born));
    assert_eq!(
        vault.get_raw(&facet).unwrap().unwrap()[ENTITY_METADATA_HEADER_LEN..],
        public
    );
}

#[test]
fn claim_birth_facet_remains_visible_after_value_edit() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let actor = EntityId::now();
    let id = EntityId::now();
    let at = crate::unix_seconds_now();
    let time = TimeRange { start: at, end: at };
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, time, at, b"actor")
        .unwrap();
    let mut claim = crate::claim::ClaimBody::new(
        "residence.test",
        crate::claim::ClaimSubject::Entity(actor),
        rmpv::Value::from("base"),
        0.8,
        crate::claim::ClaimApprovalStatus::Proposed,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    let original = crate::claim::encode_claim_body(&claim).unwrap();
    vault
        .put_entity(&id, ENTITY_TYPE_CLAIM, time, at, &original)
        .unwrap();
    let born = vault
        .record_scope(&id)
        .unwrap()
        .expect("claim carries its birth scope");
    claim.value = rmpv::Value::from("edited");
    let changed = crate::claim::encode_claim_body(&claim).unwrap();
    vault
        .put_entity(&id, ENTITY_TYPE_CLAIM, time, at, &changed)
        .unwrap();
    assert_eq!(vault.record_scope(&id).unwrap(), Some(born));
}
