use super::*;
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrantRole, InitialSharedMember, SharedVaultCreation, decode_federation_grant_body,
    encode_federation_grant_body,
};
use crate::memory::{StructuralEdgeSpec, StructuralPutInput};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_TASK,
};
use crate::{TimeRange, VaultConfig};

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

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    id
}
fn stamp_bytes(vault: &Vault, id: EntityId) -> Option<Vec<u8>> {
    let txn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .vault_meta
        .get(&txn, &key(id))
        .unwrap()
        .map(|raw| raw.to_vec())
}
fn habit(vault: &Vault, member: EntityId) -> EntityId {
    let row = vault
        .memory(member, EdgeActorClass::Human)
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "TASK".into(),
            body: serde_json::json!({"role": 4, "content": "habit"}),
            text_fields: None,
            edges: None,
            occurred_at: 10,
            learned_at: None,
        })
        .unwrap();
    EntityId::from_hex(&row.id_hex).unwrap()
}
fn shared() -> (tempfile::TempDir, Vault, EntityId, SharedVaultCreation) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let owner = person(&vault);
    let member = person(&vault);
    let authenticated = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let creation = vault
        .initialize_shared_vault(
            &authenticated,
            42,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(FederationGrantRole::Owner),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(FederationGrantRole::Member),
                },
            ],
            1,
        )
        .unwrap();
    (dir, vault, member, creation)
}

#[test]
fn generic_child_in_scope_cannot_rewrite_an_out_of_scope_habit_parent() {
    let (_dir, vault, member, created) = shared();
    let parent = habit(&vault, member);
    // This fixture changes only the DIGEST-BOUND position of the parent. The
    // child remains in the default project; no arbitrary unstamped row is used.
    let raw = vault.get_raw(&parent).unwrap().unwrap();
    let mut stamp: Stamp = serde_json::from_slice(&stamp_bytes(&vault, parent).unwrap()).unwrap();
    stamp.scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .vault_meta
                .put(txn, &key(parent), &serde_json::to_vec(&stamp).unwrap())?;
            Ok(())
        })
        .unwrap();
    assert!(vault.record_scope(&parent).unwrap().is_some());
    let grant_id = created
        .grant_refs
        .iter()
        .find_map(|hex| {
            let id = EntityId::from_hex(hex).unwrap();
            let bytes = vault.get_raw(&id).unwrap().unwrap();
            (decode_federation_grant_body(&bytes[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .unwrap()
                .member_ref
                == member)
                .then_some(id)
        })
        .unwrap();
    let bytes = vault.get_raw(&grant_id).unwrap().unwrap();
    let mut grant =
        decode_federation_grant_body(&bytes[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap();
    grant.authority_scope.audience =
        ScopeAxis::Some(BTreeSet::from([
            ScopeId(crate::claim::default_project_id()),
        ]));
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
    let child = EntityId::now();
    let old_stamp = stamp_bytes(&vault, parent);
    let old_receipts = vault
        .memory(member, EdgeActorClass::Human)
        .receipts(100)
        .unwrap();
    assert!(
        vault
            .memory(member, EdgeActorClass::Human)
            .put_structural(&StructuralPutInput {
                id: Some(child.to_hex()),
                kind: "TASK".into(),
                body: serde_json::json!({"role": 5, "note": "generic"}),
                text_fields: None,
                edges: Some(vec![StructuralEdgeSpec {
                    edge_kind: "child_of".into(),
                    target_ref: parent.to_hex(),
                    weight: None,
                }]),
                occurred_at: 11,
                learned_at: None,
            })
            .is_err()
    );
    assert_eq!(vault.get_raw(&parent).unwrap().unwrap(), raw);
    assert!(vault.get_raw(&child).unwrap().is_none());
    assert!(vault.edges_out(&child).unwrap().is_empty());
    assert_eq!(stamp_bytes(&vault, parent), old_stamp);
    assert_eq!(
        vault
            .memory(member, EdgeActorClass::Human)
            .receipts(100)
            .unwrap(),
        old_receipts
    );
}

fn materialize_streak(vault: &Vault, id: EntityId, days: u32) {
    vault
        .with_write_txn(|txn| {
            crate::ports::EntityStoreMaintenance::port_habit_streak_materialize(
                &vault.store,
                txn,
                &id,
                crate::habit::HabitStreak {
                    current: days,
                    longest: days,
                },
            )
        })
        .unwrap();
}

fn replay_changed_task(vault: &Vault, id: EntityId, marker: &str) {
    let raw = vault.get_raw(&id).unwrap().unwrap();
    // A valid opaque TASK replay must be MessagePack; change one ordinary field.
    let mut value: rmpv::Value =
        rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap();
    let rmpv::Value::Map(ref mut entries) = value else {
        panic!("task body map")
    };
    entries.push(("opaque".into(), marker.into()));
    let mut replay_body = Vec::new();
    rmpv::encode::write_value(&mut replay_body, &value).unwrap();
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_TASK,
            TimeRange { start: 10, end: 10 },
            10,
            &replay_body,
        )
        .commit()
        .unwrap();
}

#[test]
fn reducer_and_replay_keep_the_birth_stamp_and_replay_never_mints() {
    let (_dir, vault, member, _) = shared();
    let parent = habit(&vault, member);
    let expected = vault.record_scope(&parent).unwrap().unwrap();
    let born = stamp_bytes(&vault, parent).unwrap();
    // The stamp binds to the record id, not its bytes: a derived streak
    // rewrite and an opaque replayed edit both inherit the birth stamp.
    materialize_streak(&vault, parent, 1);
    assert_eq!(vault.record_scope(&parent).unwrap(), Some(expected.clone()));
    replay_changed_task(&vault, parent, "changed");
    assert_eq!(vault.record_scope(&parent).unwrap(), Some(expected.clone()));
    materialize_streak(&vault, parent, 2);
    assert_eq!(vault.record_scope(&parent).unwrap(), Some(expected));
    assert_eq!(stamp_bytes(&vault, parent), Some(born));
    // Without a local stamp, neither replay nor the reducer mints one.
    vault
        .with_write_txn(|txn| retire_stamp(&vault.store, txn, parent))
        .unwrap();
    replay_changed_task(&vault, parent, "again");
    materialize_streak(&vault, parent, 3);
    assert!(vault.record_scope(&parent).unwrap().is_none());
    assert!(stamp_bytes(&vault, parent).is_none());
}
