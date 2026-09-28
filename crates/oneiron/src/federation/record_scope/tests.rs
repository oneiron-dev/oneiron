use super::*;
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrantRole, InitialSharedMember, SharedVaultCreation, decode_federation_grant_body,
    encode_federation_grant_body,
};
use crate::memory::{StructuralEdgeSpec, StructuralPutInput};
use crate::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::{TimeRange, VaultConfig};

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
    SCOPE_RECORD.get_bytes(&vault.store, &txn, &id).unwrap()
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
            SCOPE_RECORD.put(&vault.store, txn, &parent, &stamp)?;
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

#[test]
fn reducer_rebinds_only_a_valid_prior_stamp_and_never_mints_on_replay() {
    let (_dir, vault, member, _) = shared();
    let parent = habit(&vault, member);
    let expected = vault.record_scope(&parent).unwrap().unwrap();
    vault
        .with_write_txn(|txn| {
            crate::ports::EntityStoreMaintenance::port_habit_streak_materialize(
                &vault.store,
                txn,
                &parent,
                crate::habit::HabitStreak {
                    current: 1,
                    longest: 1,
                },
            )
        })
        .unwrap();
    assert_eq!(vault.record_scope(&parent).unwrap(), Some(expected));
    let original_stamp = stamp_bytes(&vault, parent).unwrap();
    // Replaying a different opaque body has no local positive stamp.
    let raw = vault.get_raw(&parent).unwrap().unwrap();
    // A valid opaque TASK replay must be MessagePack; change one ordinary field.
    let mut value: rmpv::Value =
        rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap();
    let rmpv::Value::Map(ref mut entries) = value else {
        panic!("task body map")
    };
    entries.push(("opaque".into(), "changed".into()));
    let mut replay_body = Vec::new();
    rmpv::encode::write_value(&mut replay_body, &value).unwrap();
    vault
        .batch()
        .put_replicated(
            &parent,
            ENTITY_TYPE_TASK,
            TimeRange { start: 10, end: 10 },
            10,
            &replay_body,
        )
        .commit()
        .unwrap();
    assert!(vault.record_scope(&parent).unwrap().is_none());
    vault
        .with_write_txn(|txn| {
            crate::ports::EntityStoreMaintenance::port_habit_streak_materialize(
                &vault.store,
                txn,
                &parent,
                crate::habit::HabitStreak {
                    current: 2,
                    longest: 2,
                },
            )
        })
        .unwrap();
    assert!(vault.record_scope(&parent).unwrap().is_none());
    // Stale old bytes are not accepted as proof for a later projection.
    vault
        .with_write_txn(|txn| {
            let original: Stamp = serde_json::from_slice(&original_stamp).unwrap();
            SCOPE_RECORD.put(&vault.store, txn, &parent, &original)?;
            crate::ports::EntityStoreMaintenance::port_habit_streak_materialize(
                &vault.store,
                txn,
                &parent,
                crate::habit::HabitStreak {
                    current: 3,
                    longest: 3,
                },
            )
        })
        .unwrap();
    assert!(vault.record_scope(&parent).unwrap().is_none());
}
