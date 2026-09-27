//! Shared-vault cross-door content effects, independent of facade spelling.
use super::*;
use crate::Vault;
use crate::federation::{
    FederationGrantPreset, FederationGrantRole, InitialSharedMember, ScopeAxis, ScopeId,
    decode_federation_grant_body, encode_federation_grant_body,
};
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_FEDERATION_GRANT};
use std::collections::BTreeSet;

fn shared() -> (tempfile::TempDir, Vault, EntityId, EntityId, Vec<String>) {
    let (dir, vault) = open_vault();
    let owner = put_person(&vault, 0xD1);
    let member = put_person(&vault, 0xD2);
    let viewer = put_person(&vault, 0xD3);
    let authenticated = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let created = vault
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
                InitialSharedMember {
                    member_ref: viewer,
                    role: Some(FederationGrantRole::Viewer),
                },
            ],
            1,
        )
        .unwrap();
    (dir, vault, member, viewer, created.grant_refs)
}

fn change_member_grant(
    vault: &Vault,
    refs: &[String],
    member: EntityId,
    change: impl FnOnce(&mut crate::federation::FederationGrant),
) {
    let (id, mut grant) = refs
        .iter()
        .find_map(|hex| {
            let id = EntityId::from_hex(hex).unwrap();
            let raw = vault.get_raw(&id).unwrap().unwrap();
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
            (grant.member_ref == member).then_some((id, grant))
        })
        .unwrap();
    change(&mut grant);
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_FEDERATION_GRANT,
            test_time(1),
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
}

fn artifact(id: EntityId, name: &str) -> BlobArtifactInput {
    BlobArtifactInput {
        id: Some(id.to_hex()),
        name: name.into(),
        media_type: "text/plain".into(),
        occurred_at: 10,
        learned_at: None,
    }
}

#[test]
fn blob_creation_replacement_and_scoped_old_new_positions_fail_closed() {
    let (_dir, vault, member, viewer, refs) = shared();
    let member_facade = facade_for(&vault, member);
    let viewer_facade = facade_for(&vault, viewer);
    let id = EntityId::now();
    let denied_id = EntityId::now();
    assert!(
        viewer_facade
            .put_blob_artifact(&artifact(denied_id, "forbidden"))
            .is_err()
    );
    assert!(vault.get_raw(&denied_id).unwrap().is_none());
    member_facade
        .put_blob_artifact(&artifact(id, "original"))
        .unwrap();
    let old = vault.get_raw(&id).unwrap();
    let old_index = vault.entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT).unwrap();
    let old_receipts = member_facade.receipts(100).unwrap();
    change_member_grant(&vault, &refs, member, |grant| {
        grant.role = FederationGrantRole::Viewer;
        grant.preset = FederationGrantPreset::ReadOnly;
        grant.authority_scope = crate::federation::scope_codec::read_preset();
    });
    assert!(
        member_facade
            .put_blob_artifact(&artifact(id, "replacement"))
            .is_err()
    );
    assert_eq!(vault.get_raw(&id).unwrap(), old);
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT).unwrap(),
        old_index
    );
    assert_eq!(member_facade.receipts(100).unwrap(), old_receipts);
    change_member_grant(&vault, &refs, member, |grant| {
        grant.role = FederationGrantRole::Member;
        grant.preset = FederationGrantPreset::Member;
        grant.authority_scope = crate::federation::grant_scope::membership_preset(grant.role);
        grant.authority_scope.audience =
            ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    });
    let fresh = EntityId::now();
    assert!(
        member_facade
            .put_blob_artifact(&artifact(fresh, "outside new"))
            .is_err()
    );
    assert!(
        member_facade
            .put_blob_artifact(&artifact(id, "outside old"))
            .is_err()
    );
    assert!(vault.get_raw(&fresh).unwrap().is_none());
    assert_eq!(vault.get_raw(&id).unwrap(), old);
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT).unwrap(),
        old_index
    );
    assert_eq!(member_facade.receipts(100).unwrap(), old_receipts);

    let (_private_dir, private) = open_vault();
    let person = put_person(&private, 0xD4);
    let personal_id = EntityId::now();
    private
        .memory(person, EdgeActorClass::Human)
        .put_blob_artifact(&artifact(personal_id, "personal"))
        .unwrap();
    assert!(private.get_raw(&personal_id).unwrap().is_some());
}

#[test]
fn typed_then_generic_then_typed_checkin_preserves_parent_scope() {
    let (_dir, vault, member, _, _) = shared();
    let memory = facade_for(&vault, member);
    let habit = memory
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
    let parent = EntityId::from_hex(&habit.id_hex).unwrap();
    let typed = |at| HabitCheckinInput {
        habit_ref: habit.id_hex.clone(),
        id: None,
        data: Some(serde_json::json!({"note": "done"})),
        occurred_at: at,
        learned_at: None,
    };
    let first = memory.put_habit_checkin(&typed(11)).unwrap();
    let middle = memory
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "TASK".into(),
            body: serde_json::json!({"role": 5, "note": "generic"}),
            text_fields: None,
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "child_of".into(),
                target_ref: habit.id_hex.clone(),
                weight: None,
            }]),
            occurred_at: 12,
            learned_at: None,
        })
        .unwrap();
    let last = memory.put_habit_checkin(&typed(13)).unwrap();
    for child in [first, middle, last] {
        let id = EntityId::from_hex(&child.id_hex).unwrap();
        assert!(
            vault
                .edges_out(&id)
                .unwrap()
                .iter()
                .any(|edge| { edge.kind == EdgeKind::ChildOf && edge.target == parent })
        );
    }
    assert!(vault.record_scope(&parent).unwrap().is_some());
    let body = memory
        .get_entity(&habit.id_hex)
        .unwrap()
        .unwrap()
        .body
        .unwrap();
    assert_eq!(body["currentStreak"], serde_json::json!(1));
    assert_eq!(body["longestStreak"], serde_json::json!(1));
}

#[test]
fn unpositioned_legacy_facade_mutations_require_full_shared_write_scope() {
    let (_dir, vault, member, viewer, refs) = shared();
    let persona = member;
    let id = EntityId::now();
    let input = CompanionRecordInput {
        id: Some(id.to_hex()),
        owner_ref: viewer.to_hex(),
        persona_ref: persona.to_hex(),
        value: serde_json::json!({"name": "denied"}),
        source: None,
        retired_at: None,
        learned_at: 10,
    };
    assert!(
        facade_for(&vault, viewer)
            .put_companion_record(&input)
            .is_err()
    );
    assert!(vault.get_raw(&id).unwrap().is_none());
    change_member_grant(&vault, &refs, member, |grant| {
        grant.authority_scope.audience =
            ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    });
    let mut input = input;
    input.owner_ref = member.to_hex();
    assert!(
        facade_for(&vault, member)
            .put_companion_record(&input)
            .is_err()
    );
    assert!(vault.get_raw(&id).unwrap().is_none());
}

#[test]
fn nested_raw_batch_cannot_escape_the_actor_content_transaction() {
    let (_dir, vault, member, _, refs) = shared();
    let memory = facade_for(&vault, member);
    let note = memory.create_note("research", "current").unwrap();
    let note_id = EntityId::from_hex(&note.id_hex).unwrap();
    let before = vault.note_document(note_id).unwrap();
    change_member_grant(&vault, &refs, member, |grant| {
        grant.authority_scope.bands =
            ScopeAxis::Some(BTreeSet::from([crate::registry::ENTITY_TYPE_NOTE]));
    });
    let blob = EntityId::now();
    let data = crate::blob_artifact::encode_blob_artifact_body(
        &crate::blob_artifact::BlobArtifactBody::new("not allowed", "text/plain"),
    )
    .unwrap();
    assert!(
        memory
            .with_actor_content_write_txn(|content| {
                content.update_note(note_id, |txn| {
                    // A nested call to the ordinary batch method cannot hide its
                    // BLOB effect behind the NOTE's already-authorized position.
                    vault
                        .batch_in()
                        .put(
                            &blob,
                            crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                            test_time(20),
                            20,
                            &data,
                        )
                        .apply(txn)?;
                    Ok(())
                })
            })
            .is_err()
    );
    assert!(vault.get_raw(&blob).unwrap().is_none());
    assert_eq!(vault.note_document(note_id).unwrap(), before);
    // The failed in-flight binding cannot poison a later valid content write.
    memory.create_note("research", "after refusal").unwrap();
}
