use super::*;
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrantRole, InitialSharedMember, SharedVaultCreation, decode_federation_grant_body,
    encode_federation_grant_body,
};
use crate::memory::{StructuralEdgeSpec, StructuralPutInput};
use crate::registry::{
    ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_NOTE, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_TASK,
};
use crate::{TimeRange, VaultConfig};
use std::collections::BTreeSet;

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
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
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
            None,
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
            None,
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

fn born_note(vault: &Vault, markdown: &str) -> EntityId {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let actor = crate::WriteActor::new(owner, EdgeActorClass::Human);
    vault
        .create_note("research", markdown, actor)
        .expect("a born NOTE")
}

/// The PROJECT a NOTE reads at, as the placement reader answers it.
fn note_project(vault: &Vault, id: EntityId) -> Option<EntityId> {
    let raw = vault
        .get_raw(&id)
        .expect("the NOTE row reads")
        .expect("the NOTE is stored");
    let txn = vault.store.env.read_txn().unwrap();
    stored_project(
        &vault.store,
        &txn,
        id,
        ENTITY_TYPE_NOTE,
        &raw[ENTITY_METADATA_HEADER_LEN..],
    )
    .expect("the NOTE placement reads")
}

#[test]
fn a_note_is_born_at_the_default_project() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let note = born_note(&vault, "a fresh NOTE's placement");

    assert_eq!(
        note_project(&vault, note),
        Some(crate::claim::default_project_id()),
        "a fresh NOTE reads at the default project"
    );
}

#[test]
fn stamp_note_project_moves_only_a_default_audience() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let project = EntityId::now();
    let other = EntityId::now();
    let note = born_note(&vault, "a NOTE the session settles");

    vault
        .with_write_txn(|txn| stamp_note_project(&vault.store, txn, note, project))
        .expect("a default audience settles onto the session project");
    assert_eq!(
        note_project(&vault, note),
        Some(project),
        "the settled NOTE reads at its project"
    );
    vault
        .with_write_txn(|txn| stamp_note_project(&vault.store, txn, note, project))
        .expect("settling the same project again confirms it");
    assert_eq!(
        note_project(&vault, note),
        Some(project),
        "the re-settled NOTE still reads at its project"
    );
    let err = vault
        .with_write_txn(|txn| stamp_note_project(&vault.store, txn, note, other))
        .expect_err("a NOTE settled elsewhere refuses another project");
    assert!(
        matches!(err, Error::InvalidClaimBody("record scope restamp refused")),
        "another project is refused as a restamp, got {err:?}"
    );
    assert_eq!(
        note_project(&vault, note),
        Some(project),
        "the refused settle keeps the NOTE at its project"
    );
    let row = person(&vault);
    let err = vault
        .with_write_txn(|txn| stamp_note_project(&vault.store, txn, row, project))
        .expect_err("a non-NOTE row refuses the NOTE settle door");
    assert!(
        matches!(err, Error::InvalidEntityType(_)),
        "a non-NOTE row is refused by kind, got {err:?}"
    );
}

#[test]
fn an_unstamped_row_reads_as_default_and_an_unusable_stamp_as_none() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let bare = born_note(&vault, "a NOTE whose stamp is retired");
    vault
        .with_write_txn(|txn| retire_stamp(&vault.store, txn, bare))
        .unwrap();
    assert_eq!(
        note_project(&vault, bare),
        Some(crate::claim::default_project_id()),
        "a NOTE with no stamp reads as the default project"
    );

    let split = born_note(&vault, "a NOTE with a split audience");
    vault
        .with_write_txn(|txn| {
            let facet = birth_facet(&vault.store, txn, split)?.expect("the NOTE's birth facet");
            let mut scope = default_stamp(ENTITY_TYPE_NOTE, facet);
            scope.audience = ScopeAxis::Some(BTreeSet::from([
                ScopeId(EntityId::now()),
                ScopeId(EntityId::now()),
            ]));
            SCOPE_RECORD.put(
                &vault.store,
                txn,
                &split,
                &Stamp {
                    version: 2,
                    kind: ENTITY_TYPE_NOTE,
                    birth_facet: *facet.as_bytes(),
                    scope,
                },
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        note_project(&vault, split),
        None,
        "a NOTE whose audience names two projects reads as no placement"
    );

    let loose = born_note(&vault, "a NOTE whose stamp does not bind");
    vault
        .with_write_txn(|txn| {
            let stranger = EntityId::now();
            let scope = default_stamp(ENTITY_TYPE_NOTE, stranger);
            SCOPE_RECORD.put(
                &vault.store,
                txn,
                &loose,
                &Stamp {
                    version: 2,
                    kind: ENTITY_TYPE_NOTE,
                    birth_facet: *stranger.as_bytes(),
                    scope,
                },
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        note_project(&vault, loose),
        None,
        "a NOTE whose present stamp does not bind reads as no placement"
    );
}

#[test]
fn session_projects_admit_row_refuses_an_unusable_placement_and_a_root_row_when_bound() {
    use crate::session_project::SessionProjects;

    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let bare = born_note(&vault, "a NOTE whose stamp is retired");
    let loose = born_note(&vault, "a NOTE whose stamp does not bind");
    vault
        .with_write_txn(|txn| {
            retire_stamp(&vault.store, txn, bare)?;
            let stranger = EntityId::now();
            SCOPE_RECORD.put(
                &vault.store,
                txn,
                &loose,
                &Stamp {
                    version: 2,
                    kind: ENTITY_TYPE_NOTE,
                    birth_facet: *stranger.as_bytes(),
                    scope: default_stamp(ENTITY_TYPE_NOTE, stranger),
                },
            )?;
            Ok(())
        })
        .unwrap();

    let bare_raw = vault.get_raw(&bare).unwrap().expect("the unstamped NOTE");
    let loose_raw = vault.get_raw(&loose).unwrap().expect("the bad-stamp NOTE");
    let txn = vault.store.env.read_txn().unwrap();
    let bound = |project| SessionProjects::Bound {
        project,
        closure: BTreeSet::from([project]).into(),
    };
    let other = bound(EntityId::now());
    let root = bound(crate::claim::default_project_id());
    let admits = |id, raw: &[u8], projects: &SessionProjects| {
        session_projects_admit_row(&vault.store, &txn, id, raw, projects, false)
            .expect("the session admission decision")
    };

    assert!(
        !admits(loose, &loose_raw, &root),
        "a NOTE whose stamp does not bind must not be read even if the closure admits root"
    );
    assert!(
        !admits(bare, &bare_raw, &other),
        "an unstamped NOTE must not be read if the closure excludes root"
    );
    assert!(
        admits(bare, &bare_raw, &root),
        "an unstamped NOTE must be read if the closure admits root"
    );
    assert!(
        !admits(bare, &bare_raw, &SessionProjects::Unbound),
        "an unbound session must not read the unstamped NOTE"
    );
    assert!(
        !admits(loose, &loose_raw, &SessionProjects::Unbound),
        "an unbound session must not read the NOTE whose stamp does not bind"
    );
    assert!(
        !session_projects_admit_row(&vault.store, &txn, bare, &bare_raw, &other, true)
            .expect("the room lane's session admission decision"),
        "a room history lane still judges a NOTE by its placement (PLACEMENT-B-ROOM-ROWS = B)"
    );
}
