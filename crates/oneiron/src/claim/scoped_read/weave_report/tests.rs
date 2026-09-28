use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ScopedReadActorKey};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{EdgeKind, TimeRange, Vault};
use rmpv::Value;

fn put(vault: &Vault, id: u8, predicate: &str, subject: ClaimSubject) -> Result<EntityId> {
    let id = entity(id);
    let body = ClaimBody::new(
        predicate,
        subject,
        Value::from("live"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    if let ClaimSubject::Entity(target) = subject
        && vault.get_entity_type(&target)? == Some(vault.project_type_byte()?)
    {
        // PROJECT is a report subject, but a CLAIM must never edge to its
        // hub. The generic validated CLAIM put keeps the subject in the body
        // without minting put_claim's automatic ClaimOf edge.
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::claim::encode_claim_body(&body)?,
        )?;
    } else {
        vault.put_claim(&id, &body, TimeRange { start: 1, end: 1 }, 1)?;
    }
    Ok(id)
}
fn section(kind: WeaveSectionKind, predicates: &[&str]) -> WeaveSectionSpec {
    WeaveSectionSpec {
        kind,
        predicates: predicates.iter().map(|p| (*p).into()).collect(),
        edge_kinds: Vec::new(),
    }
}
fn claim_ids(items: &[WeaveItem]) -> Vec<EntityId> {
    items
        .iter()
        .filter_map(|item| match item {
            WeaveItem::Claim { id, .. } => Some(*id),
            _ => None,
        })
        .collect()
}

#[test]
fn person_sees_only_self_and_member_project_rows_and_touching_live_links() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let person = entity(0x31);
    let stranger = entity(0x32);
    for id in [person, stranger] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    let project = entity(0x33);
    let outsider_project = entity(0x34);
    let root = vault.root_project()?;
    let root_record = vault.project(root)?.unwrap();
    let leader = EntityId::from_hex(&root_record.leader)?;
    for (id, member) in [(project, person), (outsider_project, stranger)] {
        let mut row = ProjectRecord::new(id, Some(root), root, leader).unwrap();
        row.roster.push(member.to_hex());
        // No goal pointer: only the goal-intake interview may set one.
        vault.put_project(id, &row, 2)?;
    }
    let own = put(&vault, 0x61, "report.change", ClaimSubject::Entity(person))?;
    let member = put(&vault, 0x62, "report.change", ClaimSubject::Entity(project))?;
    let foreign = put(
        &vault,
        0x43,
        "report.change",
        ClaimSubject::Entity(stranger),
    )?;
    let foreign_project = put(
        &vault,
        0x44,
        "report.change",
        ClaimSubject::Entity(outsider_project),
    )?;
    vault.put_edge(&person, EdgeKind::Mentions, &stranger, 0.1)?;
    vault.put_edge(&stranger, EdgeKind::Supports, &person, 0.1)?;
    vault.put_edge(&stranger, EdgeKind::Mentions, &outsider_project, 0.1)?;
    let link = put(
        &vault,
        0x45,
        "report.link",
        ClaimSubject::Edge {
            source: person,
            kind: EdgeKind::Mentions,
            target: stranger,
        },
    )?;
    let ghost = put(
        &vault,
        0x46,
        "report.link",
        ClaimSubject::Edge {
            source: stranger,
            kind: EdgeKind::Mentions,
            target: person,
        },
    )?;
    let ask = put(&vault, 0x68, "report.ask", ClaimSubject::Entity(project))?;
    put(
        &vault,
        0x69,
        "report.ask",
        ClaimSubject::Entity(outsider_project),
    )?;
    crate::test_util::authorize_readers(&vault, &[&person.to_hex()]);
    let read = vault.scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap());
    let mut recipe = [
        section(WeaveSectionKind::Changes, &["report.change"]),
        section(WeaveSectionKind::Projects, &[]),
        section(WeaveSectionKind::OpenAsks, &["report.ask"]),
        section(WeaveSectionKind::Links, &["report.link"]),
    ];
    recipe[3].edge_kinds = vec![EdgeKind::Mentions, EdgeKind::Supports];
    let result = read.weave_report(WeaveReader::Person(person), &recipe)?;
    assert_eq!(
        claim_ids(&result.value.sections[0].items),
        vec![own, member]
    );
    assert!(!claim_ids(&result.value.sections[0].items).contains(&foreign));
    assert!(!claim_ids(&result.value.sections[0].items).contains(&foreign_project));
    assert_eq!(
        result.value.sections[1].items,
        vec![WeaveItem::Project {
            id: project,
            goal: None
        }]
    );
    assert_eq!(claim_ids(&result.value.sections[2].items), vec![ask]);
    assert_eq!(claim_ids(&result.value.sections[3].items), vec![link]);
    assert!(result.value.sections[3].items.contains(&WeaveItem::Link {
        source: person,
        kind: EdgeKind::Mentions,
        target: stranger,
    }));
    assert!(result.value.sections[3].items.contains(&WeaveItem::Link {
        source: stranger,
        kind: EdgeKind::Supports,
        target: person,
    }));
    assert!(!result.value.sections[3].items.contains(&WeaveItem::Link {
        source: stranger,
        kind: EdgeKind::Mentions,
        target: outsider_project,
    }));
    assert!(!claim_ids(&result.value.sections[3].items).contains(&ghost));
    assert!(
        read.weave_report(WeaveReader::Person(stranger), &recipe)
            .is_err()
    );
    assert!(
        read.weave_report(
            WeaveReader::Person(person),
            &[section(WeaveSectionKind::Budgets, &[])]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn owner_and_agent_have_distinct_sections_and_actor_bound_reads() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x51);
    let agent = entity(0x52);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let budget_ref = entity(0x56);
    vault.put_entity(
        &budget_ref,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"budget fixture",
    )?;
    let project = entity(0x57);
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let mut row = ProjectRecord::new(project, Some(root), root, leader).unwrap();
    row.budget = Some(budget_ref.to_hex());
    vault.put_project(project, &row, 2)?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.put_edge(&owner_id, EdgeKind::Supports, &agent, 0.1)?;
    let score = put(&vault, 0x53, "report.score", ClaimSubject::Entity(owner_id))?;
    let digest = put(&vault, 0x54, "report.digest", ClaimSubject::Entity(agent))?;
    let other_digest = put(
        &vault,
        0x55,
        "report.digest",
        ClaimSubject::Entity(owner_id),
    )?;
    crate::test_util::authorize_readers(&vault, &[&owner_id.to_hex(), &agent.to_hex()]);
    let owner_read = vault.scoped_read(ScopedReadActorKey::new(owner_id.to_hex()).unwrap());
    let mut owner_recipe = [
        section(WeaveSectionKind::SieveScore, &["report.score"]),
        section(WeaveSectionKind::Budgets, &[]),
        section(WeaveSectionKind::Links, &[]),
    ];
    owner_recipe[2].edge_kinds = vec![EdgeKind::Supports];
    let view = owner_read.weave_report(WeaveReader::Owner(&owner), &owner_recipe)?;
    assert_eq!(claim_ids(&view.value.sections[0].items), vec![score]);
    assert_eq!(
        view.value.sections[1].items,
        vec![WeaveItem::Budget {
            project,
            budget_ref
        }]
    );
    assert!(view.value.sections[2].items.contains(&WeaveItem::Link {
        source: owner_id,
        kind: EdgeKind::Supports,
        target: agent,
    }));
    assert!(
        owner_read
            .weave_report(
                WeaveReader::Agent(agent),
                &[section(WeaveSectionKind::Digest, &["report.digest"])]
            )
            .is_err()
    );
    let agent_read = vault.scoped_read(ScopedReadActorKey::new(agent.to_hex()).unwrap());
    let view = agent_read.weave_report(
        WeaveReader::Agent(agent),
        &[section(WeaveSectionKind::Digest, &["report.digest"])],
    )?;
    assert_eq!(claim_ids(&view.value.sections[0].items), vec![digest]);
    assert!(!claim_ids(&view.value.sections[0].items).contains(&other_digest));
    assert!(
        agent_read
            .weave_report(
                WeaveReader::Agent(agent),
                &[section(WeaveSectionKind::Admissions, &["report.score"])]
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn report_cannot_widen_world_scoped_grant_or_count_hidden_rows() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let agent = entity(0x71);
    let allowed_world = entity(0x72);
    let denied_world = entity(0x73);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let write = |seed: u8, world| -> Result<EntityId> {
        let id = entity(seed);
        let mut body = ClaimBody::new(
            "report.digest",
            ClaimSubject::Entity(agent),
            Value::from("digest"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.world = Some(world);
        vault.put_claim(&id, &body, TimeRange { start: 1, end: 1 }, 1)?;
        Ok(id)
    };
    let visible = write(0x74, allowed_world)?;
    let hidden = write(0x75, denied_world)?;
    let authority = crate::federation::scope_codec::encode_scope_value(
        &crate::federation::scope_codec::read_preset(),
    )?;
    let bytes = crate::gate::default_policy_manifest().unwrap();
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut bytes.as_slice()).expect("default manifest")
    else {
        panic!("manifest map")
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    entries.push((
        Value::from("scoped_grants"),
        Value::Array(vec![Value::Map(vec![
            (Value::from("actor_ref"), Value::from(agent.to_hex())),
            (Value::from("effector"), Value::from("core:read")),
            (Value::from("scope"), authority),
            (
                Value::from("selectors"),
                Value::Map(vec![(
                    Value::from("world_ref"),
                    Value::from(allowed_world.to_hex()),
                )]),
            ),
            (Value::from("receipt_required"), Value::Boolean(false)),
        ])]),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).expect("manifest encodes");
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )?;
    let read = vault.scoped_read(ScopedReadActorKey::new(agent.to_hex()).unwrap());
    let report = read.weave_report(
        WeaveReader::Agent(agent),
        &[section(WeaveSectionKind::Digest, &["report.digest"])],
    )?;
    assert_eq!(claim_ids(&report.value.sections[0].items), vec![visible]);
    assert!(!claim_ids(&report.value.sections[0].items).contains(&hidden));
    assert_eq!(report.receipt.suppressed_count, 0);
    Ok(())
}

#[test]
fn retracted_provenance_excludes_direct_and_edge_claim_links_for_person_and_owner() -> Result<()> {
    use crate::edge::{EdgeActorClass, EdgeConfirmationStatus};
    use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let person = entity(0x81);
    let peer = entity(0x82);
    for id in [person, peer] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )?;
    }
    let owner = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.put_edge(&person, EdgeKind::Mentions, &peer, 0.5)?;
    let provenance_id = entity(0x83);
    vault.put_edge_provenance(
        &provenance_id,
        &EdgeRef::new(person, EdgeKind::Mentions, peer),
        &EdgeProvenanceClaimBody::new(person, 0.5, SupersessionStatus::Proposed),
        EdgeActorClass::Human,
        100,
    )?;
    let claim = put(
        &vault,
        0x84,
        "report.link",
        ClaimSubject::Edge {
            source: person,
            kind: EdgeKind::Mentions,
            target: peer,
        },
    )?;
    crate::test_util::authorize_readers(&vault, &[&person.to_hex()]);
    let read = vault.scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap());
    let mut recipe = [section(WeaveSectionKind::Links, &["report.link"])];
    recipe[0].edge_kinds = vec![EdgeKind::Mentions];
    let person_view = read.weave_report(WeaveReader::Person(person), &recipe)?;
    assert_eq!(claim_ids(&person_view.value.sections[0].items), vec![claim]);
    assert!(
        person_view.value.sections[0]
            .items
            .contains(&WeaveItem::Link {
                source: person,
                kind: EdgeKind::Mentions,
                target: peer,
            })
    );
    vault.retract_edge_provenance(&provenance_id, 200)?;
    let edge = read
        .edges_out(&person)?
        .value
        .unwrap()
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == peer)
        .expect("retracted edge is retained");
    assert_eq!(
        edge.provenance.unwrap().confirmation_status,
        EdgeConfirmationStatus::Retracted
    );
    for reader in [WeaveReader::Person(person), WeaveReader::Owner(&owner)] {
        let report = read.weave_report(reader, &recipe)?;
        assert!(
            report.value.sections[0].items.is_empty(),
            "retained retracted edge and active edge claim cannot appear live"
        );
    }
    Ok(())
}

#[test]
fn session_weave_uses_composed_claim_and_project_candidates_without_changing_base() -> Result<()> {
    use crate::session_overlay::{OverlayKeyspace, SessionOverlay};
    use crate::store::Store;
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let person = entity(0x90);
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"reader",
    )?;
    let shadowed = put(&vault, 0x91, "report.change", ClaimSubject::Entity(person))?;
    let removed = put(&vault, 0x92, "report.change", ClaimSubject::Entity(person))?;
    let project = entity(0x93);
    let added = entity(0x94);
    let project_change = entity(0x95);
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let mut project_record = ProjectRecord::new(project, Some(root), root, leader).unwrap();
    project_record.roster.push(person.to_hex());
    let kind = vault.project_type_byte()?;
    let project_body = rmp_serde::to_vec_named(&project_record).expect("project encodes");
    let scope_key = [b"scope:record:v1:".as_slice(), project.as_bytes()].concat();
    // Derive the ordinary digest-bound project stamp, but keep it in the
    // overlay only: a base read must not be able to resolve this project.
    let scope_stamp = vault.with_write_txn(|txn| {
        crate::federation::record_scope::stamp_put(
            &vault.store,
            txn,
            project,
            kind,
            &project_body,
            false,
        )?;
        let stamp = vault
            .store
            .vault_meta
            .get(txn, &scope_key)?
            .unwrap()
            .to_vec();
        vault.store.vault_meta.delete(txn, &scope_key)?;
        Ok(stamp)
    })?;
    let overlay = SessionOverlay::new(128 * 1024);
    let segment = overlay.install_txn_segment()?;
    let at = TimeRange { start: 1, end: 1 };
    overlay.put(
        OverlayKeyspace::Entities,
        project.as_bytes(),
        &crate::test_util::entity_record(kind, at, 1, &project_body),
    )?;
    overlay.put(
        OverlayKeyspace::TypeIndex,
        &Store::encode_type_key(kind, &project),
        &[],
    )?;
    overlay.put(OverlayKeyspace::VaultMeta, &scope_key, &scope_stamp)?;
    let stage_claim = |id: EntityId, predicate: &str, subject: ClaimSubject| -> Result<()> {
        let body = ClaimBody::new(
            predicate,
            subject,
            Value::from("session"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        overlay.put(
            OverlayKeyspace::Entities,
            id.as_bytes(),
            &crate::test_util::entity_record(
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                1,
                &crate::claim::encode_claim_body(&body)?,
            ),
        )?;
        overlay.put(
            OverlayKeyspace::TypeIndex,
            &Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, &id),
            &[],
        )?;
        Ok(())
    };
    stage_claim(shadowed, "report.ask", ClaimSubject::Entity(person))?;
    stage_claim(added, "report.change", ClaimSubject::Entity(person))?;
    stage_claim(
        project_change,
        "report.change",
        ClaimSubject::Entity(project),
    )?;
    overlay.delete(OverlayKeyspace::Entities, removed.as_bytes())?;
    overlay.delete(
        OverlayKeyspace::TypeIndex,
        &Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, &removed),
    )?;
    segment.commit()?;
    crate::test_util::authorize_readers(&vault, &[&person.to_hex()]);
    let key = ScopedReadActorKey::new(person.to_hex()).unwrap();
    let recipe = [
        section(WeaveSectionKind::Changes, &["report.change"]),
        section(WeaveSectionKind::OpenAsks, &["report.ask"]),
        section(WeaveSectionKind::Projects, &[]),
    ];
    let base = vault
        .scoped_read(key.clone())
        .weave_report(WeaveReader::Person(person), &recipe)?;
    assert_eq!(
        claim_ids(&base.value.sections[0].items),
        vec![shadowed, removed]
    );
    assert!(base.value.sections[1].items.is_empty());
    assert!(base.value.sections[2].items.is_empty());
    let view = vault.store.session_view(overlay)?;
    let session = vault
        .scoped_read_in_session(key, &view)
        .weave_report(WeaveReader::Person(person), &recipe)?;
    assert_eq!(
        claim_ids(&session.value.sections[0].items),
        vec![added, project_change]
    );
    assert_eq!(claim_ids(&session.value.sections[1].items), vec![shadowed]);
    assert_eq!(
        session.value.sections[2].items,
        vec![WeaveItem::Project {
            id: project,
            goal: None
        }]
    );
    let still_base = vault
        .scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap())
        .weave_report(WeaveReader::Person(person), &recipe)?;
    assert_eq!(still_base.value, base.value);
    Ok(())
}

#[test]
fn authenticated_wrong_link_tap_persists_label_and_rejects_unknown_link() -> Result<()> {
    use crate::provenance::EdgeRef;
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let person = entity(0xb1);
    let peer = entity(0xb2);
    for id in [person, peer] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )?;
    }
    vault.put_edge(&person, EdgeKind::Mentions, &peer, 0.5)?;
    crate::test_util::authorize_readers(&vault, &[&person.to_hex()]);
    let auth = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let read = vault.scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap());
    let link = EdgeRef::new(person, EdgeKind::Mentions, peer);
    let filed = read.report_wrong_link(&auth, WeaveReader::Person(person), link)?;
    assert_eq!(filed.link, link);
    assert_eq!(filed.actor, person);
    assert_eq!(
        read.weave_link_corrections(WeaveReader::Person(person), link)?,
        vec![filed]
    );
    assert_eq!(
        vault.weave_link_correction_labels_in_txn(&vault.store.env.read_txn()?, link)?,
        vec![filed]
    );
    let unknown = EdgeRef::new(peer, EdgeKind::Mentions, person);
    assert!(matches!(
        read.report_wrong_link(&auth, WeaveReader::Person(person), unknown),
        Err(Error::EntityNotFound)
    ));
    assert!(matches!(
        read.weave_link_corrections(WeaveReader::Person(person), unknown),
        Err(Error::EntityNotFound)
    ));
    let stranger = entity(0xb3);
    vault.put_entity(
        &stranger,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"stranger",
    )?;
    let other_auth = vault.authenticate_owner(
        stranger,
        &stranger.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    assert!(
        read.report_wrong_link(&other_auth, WeaveReader::Person(person), link)
            .is_err()
    );
    assert_eq!(
        read.weave_link_corrections(WeaveReader::Person(person), link)?,
        vec![filed]
    );
    assert!(vault.delete_edge(&person, EdgeKind::Mentions, &peer)?);
    assert_eq!(
        vault.weave_link_correction_labels_in_txn(&vault.store.env.read_txn()?, link)?,
        vec![filed]
    );
    assert!(matches!(
        read.weave_link_corrections(WeaveReader::Person(person), link),
        Err(Error::EntityNotFound)
    ));
    Ok(())
}

#[test]
fn weave_exact_pair_admission_keeps_independent_link_to_same_target() -> Result<()> {
    use crate::edge::EdgeActorClass;
    use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let a = vault.ensure_embedded_owner_actor().unwrap();
    let b = entity(0xC7);
    vault.put_entity(
        &b,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"resident",
    )?;
    let am = vault.memory(a, EdgeActorClass::Human);
    let bm = vault.memory(b, EdgeActorClass::Human);
    let diary = |memory: &crate::memory::Memory<'_>, owner: EntityId| -> Result<EntityId> {
        let receipt = memory
            .author_note(&NoteWriteEnvelope {
                kind: NoteKind::Diary,
                scope: NoteScope::ActorPrivate { owner_ref: owner },
                markdown: "weave private notebook".into(),
                source_revision_ref: [0xC8; 16],
                mask: None,
            })
            .map_err(|error| crate::Error::InvalidConfig(error.to_string()))?;
        EntityId::from_hex(&receipt.id_hex)
    };
    let a1 = diary(&am, a)?;
    let a2 = diary(&am, a)?;
    let b_note = diary(&bm, b)?;
    am.link_diary_coreference(a1, b_note).unwrap();
    am.grant_diary_coreference(a1, b_note).unwrap();
    bm.grant_diary_coreference(a1, b_note).unwrap();
    am.link_diary_coreference(a2, b_note).unwrap(); // Empty relation
    vault
        .batch()
        .edge(&a2, EdgeKind::BlockedBy, &b_note, 1.0)
        .commit()?;
    crate::test_util::authorize_readers(&vault, &[&a.to_hex()]);
    let read =
        vault.scoped_read(ScopedReadActorKey::with_actor_class(a.to_hex(), "human").unwrap());
    let owner =
        vault.authenticate_owner(a, &a.to_hex(), true, crate::store::GateDecisionId::now())?;
    let mut recipe = [section(WeaveSectionKind::Links, &[])];
    recipe[0].edge_kinds = vec![EdgeKind::SameAs, EdgeKind::BlockedBy];
    let report = || {
        read.weave_report(WeaveReader::Owner(&owner), &recipe)
            .unwrap()
    };
    let links = &report().value.sections[0].items;
    let hidden = WeaveItem::Link {
        source: a2,
        kind: EdgeKind::SameAs,
        target: b_note,
    };
    let independent = WeaveItem::Link {
        source: a2,
        kind: EdgeKind::BlockedBy,
        target: b_note,
    };
    assert!(!links.contains(&hidden));
    assert!(links.contains(&independent));
    am.grant_diary_coreference(a2, b_note).unwrap();
    let b_grant = bm.grant_diary_coreference(a2, b_note).unwrap();
    assert!(report().value.sections[0].items.contains(&hidden));
    bm.revoke_diary_coreference_grant(b_grant).unwrap();
    let restored = &report().value.sections[0].items;
    assert!(!restored.contains(&hidden));
    assert!(restored.contains(&independent));
    Ok(())
}

fn replace_weave_policy(vault: &Vault, policy: Value) -> Result<()> {
    let invalid = || Error::InvalidConfig("default policy manifest".into());
    let id = crate::gate::default_policy_manifest_id()?;
    let txn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| invalid())?
    else {
        return Err(invalid());
    };
    drop(txn);
    entries
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some(crate::gate::weave_policy::KEY))
        .ok_or_else(invalid)?
        .1 = policy;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).map_err(|_| invalid())?;
    crate::test_util::put_policy_manifest_bytes(vault, id, &bytes)
}

#[test]
fn wrong_link_correction_follows_weave_report_policy() -> Result<()> {
    use crate::provenance::EdgeRef;
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let person = entity(0xb4);
    let peer = entity(0xb5);
    for id in [person, peer] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reader",
        )?;
    }
    vault.put_edge(&person, EdgeKind::Mentions, &peer, 0.5)?;
    crate::test_util::authorize_readers(&vault, &[&person.to_hex()]);
    let auth = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let read = vault.scoped_read(ScopedReadActorKey::new(person.to_hex()).unwrap());
    let link = EdgeRef::new(person, EdgeKind::Mentions, peer);
    let filed = read.report_wrong_link(&auth, WeaveReader::Person(person), link)?;
    assert_eq!(
        read.weave_link_corrections(WeaveReader::Person(person), link)?,
        vec![filed]
    );

    // The manifest's person row stops granting the links section: the
    // correction doors re-run the report under the same resolved policy.
    let Value::Array(mut roles) = crate::gate::weave_policy::default_value() else {
        panic!("policy array")
    };
    for role in &mut roles {
        let Value::Map(fields) = role else { continue };
        if fields
            .iter()
            .any(|(k, v)| k.as_str() == Some("role") && v.as_str() == Some("person"))
        {
            for (k, v) in fields.iter_mut() {
                if k.as_str() == Some("sections") {
                    *v = Value::Array(vec![Value::from("changes")]);
                }
            }
        }
    }
    replace_weave_policy(&vault, Value::Array(roles))?;

    assert!(matches!(
        read.weave_link_corrections(WeaveReader::Person(person), link),
        Err(Error::InvalidConfig(_))
    ));
    assert!(
        read.report_wrong_link(&auth, WeaveReader::Person(person), link)
            .is_err()
    );
    assert_eq!(
        vault.weave_link_correction_labels_in_txn(&vault.store.env.read_txn()?, link)?,
        vec![filed]
    );
    Ok(())
}
