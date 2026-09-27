use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
};
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{TimeRange, Vault};
use rmpv::Value;

fn person(vault: &Vault, id: EntityId) -> Result<()> {
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"reader",
    )
}

fn recipe(kind: WeaveSectionKind) -> Vec<WeaveSectionSpec> {
    vec![WeaveSectionSpec {
        kind,
        predicates: vec!["report.digest".into()],
        edge_kinds: Vec::new(),
    }]
}

fn read_saved(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    reader: WeaveDigestReader,
    due: u64,
) -> Result<Option<StoredWeaveDigest>> {
    let id = match reader {
        WeaveDigestReader::Person(id)
        | WeaveDigestReader::Owner(id)
        | WeaveDigestReader::Agent(id) => id,
    };
    let scoped = vault.scoped_read(ScopedReadActorKey::new(id.to_hex()).unwrap());
    let role = match reader {
        WeaveDigestReader::Person(id) => WeaveReader::Person(id),
        WeaveDigestReader::Owner(_) => WeaveReader::Owner(owner),
        WeaveDigestReader::Agent(id) => WeaveReader::Agent(id),
    };
    scoped.read_weave_digest(role, due)
}

#[test]
fn due_rows_store_exact_live_lens_and_advance_each_reader_independently() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x31);
    let person_id = entity(0x32);
    let agent_id = entity(0x33);
    for id in [owner_id, person_id, agent_id] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    for (claim, reader) in [(entity(0x41), person_id), (entity(0x43), agent_id)] {
        vault.put_claim(
            &claim,
            &ClaimBody::new(
                "report.digest",
                ClaimSubject::Entity(reader),
                Value::from("live report"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )?;
    }
    crate::test_util::authorize_readers(
        &vault,
        &[&person_id.to_hex(), &agent_id.to_hex(), &owner_id.to_hex()],
    );
    let person_row = WeaveDigestSchedule {
        reader: WeaveDigestReader::Person(person_id),
        cadence: WeaveDigestCadence::Daily,
        next_due_at: 100,
        recipe: recipe(WeaveSectionKind::Changes),
    };
    let agent_row = WeaveDigestSchedule {
        reader: WeaveDigestReader::Agent(agent_id),
        cadence: WeaveDigestCadence::Weekly,
        next_due_at: 200,
        recipe: recipe(WeaveSectionKind::Digest),
    };
    vault.set_weave_digest_schedule(&owner, &person_row)?;
    vault.set_weave_digest_schedule(&owner, &agent_row)?;
    let person_read = vault.scoped_read(ScopedReadActorKey::new(person_id.to_hex()).unwrap());
    let agent_read = vault.scoped_read(ScopedReadActorKey::new(agent_id.to_hex()).unwrap());
    assert!(
        person_read
            .render_due_weave_digest(WeaveReader::Person(person_id), 99)?
            .is_none()
    );
    assert!(read_saved(&vault, &owner, person_row.reader, 100)?.is_none());
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, person_row.reader)?
            .unwrap()
            .next_due_at,
        100
    );
    let live = person_read.weave_report(WeaveReader::Person(person_id), &person_row.recipe)?;
    let rendered = person_read
        .render_due_weave_digest(WeaveReader::Person(person_id), 100)?
        .unwrap();
    assert_eq!(rendered.report, live);
    assert_eq!(
        rendered,
        read_saved(&vault, &owner, person_row.reader, 100)?.unwrap()
    );
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, person_row.reader)?
            .unwrap()
            .next_due_at,
        86_500
    );
    assert!(
        person_read
            .render_due_weave_digest(WeaveReader::Person(person_id), 100)?
            .is_none()
    );
    assert!(
        agent_read
            .render_due_weave_digest(WeaveReader::Agent(agent_id), 199)?
            .is_none()
    );
    let agent_live = agent_read.weave_report(WeaveReader::Agent(agent_id), &agent_row.recipe)?;
    let agent_render = agent_read
        .render_due_weave_digest(WeaveReader::Agent(agent_id), 200)?
        .unwrap();
    assert_eq!(agent_render.report, agent_live);
    assert_eq!(
        agent_render,
        read_saved(&vault, &owner, agent_row.reader, 200)?.unwrap()
    );
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, agent_row.reader)?
            .unwrap()
            .next_due_at,
        605_000
    );
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, person_row.reader)?
            .unwrap()
            .next_due_at,
        86_500
    );
    // A late host wake catches up by whole periods; it never backfills stale digests.
    let late = person_read
        .render_due_weave_digest(WeaveReader::Person(person_id), 200_000)?
        .unwrap();
    assert_eq!(late.scheduled_for, 86_500);
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, person_row.reader)?
            .unwrap()
            .next_due_at,
        259_300
    );
    Ok(())
}

#[test]
fn schedule_refuses_cross_role_recipes_and_cross_reader_render() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x51);
    let agent = entity(0x52);
    person(&vault, owner_id)?;
    person(&vault, agent)?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let bad = WeaveDigestSchedule {
        reader: WeaveDigestReader::Agent(agent),
        cadence: WeaveDigestCadence::Daily,
        next_due_at: 1,
        recipe: recipe(WeaveSectionKind::Budgets),
    };
    assert!(vault.set_weave_digest_schedule(&owner, &bad).is_err());
    assert!(vault.weave_digest_schedule(&owner, bad.reader)?.is_none());
    let good = WeaveDigestSchedule {
        recipe: recipe(WeaveSectionKind::Digest),
        ..bad
    };
    vault.set_weave_digest_schedule(&owner, &good)?;
    let impostor = vault.scoped_read(ScopedReadActorKey::new(owner_id.to_hex()).unwrap());
    assert!(
        impostor
            .render_due_weave_digest(WeaveReader::Agent(agent), 1)
            .is_err()
    );
    assert!(read_saved(&vault, &owner, good.reader, 1)?.is_none());
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, good.reader)?
            .unwrap()
            .next_due_at,
        1
    );
    let wrong_owner = WeaveDigestSchedule {
        reader: WeaveDigestReader::Owner(agent),
        cadence: WeaveDigestCadence::Weekly,
        next_due_at: 2,
        recipe: recipe(WeaveSectionKind::SieveScore),
    };
    assert!(
        vault
            .set_weave_digest_schedule(&owner, &wrong_owner)
            .is_err()
    );
    let owner_row = WeaveDigestSchedule {
        reader: WeaveDigestReader::Owner(owner_id),
        ..wrong_owner
    };
    crate::test_util::authorize_readers(&vault, &[&owner_id.to_hex()]);
    vault.set_weave_digest_schedule(&owner, &owner_row)?;
    assert!(
        impostor
            .render_due_weave_digest(WeaveReader::Owner(&owner), 1)?
            .is_none()
    );
    let live = impostor.weave_report(WeaveReader::Owner(&owner), &owner_row.recipe)?;
    let stored = impostor
        .render_due_weave_digest(WeaveReader::Owner(&owner), 2)?
        .unwrap();
    assert_eq!(stored.report, live);
    assert_eq!(
        stored,
        read_saved(&vault, &owner, owner_row.reader, 2)?.unwrap()
    );
    Ok(())
}

#[test]
fn hard_delete_scrubs_copied_digest_bytes_and_saved_read_refuses_erased_source() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x61);
    let person_id = entity(0x62);
    let other_id = entity(0x63);
    for id in [owner_id, person_id, other_id] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let erased = entity(0x64);
    let intact = entity(0x65);
    for (id, subject) in [(erased, person_id), (intact, other_id)] {
        vault.put_claim(
            &id,
            &ClaimBody::new(
                "report.digest",
                ClaimSubject::Entity(subject),
                Value::from("copied body"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )?;
    }
    crate::test_util::authorize_readers(&vault, &[&person_id.to_hex(), &other_id.to_hex()]);
    for subject in [person_id, other_id] {
        let reader = WeaveDigestReader::Person(subject);
        vault.set_weave_digest_schedule(
            &owner,
            &WeaveDigestSchedule {
                reader,
                cadence: WeaveDigestCadence::Daily,
                next_due_at: 1,
                recipe: recipe(WeaveSectionKind::Changes),
            },
        )?;
        vault
            .scoped_read(ScopedReadActorKey::new(subject.to_hex()).unwrap())
            .render_due_weave_digest(WeaveReader::Person(subject), 1)?
            .unwrap();
    }
    let digest_key = [
        WeaveDigestReader::Person(person_id).key(DIGEST_PREFIX),
        1u64.to_be_bytes().to_vec(),
    ]
    .concat();
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &digest_key)?
            .is_some()
    );
    assert!(vault.delete_entity(&erased)?);
    assert!(read_saved(&vault, &owner, WeaveDigestReader::Person(person_id), 1)?.is_none());
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &digest_key)?
            .is_none()
    );
    assert!(read_saved(&vault, &owner, WeaveDigestReader::Person(other_id), 1)?.is_some());
    Ok(())
}

#[test]
fn deletion_between_projection_and_commit_cannot_republish_erased_body() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x71);
    let person_id = entity(0x72);
    person(&vault, owner_id)?;
    person(&vault, person_id)?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let erased = entity(0x73);
    vault.put_claim(
        &erased,
        &ClaimBody::new(
            "report.digest",
            ClaimSubject::Entity(person_id),
            Value::from("never republish"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        ),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    crate::test_util::authorize_readers(&vault, &[&person_id.to_hex()]);
    let reader = WeaveDigestReader::Person(person_id);
    vault.set_weave_digest_schedule(
        &owner,
        &WeaveDigestSchedule {
            reader,
            cadence: WeaveDigestCadence::Daily,
            next_due_at: 2,
            recipe: recipe(WeaveSectionKind::Changes),
        },
    )?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new(person_id.to_hex()).unwrap());
    let result = scoped.render_due_weave_digest_with(WeaveReader::Person(person_id), 2, || {
        vault.delete_entity(&erased)?;
        Ok(())
    })?;
    assert!(result.is_none());
    assert!(read_saved(&vault, &owner, reader, 2)?.is_none());
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, reader)?
            .unwrap()
            .next_due_at,
        2
    );
    assert!(
        scoped
            .render_due_weave_digest(WeaveReader::Person(person_id), 2)?
            .is_some()
    );
    Ok(())
}

#[test]
fn owner_inactivation_between_projection_and_commit_preserves_due_row() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0x81);
    person(&vault, owner_id)?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let reader = WeaveDigestReader::Owner(owner_id);
    vault.set_weave_digest_schedule(
        &owner,
        &WeaveDigestSchedule {
            reader,
            cadence: WeaveDigestCadence::Weekly,
            next_due_at: 3,
            recipe: recipe(WeaveSectionKind::SieveScore),
        },
    )?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new(owner_id.to_hex()).unwrap());
    let before = vault
        .store
        .vault_meta
        .get(&vault.store.env.read_txn()?, &reader.key(SCHEDULE_PREFIX))?
        .unwrap()
        .to_vec();
    assert!(
        scoped
            .render_due_weave_digest_with(WeaveReader::Owner(&owner), 3, || {
                // Mutate only the fixture's owner row to force the exact
                // projection-to-commit inactivation point, independent of
                // the public delete door's owner-protection semantics.
                vault.with_write_txn(|txn| {
                    vault.store.entities.delete(txn, owner_id.as_bytes())?;
                    Ok(())
                })
            })
            .is_err()
    );
    assert_eq!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &reader.key(SCHEDULE_PREFIX))?
            .unwrap(),
        before
    );
    let digest_key = [reader.key(DIGEST_PREFIX), 3u64.to_be_bytes().to_vec()].concat();
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &digest_key)?
            .is_none()
    );
    Ok(())
}

#[test]
fn erased_upstream_source_scrubs_derived_claim_digest_even_after_regeneration() -> Result<()> {
    use crate::ports::{DependencyIndex, EntityRecord, SourceSpan};
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0xA8);
    let reader_id = entity(0xA9);
    let document = entity(0xAA);
    let replacement = entity(0xAB);
    for id in [owner_id, reader_id, document, replacement] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let claim_id = entity(0xAC);
    let claim = |value| {
        ClaimBody::new(
            "report.digest",
            ClaimSubject::Entity(reader_id),
            Value::from(value),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
    };
    vault.put_claim(
        &claim_id,
        &claim("derived from erased document"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    vault.with_write_txn(|txn| {
        vault.port_dependency_put(
            txn,
            SourceSpan {
                document,
                frontier: 1,
            },
            &claim_id,
        )
    })?;
    crate::test_util::authorize_readers(&vault, &[&reader_id.to_hex()]);
    let reader = WeaveDigestReader::Person(reader_id);
    vault.set_weave_digest_schedule(
        &owner,
        &WeaveDigestSchedule {
            reader,
            cadence: WeaveDigestCadence::Daily,
            next_due_at: 1,
            recipe: recipe(WeaveSectionKind::Changes),
        },
    )?;
    vault
        .scoped_read(ScopedReadActorKey::new(reader_id.to_hex()).unwrap())
        .render_due_weave_digest(WeaveReader::Person(reader_id), 1)?
        .unwrap();
    let digest_key = [reader.key(DIGEST_PREFIX), 1u64.to_be_bytes().to_vec()].concat();
    assert!(read_saved(&vault, &owner, reader, 1)?.is_some());
    assert!(vault.delete_entity(&document)?);
    assert!(read_saved(&vault, &owner, reader, 1)?.is_none());
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &digest_key)?
            .is_none()
    );
    // A new, independently sourced version may clear staleness. The old
    // digest must not spring back when that bit disappears.
    vault.with_write_txn(|txn| {
        let replacement_row = EntityRecord {
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred: TimeRange { start: 2, end: 2 },
            learned_at: 2,
            body: encode_claim_body(&claim("new source"))?,
        };
        // The record is a regeneration fixture. The production regeneration
        // completion below is the guard under test, not Gate write admission.
        vault
            .store
            .entities
            .put(txn, claim_id.as_bytes(), &replacement_row.encode())?;
        assert!(vault.port_dependency_complete_regeneration(
            txn,
            &claim_id,
            2,
            &[SourceSpan {
                document: replacement,
                frontier: 1
            }]
        )?);
        Ok(())
    })?;
    assert!(read_saved(&vault, &owner, reader, 1)?.is_none());
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &digest_key)?
            .is_none()
    );
    Ok(())
}

fn configure_weave_policy(
    vault: &Vault,
    change: impl FnOnce(&mut Vec<(Value, Value)>),
) -> Result<()> {
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
    change(&mut entries);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).map_err(|_| invalid())?;
    crate::test_util::put_policy_manifest_bytes(vault, id, &bytes)
}

#[test]
fn configurable_manifest_sections_and_ceilings_narrow_per_holder_without_expanding_read_grant()
-> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0xB8);
    let agent = entity(0xB9);
    let other = entity(0xBA);
    for id in [owner_id, agent, other] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex(), &other.to_hex()]);
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let mut project =
        crate::workspace_roster::ProjectRecord::new(entity(0xBD), Some(root), root, leader);
    project.roster.push(agent.to_hex());
    vault.put_project(entity(0xBD), &project, 2)?;
    let row = WeaveDigestSchedule {
        reader: WeaveDigestReader::Agent(agent),
        cadence: WeaveDigestCadence::Daily,
        next_due_at: 1,
        recipe: recipe(WeaveSectionKind::Projects),
    };
    assert!(vault.set_weave_digest_schedule(&owner, &row).is_err());
    configure_weave_policy(&vault, |entries| {
        let value = entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(crate::gate::weave_policy::KEY))
            .unwrap();
        let Value::Array(roles) = &mut value.1 else {
            panic!("policy array")
        };
        let Value::Map(agent_row) = roles
            .iter_mut()
            .find_map(|v| match v {
                Value::Map(fields)
                    if fields.iter().any(|(k, v)| {
                        k.as_str() == Some("role") && v.as_str() == Some("agent")
                    }) =>
                {
                    Some(v)
                }
                _ => None,
            })
            .unwrap()
        else {
            panic!("agent policy")
        };
        agent_row
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("sections"))
            .unwrap()
            .1 = Value::Array(vec![Value::from("digest"), Value::from("projects")]);
        agent_row
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("max_sections"))
            .unwrap()
            .1 = Value::from(20);
        roles.push(Value::Map(vec![
            (Value::from("role"), Value::from("agent")),
            (Value::from("holder_ref"), Value::from(agent.to_hex())),
            (
                Value::from("sections"),
                Value::Array(vec![Value::from("projects")]),
            ),
            (Value::from("max_sections"), Value::from(19)),
            (Value::from("max_predicates"), Value::from(32)),
            (Value::from("max_edge_kinds"), Value::from(32)),
            (Value::from("max_rows"), Value::from(10_000)),
        ]));
    })?;
    vault.set_weave_digest_schedule(&owner, &row)?;
    let read = vault.scoped_read(ScopedReadActorKey::new(agent.to_hex()).unwrap());
    assert!(
        read.weave_report(WeaveReader::Agent(agent), &row.recipe)
            .is_ok()
    );
    assert!(
        read.weave_report(WeaveReader::Agent(agent), &recipe(WeaveSectionKind::Digest))
            .is_err()
    );
    let other_read = vault.scoped_read(ScopedReadActorKey::new(other.to_hex()).unwrap());
    assert!(
        other_read
            .weave_report(WeaveReader::Agent(other), &recipe(WeaveSectionKind::Digest))
            .is_ok()
    );
    assert!(
        other_read
            .weave_report(WeaveReader::Agent(other), &row.recipe)
            .is_ok()
    );
    let more = vec![recipe(WeaveSectionKind::Projects)[0].clone(); 20];
    assert!(read.weave_report(WeaveReader::Agent(agent), &more).is_err());
    assert!(
        other_read
            .weave_report(WeaveReader::Agent(other), &more)
            .is_ok()
    );
    assert!(
        !read
            .weave_report(WeaveReader::Agent(agent), &row.recipe)?
            .value
            .sections[0]
            .items
            .is_empty()
    );
    // The policy label cannot grant read authority: revoke the actual read grant.
    configure_weave_policy(&vault, |entries| {
        entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("scoped_grants"))
            .unwrap()
            .1 = Value::Array(vec![]);
    })?;
    let after = read.weave_report(WeaveReader::Agent(agent), &row.recipe)?;
    assert!(after.value.sections[0].items.is_empty());
    Ok(())
}

#[test]
fn policy_narrowing_between_projection_and_commit_leaves_schedule_due() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0xBB);
    let agent = entity(0xBC);
    for id in [owner_id, agent] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex()]);
    let reader = WeaveDigestReader::Agent(agent);
    let row = WeaveDigestSchedule {
        reader,
        cadence: WeaveDigestCadence::Weekly,
        next_due_at: 1,
        recipe: recipe(WeaveSectionKind::Digest),
    };
    vault.set_weave_digest_schedule(&owner, &row)?;
    let read = vault.scoped_read(ScopedReadActorKey::new(agent.to_hex()).unwrap());
    assert!(
        read.render_due_weave_digest_with(WeaveReader::Agent(agent), 1, || {
            configure_weave_policy(&vault, |entries| {
                let value = entries
                    .iter_mut()
                    .find(|(k, _)| k.as_str() == Some(crate::gate::weave_policy::KEY))
                    .unwrap();
                let Value::Array(roles) = &mut value.1 else {
                    panic!("policy array")
                };
                let Value::Map(fields) = roles
                    .iter_mut()
                    .find_map(|v| match v {
                        Value::Map(fields)
                            if fields.iter().any(|(k, v)| {
                                k.as_str() == Some("role") && v.as_str() == Some("agent")
                            }) =>
                        {
                            Some(v)
                        }
                        _ => None,
                    })
                    .unwrap()
                else {
                    panic!("agent row")
                };
                fields
                    .iter_mut()
                    .find(|(k, _)| k.as_str() == Some("sections"))
                    .unwrap()
                    .1 = Value::Array(vec![]);
            })
        })
        .is_err()
    );
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, reader)?
            .unwrap()
            .next_due_at,
        1
    );
    assert!(read_saved(&vault, &owner, reader, 1)?.is_none());
    Ok(())
}

#[test]
fn non_claim_rows_and_edge_endpoints_are_rechecked_at_publication() -> Result<()> {
    use crate::workspace_roster::ProjectRecord;
    for case in 0..4 {
        let (_tmp, vault) = open_test_vault_with(embedding_test_config());
        let owner_id = entity(0xC1);
        let person_id = entity(0xC2);
        let peer = entity(0xC3);
        for id in [owner_id, person_id, peer] {
            person(&vault, id)?;
        }
        let owner = vault.authenticate_owner(
            owner_id,
            &owner_id.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let project = entity(0xC4);
        let root = vault.root_project()?;
        let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
        let mut record = ProjectRecord::new(project, Some(root), root, leader);
        record.roster.push(person_id.to_hex());
        record.budget = Some(peer.to_hex());
        record.goal = Some(peer.to_hex());
        vault.put_project(project, &record, 2)?;
        vault.put_edge(&person_id, EdgeKind::Mentions, &peer, 0.1)?;
        let link_claim = entity(0xC5);
        vault.put_claim(
            &link_claim,
            &ClaimBody::new(
                "report.link",
                ClaimSubject::Edge {
                    source: person_id,
                    kind: EdgeKind::Mentions,
                    target: peer,
                },
                Value::from("edge claim"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )?;
        crate::test_util::authorize_readers(&vault, &[&owner_id.to_hex(), &person_id.to_hex()]);
        let kind = match case {
            0 => WeaveSectionKind::Links,
            1 => WeaveSectionKind::Projects,
            2 => WeaveSectionKind::Budgets,
            _ => WeaveSectionKind::Links,
        };
        let owner_reader = case == 2;
        let target = if owner_reader { owner_id } else { person_id };
        let reader = if owner_reader {
            WeaveDigestReader::Owner(owner_id)
        } else {
            WeaveDigestReader::Person(person_id)
        };
        let mut spec = recipe(kind);
        spec[0].predicates = if case == 3 {
            vec!["report.link".into()]
        } else {
            Vec::new()
        };
        if case == 0 {
            spec[0].edge_kinds = vec![EdgeKind::Mentions];
        }
        vault.set_weave_digest_schedule(
            &owner,
            &WeaveDigestSchedule {
                reader,
                cadence: WeaveDigestCadence::Daily,
                next_due_at: 1,
                recipe: spec.clone(),
            },
        )?;
        let scoped = vault.scoped_read(ScopedReadActorKey::new(target.to_hex()).unwrap());
        let before = if owner_reader {
            scoped.weave_report(WeaveReader::Owner(&owner), &spec)?
        } else {
            scoped.weave_report(WeaveReader::Person(person_id), &spec)?
        };
        assert!(!before.value.sections[0].items.is_empty(), "fixture {case}");
        let revoke = || {
            crate::test_util::authorize_readers(&vault, &[]);
            Ok(())
        };
        let result = if owner_reader {
            scoped.render_due_weave_digest_with(WeaveReader::Owner(&owner), 1, revoke)
        } else {
            scoped.render_due_weave_digest_with(WeaveReader::Person(person_id), 1, revoke)
        };
        assert!(result.is_err() || result?.is_none(), "revoked case {case}");
        assert_eq!(
            vault
                .weave_digest_schedule(&owner, reader)?
                .unwrap()
                .next_due_at,
            1
        );
        assert!(read_saved(&vault, &owner, reader, 1)?.is_none());
    }
    Ok(())
}

#[test]
fn saved_digest_is_reader_bound_and_revocation_hides_every_saved_byte() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0xD4);
    let person_id = entity(0xD5);
    for id in [owner_id, person_id] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let claim_id = entity(0xD6);
    vault.put_claim(
        &claim_id,
        &ClaimBody::new(
            "report.digest",
            ClaimSubject::Entity(person_id),
            Value::from("private digest"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        ),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    // Deliberately grant the subject only; active-owner authentication is not a read grant.
    crate::test_util::authorize_readers(&vault, &[&person_id.to_hex()]);
    let reader = WeaveDigestReader::Person(person_id);
    vault.set_weave_digest_schedule(
        &owner,
        &WeaveDigestSchedule {
            reader,
            cadence: WeaveDigestCadence::Daily,
            next_due_at: 1,
            recipe: recipe(WeaveSectionKind::Changes),
        },
    )?;
    let person_read = vault.scoped_read(ScopedReadActorKey::new(person_id.to_hex()).unwrap());
    person_read
        .render_due_weave_digest(WeaveReader::Person(person_id), 1)?
        .unwrap();
    assert!(read_saved(&vault, &owner, reader, 1)?.is_some());
    let owner_read = vault.scoped_read(ScopedReadActorKey::new(owner_id.to_hex()).unwrap());
    assert!(
        owner_read
            .read_weave_digest(WeaveReader::Person(person_id), 1)
            .is_err()
    );
    crate::test_util::authorize_readers(&vault, &[]);
    assert!(read_saved(&vault, &owner, reader, 1)?.is_none());
    // The row still exists, but the public door reveals no body or item count.
    let key = [reader.key(DIGEST_PREFIX), 1u64.to_be_bytes().to_vec()].concat();
    assert!(
        vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, &key)?
            .is_some()
    );
    Ok(())
}

#[test]
fn saved_private_claim_cannot_be_authorized_by_a_new_public_revision() -> Result<()> {
    use crate::ports::EntityRecord;
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0xD8);
    let person_id = entity(0xD9);
    let world = entity(0xDA);
    for id in [owner_id, person_id] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let claim_id = entity(0xDB);
    let mut old = ClaimBody::new(
        "report.digest",
        ClaimSubject::Entity(person_id),
        Value::from("old private"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    old.world = Some(world);
    vault.put_claim(&claim_id, &old, TimeRange { start: 1, end: 1 }, 1)?;
    crate::test_util::authorize_readers(&vault, &[&person_id.to_hex()]);
    let reader = WeaveDigestReader::Person(person_id);
    vault.set_weave_digest_schedule(
        &owner,
        &WeaveDigestSchedule {
            reader,
            cadence: WeaveDigestCadence::Weekly,
            next_due_at: 1,
            recipe: recipe(WeaveSectionKind::Changes),
        },
    )?;
    let read = vault.scoped_read(ScopedReadActorKey::new(person_id.to_hex()).unwrap());
    read.render_due_weave_digest(WeaveReader::Person(person_id), 1)?
        .unwrap();
    assert!(read_saved(&vault, &owner, reader, 1)?.is_some());
    let public = ClaimBody::new(
        "report.digest",
        ClaimSubject::Entity(person_id),
        Value::from("new public"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.with_write_txn(|txn| {
        let record = EntityRecord {
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred: TimeRange { start: 2, end: 2 },
            learned_at: 2,
            body: encode_claim_body(&public)?,
        };
        // Controlled revision change in the fixture: scope checks must not
        // substitute its public bytes for the saved private body.
        vault
            .store
            .entities
            .put(txn, claim_id.as_bytes(), &record.encode())?;
        Ok(())
    })?;
    assert!(read_saved(&vault, &owner, reader, 1)?.is_none());
    Ok(())
}

#[test]
fn explicit_empty_policy_denies_schedule_live_and_saved_report() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0xDC);
    let person_id = entity(0xDD);
    for id in [owner_id, person_id] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    crate::test_util::authorize_readers(&vault, &[&person_id.to_hex()]);
    let reader = WeaveDigestReader::Person(person_id);
    let row = WeaveDigestSchedule {
        reader,
        cadence: WeaveDigestCadence::Daily,
        next_due_at: 1,
        recipe: recipe(WeaveSectionKind::Changes),
    };
    vault.set_weave_digest_schedule(&owner, &row)?;
    let read = vault.scoped_read(ScopedReadActorKey::new(person_id.to_hex()).unwrap());
    read.render_due_weave_digest(WeaveReader::Person(person_id), 1)?
        .unwrap();
    vault.set_weave_digest_schedule(&owner, &row)?; // same period becomes due again
    configure_weave_policy(&vault, |entries| {
        entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(crate::gate::weave_policy::KEY))
            .unwrap()
            .1 = Value::Array(vec![]);
    })?;
    assert!(vault.set_weave_digest_schedule(&owner, &row).is_err());
    assert!(
        read.weave_report(WeaveReader::Person(person_id), &row.recipe)
            .is_err()
    );
    assert!(
        read.render_due_weave_digest(WeaveReader::Person(person_id), 1)
            .is_err()
    );
    assert!(read_saved(&vault, &owner, reader, 1)?.is_none());
    assert_eq!(
        vault
            .weave_digest_schedule(&owner, reader)?
            .unwrap()
            .next_due_at,
        1
    );
    Ok(())
}

#[test]
fn authored_policy_can_exceed_old_compiled_scan_and_section_limits() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0xDE);
    let agent = entity(0xDF);
    for id in [owner_id, agent] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex()]);
    configure_weave_policy(&vault, |entries| {
        let Value::Array(rows) = &mut entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(crate::gate::weave_policy::KEY))
            .unwrap()
            .1
        else {
            panic!("policy rows")
        };
        let Value::Map(fields) = rows
            .iter_mut()
            .find_map(|row| match row {
                Value::Map(fields)
                    if fields.iter().any(|(k, v)| {
                        k.as_str() == Some("role") && v.as_str() == Some("agent")
                    }) =>
                {
                    Some(row)
                }
                _ => None,
            })
            .unwrap()
        else {
            panic!("role")
        };
        fields
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("max_sections"))
            .unwrap()
            .1 = Value::from(65);
        fields
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some("max_rows"))
            .unwrap()
            .1 = Value::from(10_001);
    })?;
    let recipe = vec![recipe(WeaveSectionKind::Digest)[0].clone(); 65];
    let row = WeaveDigestSchedule {
        reader: WeaveDigestReader::Agent(agent),
        cadence: WeaveDigestCadence::Daily,
        next_due_at: 1,
        recipe: recipe.clone(),
    };
    vault.set_weave_digest_schedule(&owner, &row)?;
    assert_eq!(
        vault
            .scoped_read(ScopedReadActorKey::new(agent.to_hex()).unwrap())
            .weave_report(WeaveReader::Agent(agent), &recipe)?
            .value
            .sections
            .len(),
        65
    );
    Ok(())
}

#[test]
fn authored_holder_required_precedence_is_enforced_without_widening_vault_role() -> Result<()> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let owner_id = entity(0xE3);
    let agent = entity(0xE4);
    for id in [owner_id, agent] {
        person(&vault, id)?;
    }
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex()]);
    let row = WeaveDigestSchedule {
        reader: WeaveDigestReader::Agent(agent),
        cadence: WeaveDigestCadence::Daily,
        next_due_at: 1,
        recipe: recipe(WeaveSectionKind::Digest),
    };
    vault.set_weave_digest_schedule(&owner, &row)?;
    configure_weave_policy(&vault, |entries| {
        entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(crate::gate::weave_policy::PRECEDENCE_KEY))
            .unwrap()
            .1 = Value::from("holder_required");
    })?;
    let read = vault.scoped_read(ScopedReadActorKey::new(agent.to_hex()).unwrap());
    assert!(vault.set_weave_digest_schedule(&owner, &row).is_err());
    assert!(
        read.weave_report(WeaveReader::Agent(agent), &row.recipe)
            .is_err()
    );
    configure_weave_policy(&vault, |entries| {
        let Value::Array(rows) = &mut entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(crate::gate::weave_policy::KEY))
            .unwrap()
            .1
        else {
            panic!("rows")
        };
        rows.push(Value::Map(vec![
            (Value::from("role"), Value::from("agent")),
            (Value::from("holder_ref"), Value::from(agent.to_hex())),
            (
                Value::from("sections"),
                Value::Array(vec![Value::from("digest"), Value::from("projects")]),
            ),
            (Value::from("max_sections"), Value::from(20)),
            (Value::from("max_predicates"), Value::from(40)),
            (Value::from("max_edge_kinds"), Value::from(40)),
            (Value::from("max_rows"), Value::from(10_001)),
        ]));
    })?;
    vault.set_weave_digest_schedule(&owner, &row)?;
    assert!(
        read.weave_report(WeaveReader::Agent(agent), &row.recipe)
            .is_ok()
    );
    assert!(
        read.weave_report(
            WeaveReader::Agent(agent),
            &recipe(WeaveSectionKind::Projects)
        )
        .is_err()
    );
    Ok(())
}
