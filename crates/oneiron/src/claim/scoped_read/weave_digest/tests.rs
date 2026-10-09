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
            )
            .unwrap(),
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
        )
        .unwrap(),
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
        .unwrap()
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
        let mut record = ProjectRecord::new(project, Some(root), root, leader).unwrap();
        record.roster.push(person_id.to_hex());
        record.budget = Some(peer.to_hex());
        // No goal pointer: only the goal-intake interview may set one.
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
            )
            .unwrap(),
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
        )
        .unwrap(),
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
    )
    .unwrap();
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
    )
    .unwrap();
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
fn saved_edge_claim_is_withheld_after_exact_pair_revocation_with_readable_endpoints() -> Result<()>
{
    use crate::edge::EdgeActorClass;
    use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let a = vault.ensure_embedded_owner_actor().unwrap();
    let b = entity(0xE9);
    person(&vault, b)?;
    let am = vault.memory(a, EdgeActorClass::Human);
    let bm = vault.memory(b, EdgeActorClass::Human);
    let diary = |memory: &crate::memory::Memory<'_>, owner: EntityId| -> Result<EntityId> {
        let receipt = memory
            .author_note(&NoteWriteEnvelope {
                kind: NoteKind::Diary,
                scope: NoteScope::ActorPrivate { owner_ref: owner },
                markdown: "weave digest notebook".into(),
                source_revision_ref: [0xE2; 16],
                mask: None,
            })
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        EntityId::from_hex(&receipt.id_hex)
    };
    let a1 = diary(&am, a)?;
    let a2 = diary(&am, a)?;
    let b_note = diary(&bm, b)?;
    // a1's pair stays authorized, so b_note stays readable after a2's pair is revoked.
    am.link_diary_coreference(a1, b_note).unwrap();
    am.grant_diary_coreference(a1, b_note).unwrap();
    bm.grant_diary_coreference(a1, b_note).unwrap();
    am.link_diary_coreference(a2, b_note).unwrap();
    am.grant_diary_coreference(a2, b_note).unwrap();
    let b_grant = bm.grant_diary_coreference(a2, b_note).unwrap();
    let claim_id = entity(0xEA);
    vault.put_claim(
        &claim_id,
        &ClaimBody::new(
            "report.digest",
            ClaimSubject::Edge {
                source: a2,
                kind: EdgeKind::SameAs,
                target: b_note,
            },
            Value::from("pair digest"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap(),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    crate::test_util::authorize_readers(&vault, &[&a.to_hex()]);
    let owner =
        vault.authenticate_owner(a, &a.to_hex(), true, crate::store::GateDecisionId::now())?;
    let read =
        vault.scoped_read(ScopedReadActorKey::with_actor_class(a.to_hex(), "human").unwrap());
    // A predicate-only Links section: no edge_kinds, so only claim admission applies.
    let recipe = recipe(WeaveSectionKind::Links);
    vault.set_weave_digest_schedule(
        &owner,
        &WeaveDigestSchedule {
            reader: WeaveDigestReader::Owner(a),
            cadence: WeaveDigestCadence::Daily,
            next_due_at: 1,
            recipe: recipe.clone(),
        },
    )?;
    let stored = read
        .render_due_weave_digest(WeaveReader::Owner(&owner), 1)?
        .unwrap();
    let has_claim = |items: &[WeaveItem]| {
        items
            .iter()
            .any(|item| matches!(item, WeaveItem::Claim { id, .. } if *id == claim_id))
    };
    assert!(has_claim(&stored.report.value.sections[0].items));
    let saved = read
        .read_weave_digest(WeaveReader::Owner(&owner), 1)?
        .unwrap();
    assert!(has_claim(&saved.report.value.sections[0].items));

    bm.revoke_diary_coreference_grant(b_grant).unwrap();
    let mut links = recipe;
    links[0].edge_kinds = vec![EdgeKind::SameAs];
    let live = read.weave_report(WeaveReader::Owner(&owner), &links)?;
    let items = &live.value.sections[0].items;
    // Both endpoints stay readable: a2 by ownership, b_note through a1's pair.
    assert!(items.contains(&WeaveItem::Link {
        source: a1,
        kind: EdgeKind::SameAs,
        target: b_note,
    }));
    assert!(!items.contains(&WeaveItem::Link {
        source: a2,
        kind: EdgeKind::SameAs,
        target: b_note,
    }));
    assert!(!has_claim(items));
    // The saved digest yields no body, pair IDs or item count for the revoked pair.
    assert!(
        read.read_weave_digest(WeaveReader::Owner(&owner), 1)?
            .is_none()
    );
    Ok(())
}
