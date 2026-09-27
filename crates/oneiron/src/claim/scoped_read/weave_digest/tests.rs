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
    assert!(
        vault
            .read_weave_digest(&owner, person_row.reader, 100)?
            .is_none()
    );
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
        vault
            .read_weave_digest(&owner, person_row.reader, 100)?
            .unwrap()
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
        vault
            .read_weave_digest(&owner, agent_row.reader, 200)?
            .unwrap()
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
    assert!(vault.read_weave_digest(&owner, good.reader, 1)?.is_none());
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
        vault
            .read_weave_digest(&owner, owner_row.reader, 2)?
            .unwrap()
    );
    Ok(())
}
