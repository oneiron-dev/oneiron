//! FIX 1161: TASKS fits use measured person fit before completion count.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::context_board::{
    People, PeopleView, TaskBoardStatus, TaskIntentPresence, TasksSectionRows,
};
use oneiron::learning::{
    Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation, TypeRef,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill_reliability::SKILL_OUTCOME_AXIS;
use oneiron::task_type::{SeedTaskType, TaskTypeRef};
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault, VaultConfig};

#[test]
fn tasks_fits_rank_measured_fit_above_completion_count() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    let now = 10;
    let person_p = EntityId::now();
    let person_q = EntityId::now();
    for person in [person_p, person_q] {
        vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"person",
            )
            .expect("put roster person");
    }

    let tree = oneiron::task_type::type_tree(&vault, None).expect("vault type tree");
    let task_type = TaskTypeRef::seed(SeedTaskType::Build, tree.version());
    // Seed the same (subject=person, executor=person) cells as driven runs.
    // Equal own-run counts leave the estimate mean as the deciding factor.
    for (person, success) in [(person_p, false), (person_q, true)] {
        let cell = LearningCell::new(LearningPredicate::Reliability, person)
            .executor(person.to_hex())
            .type_ref(TypeRef::from(&task_type))
            .axis(SKILL_OUTCOME_AXIS)
            .project(None);
        for _ in 0..8 {
            let evidence = LearningEvidence::anchored(
                EntityId::now().to_hex(),
                now,
                Anchor::HeldOut,
                Observation::Success(success),
            );
            oneiron::learning::record_evidence(&vault, &cell, &evidence, now)
                .expect("project person run evidence")
                .expect("person cell has own runs");
        }
    }

    let people = People::load(&vault, now, &mut |person| {
        Ok(person == person_p || person == person_q)
    })
    .expect("load P and Q roster");
    let resident = BTreeSet::from([person_p, person_q]);
    let people_view = PeopleView::new(&people, &resident);
    let mut rows = TasksSectionRows {
        intents: Vec::new(),
        bare_jobs: Vec::new(),
        source_exhausted: true,
    };
    // P has two completed rows; Q has one. Main therefore ranks P first.
    for person in [person_p, person_p, person_q] {
        let mut done = TaskIntentPresence::new(
            EntityId::now().to_hex(),
            TaskBoardStatus::Done,
            None,
            false,
            Vec::new(),
        );
        done.who = Some(person);
        done.type_ref = Some(task_type.clone());
        rows.intents.push(done);
    }
    let open_task = EntityId::now();
    let mut open = TaskIntentPresence::new(
        open_task.to_hex(),
        TaskBoardStatus::Queued,
        None,
        false,
        Vec::new(),
    );
    open.type_ref = Some(task_type);
    rows.intents.push(open);
    rows.attach_people(&vault, &people_view, &[]);

    let open = rows
        .intents
        .iter()
        .find(|row| row.id == open_task.to_hex())
        .expect("open task row");
    assert_eq!(
        open.fits,
        vec![people_view.label(person_q), people_view.label(person_p)],
        "Q's successful driven runs must outrank P's larger completion count",
    );
}
