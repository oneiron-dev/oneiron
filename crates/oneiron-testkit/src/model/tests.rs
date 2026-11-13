use crate::model::generator::{Step, sequence};
use crate::model::*;

fn vault() -> VaultModel {
    VaultModel::new(&Universe::default())
}
fn question(subject: u8, aud: u8) -> Question {
    Question {
        subject: Ent(subject),
        predicate: QKey(0),
        audience: Aud(aud),
    }
}
fn applied(result: Outcome) {
    assert_eq!(result, Outcome::Applied);
}
fn write(model: &mut VaultModel, id: u32, subject: u8, aud: u8) {
    applied(model.owner_write(ClaimKey(id), Ent(subject), QKey(0), id, Aud(aud)));
}
fn settled() -> VaultModel {
    let mut model = vault();
    write(&mut model, 1, 0, 1);
    applied(model.agent_propose(0, ClaimKey(2), Ent(0), QKey(0), 2, Aud(1)));
    assert_eq!(model.standing_heads(question(0, 1)), vec![ClaimKey(1)]);
    assert_eq!(model.visible_to(Actor::Owner), vec![ClaimKey(1)]);
    applied(model.owner_approve(ClaimKey(2)));
    model
}
fn merged() -> VaultModel {
    let mut model = vault();
    write(&mut model, 1, 0, 1); // own
    write(&mut model, 2, 1, 1); // inherited
    applied(model.merge(&[Ent(1)], Ent(0)));
    assert_eq!(model.claims()[&ClaimKey(2)].subject, Ent(1));
    assert_eq!(model.claims_held_by(Ent(0)), vec![ClaimKey(1), ClaimKey(2)]);
    assert_eq!(model.claims_held_by(Ent(1)), vec![ClaimKey(2)]);
    assert_eq!(model.remaining_on(Ent(0)), vec![ClaimKey(1), ClaimKey(2)]);
    model
}
fn split_variant(assign_inherited: bool) -> VaultModel {
    let mut model = merged();
    let mut assignments = vec![(ClaimKey(1), Ent(2))];
    if assign_inherited {
        assignments.push((ClaimKey(2), Ent(3)));
    }
    applied(model.split(Ent(0), &[Ent(2), Ent(3)], &assignments));
    model
}
#[test]
fn memory_01_approval_closes_the_former_head() {
    let model = settled();
    assert_eq!(model.standing_heads(question(0, 1)), vec![ClaimKey(2)]);
    assert_eq!(model.status(ClaimKey(1)), Some(Status::Superseded));
    assert_eq!(model.status(ClaimKey(2)), Some(Status::Standing));
    assert_eq!(model.supersedes(ClaimKey(2)), Some(ClaimKey(1)));
    assert_eq!(model.claims()[&ClaimKey(2)].writer, Actor::Agent(0));
    assert_eq!(model.live_claims(), vec![ClaimKey(1), ClaimKey(2)]);
    assert_eq!(model.visible_to(Actor::Owner), vec![ClaimKey(2)]);
}
#[test]
fn direct_correction_and_rejection_are_different_paths() {
    let mut model = vault();
    write(&mut model, 1, 0, 1);
    write(&mut model, 2, 0, 1);
    assert_eq!(model.status(ClaimKey(1)), Some(Status::Superseded));
    assert_eq!(model.supersedes(ClaimKey(2)), Some(ClaimKey(1)));
    let before = model.clone();
    assert!(matches!(
        model.owner_write(ClaimKey(99), Ent(0), QKey(0), 2, Aud(1)),
        Outcome::Unspecified(_)
    ));
    assert_eq!(model, before);
    applied(model.agent_propose(0, ClaimKey(3), Ent(0), QKey(0), 3, Aud(1)));
    applied(model.owner_reject(ClaimKey(3)));
    assert_eq!(model.status(ClaimKey(3)), Some(Status::Rejected));
    assert_eq!(model.supersedes(ClaimKey(3)), None);
    assert_eq!(model.standing_heads(question(0, 1)), vec![ClaimKey(2)]);
    let before = model.clone();
    assert!(matches!(
        model.owner_approve(ClaimKey(3)),
        Outcome::Refused(_)
    ));
    assert_eq!(model, before);
}
#[test]
fn memory_07_inherited_claim_can_be_assigned_to_south() {
    let model = split_variant(true);
    assert_eq!(model.assigned_to(Ent(3)), vec![ClaimKey(2)]);
    assert_eq!(model.claims_held_by(Ent(3)), vec![ClaimKey(2)]);
    assert_eq!(model.remaining_on(Ent(0)), vec![]);
    assert_eq!(model.claims()[&ClaimKey(2)].subject, Ent(1));
    assert_eq!(model.live_claims(), vec![ClaimKey(1), ClaimKey(2)]);
}
#[test]
fn memory_07_unassigned_inherited_claim_remains_on_survivor() {
    let model = split_variant(false);
    assert_eq!(model.assigned_to(Ent(3)), vec![]);
    assert_eq!(model.remaining_on(Ent(0)), vec![ClaimKey(2)]);
    assert_eq!(model.claims_held_by(Ent(0)), vec![ClaimKey(2)]);
}
#[test]
fn split_refuses_a_claim_of_a_never_merged_entity_atomically() {
    let mut model = merged();
    write(&mut model, 3, 4, 1);
    let before = model.clone();
    assert!(matches!(
        model.split(
            Ent(0),
            &[Ent(2), Ent(3)],
            &[(ClaimKey(1), Ent(2)), (ClaimKey(3), Ent(3))]
        ),
        Outcome::Refused(_)
    ));
    assert_eq!(model, before);
    assert_eq!(model.assigned_to(Ent(3)), vec![]);
}
#[test]
fn merge_chains_preserve_claim_subjects_and_split_membership() {
    let mut model = vault();
    write(&mut model, 1, 2, 1);
    applied(model.merge(&[Ent(2)], Ent(1)));
    applied(model.merge(&[Ent(1)], Ent(0)));
    assert_eq!(model.remaining_on(Ent(0)), vec![ClaimKey(1)]);
    applied(model.split(Ent(0), &[Ent(3), Ent(4)], &[(ClaimKey(1), Ent(4))]));
    assert_eq!(model.assigned_to(Ent(4)), vec![ClaimKey(1)]);
    assert_eq!(model.claims()[&ClaimKey(1)].subject, Ent(2));
}
#[test]
fn restart_changes_no_state_or_observation() {
    let mut model = split_variant(false);
    write(&mut model, 3, 4, 0);
    applied(model.agent_propose(1, ClaimKey(4), Ent(4), QKey(0), 4, Aud(1)));
    write(&mut model, 5, 5, 0);
    applied(model.delete(ClaimKey(5)));
    let before = model.clone();
    let observed = model.observe();
    applied(model.restart());
    assert_eq!(model, before);
    assert_eq!(model.observe(), observed);
}
#[test]
fn deletion_removes_live_topology_and_recall_but_not_its_tombstone() {
    let mut model = split_variant(true);
    applied(model.delete(ClaimKey(2)));
    assert_eq!(model.status(ClaimKey(2)), Some(Status::Deleted));
    assert_eq!(model.audience(ClaimKey(2)), Aud::ABSENT);
    assert_eq!(model.live_claims(), vec![ClaimKey(1)]);
    assert_eq!(model.assigned_to(Ent(3)), vec![]);
    assert_eq!(model.claims_held_by(Ent(3)), vec![]);
    assert_eq!(model.visible_to(Actor::Owner), vec![ClaimKey(1)]);
    let mut history = settled();
    let before = history.clone();
    assert!(matches!(
        history.delete(ClaimKey(2)),
        Outcome::Unspecified(_)
    ));
    assert_eq!(history, before);
    assert!(matches!(history.merge(&[Ent(0)], Ent(1)), Outcome::Applied));
    let before = history.clone();
    assert!(matches!(
        history.merge(&[Ent(0)], Ent(2)),
        Outcome::Unspecified(_)
    ));
    assert_eq!(history, before);
}
#[test]
fn audiences_are_exact_scopes_and_proposals_cannot_escalate_themselves() {
    let mut model = vault();
    write(&mut model, 1, 0, 0);
    write(&mut model, 2, 0, 1);
    assert_eq!(model.standing_heads(question(0, 0)), vec![ClaimKey(1)]);
    assert_eq!(model.standing_heads(question(0, 1)), vec![ClaimKey(2)]);
    assert_eq!(
        model.visible_to(Actor::Owner),
        vec![ClaimKey(1), ClaimKey(2)]
    );
    assert_eq!(model.visible_to(Actor::Agent(0)), vec![ClaimKey(2)]);
    let before = model.clone();
    assert!(matches!(
        model.agent_propose(0, ClaimKey(3), Ent(0), QKey(0), 3, Aud(0)),
        Outcome::Refused(_)
    ));
    assert_eq!(model, before);
    applied(model.agent_propose(0, ClaimKey(3), Ent(0), QKey(0), 3, Aud(1)));
    assert_eq!(model.status(ClaimKey(3)), Some(Status::Proposed));
    assert_eq!(model.visible_to(Actor::Agent(0)), vec![ClaimKey(2)]);
    assert_eq!(model.visible_to(Actor::Agent(255)), vec![]);
}
#[test]
fn i2_reports_both_the_two_head_defect_and_its_lifecycle_details() {
    let model = settled();
    let mut observed = Observed::default();
    observed
        .standing_heads
        .insert(question(0, 1), vec![ClaimKey(1), ClaimKey(2)]);
    let error = model.i2_one_live_version(&observed).unwrap_err();
    assert_eq!(error.invariant, "I2");
    assert!(error.message.contains("2 standing heads"));
    observed = Observed::default();
    observed
        .statuses
        .insert(ClaimKey(1), Some(Status::Standing));
    assert!(
        model
            .i2_one_live_version(&observed)
            .unwrap_err()
            .message
            .contains("status")
    );
    observed = Observed::default();
    observed.supersedes.insert(ClaimKey(2), None);
    assert!(
        model
            .i2_one_live_version(&observed)
            .unwrap_err()
            .message
            .contains("supersedes")
    );
}
#[test]
fn i1_reports_inherited_assignment_and_remaining_defects_even_with_equal_live_count() {
    let model = split_variant(true);
    let mut observed = Observed::default();
    observed.live = Some(model.live_claims());
    observed.assigned.insert(Ent(3), vec![]);
    let error = model.i1_counts_conserve(&observed).unwrap_err();
    assert_eq!(error.invariant, "I1");
    assert!(error.message.contains("assigned to Ent(3)"));
    let model = split_variant(false);
    observed = Observed::default();
    observed.live = Some(model.live_claims());
    observed.remaining.insert(Ent(0), vec![]);
    assert!(
        model
            .i1_counts_conserve(&observed)
            .unwrap_err()
            .message
            .contains("remaining on Ent(0)")
    );
    observed = Observed::default();
    observed.held.insert(Ent(0), vec![]);
    assert!(model.i1_counts_conserve(&observed).is_err());
    let model = merged();
    assert!(model.i1_counts_conserve(&observed).is_err()); // inherited is held before any split, too
}
#[test]
fn i3_reports_scope_changes_and_read_leaks_but_allows_read_subsets() {
    let mut model = vault();
    write(&mut model, 1, 0, 0);
    write(&mut model, 2, 1, 1);
    let mut observed = Observed::default();
    observed.audience.insert(ClaimKey(1), Aud(1));
    assert_eq!(
        model
            .i3_no_audience_widens(&observed)
            .unwrap_err()
            .invariant,
        "I3"
    );
    observed = Observed::default();
    observed.visible.insert(Actor::Agent(0), vec![ClaimKey(1)]);
    assert!(
        model
            .i3_no_audience_widens(&observed)
            .unwrap_err()
            .message
            .contains("disallowed")
    );
    observed.visible.insert(Actor::Agent(0), vec![]);
    observed.visible.insert(Actor::Owner, vec![ClaimKey(2)]);
    assert!(model.i3_no_audience_widens(&observed).is_ok());
}
#[test]
fn partial_observations_skip_only_omitted_fields_and_sets_are_order_independent() {
    let model = merged();
    let mut observed = Observed::default();
    assert!(model.i1_counts_conserve(&observed).is_ok());
    assert!(model.i2_one_live_version(&observed).is_ok());
    assert!(model.i3_no_audience_widens(&observed).is_ok());
    observed.live = Some(vec![ClaimKey(2), ClaimKey(1)]);
    assert!(model.i1_counts_conserve(&observed).is_ok());
    observed.live = Some(vec![]);
    assert!(model.i1_counts_conserve(&observed).is_err());
    observed = Observed::default();
    observed.statuses.insert(ClaimKey(1), None);
    assert!(model.i2_one_live_version(&observed).is_err());
}
#[test]
fn generator_covers_both_regressions_in_eight_short_seeds() {
    let universe = Universe::default();
    let mut approvals = 0;
    let mut assigned = 0;
    let mut residue = 0;
    for seed in 0..8 {
        let mut model = VaultModel::new(&universe);
        let mut covered = [false; 3];
        for step in sequence(seed, 40, &universe) {
            if let Step::OwnerApprove { claim } = &step {
                let proposed = &model.claims()[claim];
                if proposed.status == Status::Proposed
                    && matches!(proposed.writer, Actor::Agent(_))
                    && model.standing_heads(proposed.question_key()).len() == 1
                {
                    covered[0] = true;
                }
            }
            let mut check = Vec::new();
            if let Step::Split { entity, assign, .. } = &step {
                for id in model.claims_held_by(*entity) {
                    let claim = &model.claims()[&id];
                    if claim.subject != *entity
                        && model.entities()[&claim.subject].merged_into == Some(*entity)
                    {
                        assert!(model.remaining_on(*entity).contains(&id));
                        check.push((
                            id,
                            *entity,
                            assign.iter().find(|(key, _)| *key == id).map(|(_, h)| *h),
                        ));
                    }
                }
            }
            applied(step.apply(&mut model));
            for (id, entity, head) in check {
                if let Some(head) = head {
                    assert!(model.assigned_to(head).contains(&id));
                    covered[1] = true;
                } else {
                    assert!(model.remaining_on(entity).contains(&id));
                    covered[2] = true;
                }
            }
        }
        approvals += usize::from(covered[0]);
        assigned += usize::from(covered[1]);
        residue += usize::from(covered[2]);
        eprintln!(
            "seed {seed}, len 40: approval={}, inherited assigned={}, inherited remaining={}",
            covered[0], covered[1], covered[2]
        );
    }
    assert!(
        approvals > 0 && assigned > 0 && residue > 0,
        "coverage: {approvals}/{assigned}/{residue}"
    );
}
#[test]
fn generator_is_deterministic_and_replays_only_applied_steps() {
    let universe = Universe::default();
    assert_eq!(
        sequence(8123, 100, &universe),
        sequence(8123, 100, &universe)
    );
    for seed in 0..64 {
        let mut model = VaultModel::new(&universe);
        let steps = sequence(seed, 128, &universe);
        assert_eq!(steps.len(), 128);
        for step in steps {
            assert_eq!(
                step.apply(&mut model),
                Outcome::Applied,
                "seed {seed}: {step:?}"
            );
            let observed = model.observe();
            model.i1_counts_conserve(&observed).unwrap();
            model.i2_one_live_version(&observed).unwrap();
            model.i3_no_audience_widens(&observed).unwrap();
        }
    }
}
#[test]
fn generator_handles_empty_and_small_universes_without_panics() {
    for universe in [
        Universe {
            persons: 0,
            predicates: 0,
            agents: 0,
            audiences: 0,
        },
        Universe {
            persons: 1,
            predicates: 1,
            agents: 0,
            audiences: 1,
        },
        Universe {
            persons: 2,
            predicates: 0,
            agents: 1,
            audiences: 0,
        },
    ] {
        assert!(sequence(0, 0, &universe).is_empty());
        let mut model = VaultModel::new(&universe);
        for step in sequence(u64::MAX, 40, &universe) {
            applied(step.apply(&mut model));
        }
    }
}
