use super::*;
use crate::registry::ENTITY_TYPE_PERSON;

fn axis(name: &str, measure: &str, bound: &str) -> GoalAxis {
    GoalAxis {
        name: name.into(),
        measure: measure.into(),
        bound: bound.into(),
    }
}

// Scripted exchange: agent asks what improves, what may not regress, what
// costs count, and the human supplies the explicit numbers and rationale.
fn transcript_record() -> GoalRecord {
    GoalRecord {
        goal: "Answer customer requests correctly".into(),
        why: "Reduce repeat support tickets".into(),
        primary_axes: vec![axis(
            "confirmed_answers",
            "resolved requests per week from receipts",
            ">= 90",
        )],
        floor_axes: vec![axis(
            "unsafe_answers",
            "held-out unsafe answer count",
            "= 0",
        )],
        cost_axes: vec![
            axis(
                "human_minutes",
                "minutes of review and asks per week",
                "<= 30",
            ),
            axis("tokens", "token spend per week", "<= 10000"),
        ],
        preferences: vec![GoalPreference {
            prefer: "lower cost".into(),
            over: "faster response".into(),
            reason: "The human chose cost on this tradeoff".into(),
        }],
        exploration_budget: GoalExplorationBudget {
            max_spend: 1000,
            exploration_slice: 100,
            human_minutes: 20,
        },
    }
}

#[test]
fn scripted_human_interview_commits_valid_typed_goal_and_revisions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let project = vault.root_project()?;
    let human = EntityId::now();
    vault.put_entity(
        &human,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    let owner = vault.authenticate_owner(
        human,
        &human.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let record = transcript_record();
    assert!(vault.project_goal_record(project)?.is_none());
    let id = vault.write_project_goal_from_intake(&owner, project, &record, 2)?;
    assert_eq!(
        vault.project(project)?.unwrap().goal.as_deref(),
        Some(id.to_hex().as_str())
    );
    assert_eq!(vault.project_goal_record(project)?, Some(record.clone()));
    let mut revision = record;
    revision.primary_axes[0].bound = ">= 95".into();
    let new_id = vault.write_project_goal_from_intake(&owner, project, &revision, 3)?;
    assert_ne!(new_id, id);
    assert_eq!(
        vault.get_claim(&id)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(vault.project_goal_record(project)?, Some(revision.clone()));
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.project_goal_record(project)?, Some(revision));
    Ok(())
}

#[test]
fn incomplete_answers_and_unauthenticated_agent_cannot_commit_goal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let project = vault.root_project()?;
    let human = EntityId::now();
    vault.put_entity(
        &human,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    let owner = vault.authenticate_owner(
        human,
        &human.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let agent = vault.project(project)?.unwrap().leader;
    assert!(
        vault
            .authenticate_owner(
                EntityId::from_hex(&agent)?,
                &agent,
                true,
                crate::store::GateDecisionId::now()
            )
            .is_err()
    );
    assert!(
        vault
            .authenticate_owner(
                human,
                &human.to_hex(),
                false,
                crate::store::GateDecisionId::now()
            )
            .is_err()
    );
    let mut draft = transcript_record();
    draft.cost_axes.retain(|a| a.name != "human_minutes");
    assert!(
        vault
            .write_project_goal_from_intake(&owner, project, &draft, 2)
            .is_err()
    );
    draft = transcript_record();
    draft.floor_axes.clear();
    assert!(
        vault
            .write_project_goal_from_intake(&owner, project, &draft, 2)
            .is_err()
    );
    draft = transcript_record();
    draft.exploration_budget.exploration_slice = 1001;
    assert!(
        vault
            .write_project_goal_from_intake(&owner, project, &draft, 2)
            .is_err()
    );
    assert!(vault.project_goal_record(project)?.is_none());
    // A loop can propose a replacement, but its ordinary generated claim
    // cannot impersonate a confirmed interview through the normal claim gate.
    let leader = EntityId::from_hex(&agent)?;
    let candidate_id = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(leader, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("loop proposal"))?,
        ClaimApprovalStatus::Auto,
    );
    assert!(
        vault
            .batch()
            .claim_candidate(
                &candidate_id,
                ClaimCandidate::new(
                    PREDICATE,
                    ClaimSubject::Entity(project),
                    Value::Binary(encode(&transcript_record())?),
                    1.0,
                ),
                &envelope,
                TimeRange { start: 2, end: 2 },
                2,
            )
            .commit()
            .is_err()
    );
    assert!(vault.get_claim(&candidate_id)?.is_none());
    assert!(vault.project_goal_record(project)?.is_none());
    Ok(())
}
