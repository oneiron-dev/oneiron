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
pub(super) fn transcript_record() -> GoalRecord {
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

#[test]
fn forged_human_claim_and_generic_or_replicated_project_changes_are_refused() -> Result<()> {
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
    let fake = WriteEnvelope::new(
        WriteActor::new(human, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("claimed owner confirmation"))?,
        ClaimApprovalStatus::Approved,
    );
    let forged_id = EntityId::now();
    assert!(
        vault
            .batch()
            .claim_candidate(
                &forged_id,
                ClaimCandidate::new(
                    PREDICATE,
                    ClaimSubject::Entity(project),
                    Value::Binary(encode(&transcript_record())?),
                    1.0
                ),
                &fake,
                TimeRange { start: 2, end: 2 },
                2,
            )
            .commit()
            .is_err()
    );
    assert!(vault.get_claim(&forged_id)?.is_none());
    let mut forged_raw = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(project),
        Value::Binary(encode(&transcript_record())?),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    forged_raw.source = Some(ClaimSource::UserStated);
    assert!(
        vault
            .put_claim(&forged_id, &forged_raw, TimeRange { start: 2, end: 2 }, 2)
            .is_err()
    );
    let mut project_body = vault.project(project)?.unwrap();
    project_body.goal = Some(forged_id.to_hex());
    assert!(vault.put_project(project, &project_body, 2).is_err());
    assert!(
        vault
            .batch()
            .put_replicated(
                &project,
                vault.project_type_byte()?,
                TimeRange { start: 2, end: 2 },
                2,
                &encode(&project_body)?,
            )
            .commit()
            .is_err()
    );
    assert!(vault.project_goal_record(project)?.is_none());

    let owner = vault.authenticate_owner(
        human,
        &human.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let admitted =
        vault.write_project_goal_from_intake(&owner, project, &transcript_record(), 3)?;
    let claim = vault.get_claim(&admitted)?.unwrap();
    let other_id = EntityId::now();
    assert!(
        vault
            .batch()
            .put_replicated(
                &other_id,
                crate::registry::ENTITY_TYPE_CLAIM,
                TimeRange { start: 3, end: 3 },
                3,
                &crate::claim::encode_claim_body(&claim)?,
            )
            .commit()
            .is_err()
    );
    // Exact re-materialization of a locally admitted row is harmless; bytes
    // from a new remote id still cannot create an owner authorization.
    vault
        .batch()
        .put_replicated(
            &admitted,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 3, end: 3 },
            3,
            &crate::claim::encode_claim_body(&claim)?,
        )
        .commit()?;
    let current_project = vault.project(project)?.unwrap();
    vault
        .batch()
        .put_replicated(
            &project,
            vault.project_type_byte()?,
            TimeRange { start: 3, end: 3 },
            3,
            &encode(&current_project)?,
        )
        .commit()?;
    assert!(vault.batch().delete(&admitted).commit().is_err());
    assert!(vault.batch().delete(&project).commit().is_err());
    let mut cleared = vault.project(project)?.unwrap();
    cleared.goal = None;
    assert!(vault.put_project(project, &cleared, 4).is_err());
    assert!(
        vault
            .batch()
            .put_replicated(
                &project,
                vault.project_type_byte()?,
                TimeRange { start: 4, end: 4 },
                4,
                &encode(&cleared)?,
            )
            .commit()
            .is_err()
    );
    assert_eq!(
        vault.project(project)?.unwrap().goal,
        Some(admitted.to_hex())
    );
    assert_eq!(
        vault.project_goal_record(project)?,
        Some(transcript_record())
    );
    Ok(())
}

#[test]
fn intake_does_not_supersede_a_claim_named_by_a_corrupt_project_pointer() -> Result<()> {
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
    let foreign = EntityId::now();
    let mut body = ClaimBody::new(
        "core.fact",
        ClaimSubject::Entity(project),
        Value::from("unrelated truth"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::UserStated);
    vault
        .batch()
        .put_replicated(
            &foreign,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 2, end: 2 },
            2,
            &crate::claim::encode_claim_body(&body)?,
        )
        .commit()?;
    assert!(
        vault
            .put_edge(&foreign, crate::edge::EdgeKind::ClaimOf, &project, 1.0,)
            .is_err()
    );
    // Corrupt pre-existing data exercises the write-side safety check even
    // though the new generic project door will not admit this pointer.
    let mut corrupted = vault.project(project)?.unwrap();
    corrupted.goal = Some(foreign.to_hex());
    let mut raw = vault.get_raw(&project)?.unwrap();
    raw.truncate(crate::batch::ENTITY_METADATA_HEADER_LEN);
    raw.extend_from_slice(&encode(&corrupted)?);
    vault.with_write_txn(|txn| {
        vault.store.entities.put(txn, project.as_bytes(), &raw)?;
        Ok(())
    })?;
    let before = vault.count_entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?;
    assert!(
        vault
            .write_project_goal_from_intake(&owner, project, &transcript_record(), 3)
            .is_err()
    );
    assert_eq!(
        vault.count_entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?,
        before
    );
    assert_eq!(
        vault.get_claim(&foreign)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault.project(project)?.unwrap().goal,
        Some(foreign.to_hex())
    );
    Ok(())
}
