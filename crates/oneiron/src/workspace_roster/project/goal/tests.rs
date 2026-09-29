use super::*;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::workspace_roster::ProjectRecord;

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
    assert!(vault.project_intake_goal(project)?.is_none());
    let id = vault.write_project_goal_from_intake(&owner, project, &record, 2)?;
    assert_eq!(
        vault.project(project)?.unwrap().goal.as_deref(),
        Some(id.to_hex().as_str())
    );
    assert_eq!(vault.project_intake_goal(project)?, Some(record.clone()));
    let mut revision = record;
    revision.primary_axes[0].bound = ">= 95".into();
    let new_id = vault.write_project_goal_from_intake(&owner, project, &revision, 3)?;
    assert_ne!(new_id, id);
    assert_eq!(
        vault.get_claim(&id)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(vault.project_intake_goal(project)?, Some(revision.clone()));
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.project_intake_goal(project)?, Some(revision));
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
    assert!(vault.project_intake_goal(project)?.is_none());
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
    assert!(vault.project_intake_goal(project)?.is_none());
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
    )
    .unwrap();
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
    assert!(vault.project_intake_goal(project)?.is_none());

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
        vault.project_intake_goal(project)?,
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
    )
    .unwrap();
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

#[test]
fn goal_limits_are_policy_rows_and_narrow_only_at_admission() -> Result<()> {
    let defaults = crate::workspace_roster::GoalLimits::default();
    assert!(crate::workspace_roster::GoalLimits::decode(&defaults.encode()).is_some());
    let mut malformed = defaults.encode();
    let Value::Map(fields) = &mut malformed else {
        unreachable!()
    };
    fields.push((Value::from("preferences"), Value::from(999_u64)));
    assert!(crate::workspace_roster::GoalLimits::decode(&malformed).is_none());
    let Value::Map(fields) = &mut malformed else {
        unreachable!()
    };
    fields.pop();
    fields.push((Value::from("unknown"), Value::from(1_u64)));
    assert!(crate::workspace_roster::GoalLimits::decode(&malformed).is_none());
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
    vault.write_project_goal_from_intake(&owner, project, &record, 2)?;
    let mut narrowed = defaults;
    narrowed.preferences = 1;
    let mut manifest = rmpv::decode::read_value(&mut std::io::Cursor::new(
        crate::gate::default_policy_manifest().unwrap(),
    ))
    .map_err(|_| invalid())?;
    let Value::Map(ref mut rows) = manifest else {
        unreachable!()
    };
    *rows
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("goal_limits"))
        .ok_or_else(invalid)? = (Value::from("goal_limits"), narrowed.encode());
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).map_err(|_| invalid())?;
    crate::test_util::put_policy_manifest_bytes(&vault, EntityId::now(), &bytes)?;
    assert_eq!(
        crate::gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn()?)?
            .goal_limits()
            .preferences,
        1
    );
    // A narrowed rule cannot unwrite a historically admitted goal.
    assert_eq!(vault.project_intake_goal(project)?, Some(record.clone()));
    let mut too_many = record.clone();
    too_many.preferences.push(GoalPreference {
        prefer: "speed".into(),
        over: "cost".into(),
        reason: "human pick".into(),
    });
    assert!(
        vault
            .write_project_goal_from_intake(&owner, project, &too_many, 3)
            .is_err()
    );
    assert_eq!(vault.project_intake_goal(project)?, Some(record));
    Ok(())
}

#[test]
fn goal_owner_delete_uses_soft_and_hard_rails_without_stranding_project() -> Result<()> {
    use crate::memory::SafeDeleteReason;
    for hard in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let root_record = vault.project(root)?.unwrap();
        let human = EntityId::now();
        vault.put_entity(
            &human,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )?;
        let project = EntityId::now();
        vault.put_project(
            project,
            &ProjectRecord::new(
                project,
                Some(root),
                root,
                EntityId::from_hex(&root_record.leader)?,
            )
            .unwrap(),
            1,
        )?;
        let owner = vault.authenticate_owner(
            human,
            &human.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let first =
            vault.write_project_goal_from_intake(&owner, project, &transcript_record(), 2)?;
        let mut revised = transcript_record();
        revised.primary_axes[0].bound = ">= 95".into();
        let current = vault.write_project_goal_from_intake(&owner, project, &revised, 3)?;
        assert!(vault.delete_entity(&current).is_err());
        assert!(vault.batch().delete(&current).commit().is_err());
        assert!(
            vault
                .delete_entity_with_reason(&current, crate::DeleteReason::UserHardDelete)
                .is_err()
        );
        assert_eq!(vault.project_intake_goal(project)?, Some(revised));
        let result = vault
            .memory(human, EdgeActorClass::Human)
            .safe_delete(
                &current.to_hex(),
                if hard {
                    SafeDeleteReason::UserHardDelete
                } else {
                    SafeDeleteReason::UserDelete
                },
            )
            .map_err(|_| invalid())?;
        assert!(result.existed);
        if hard {
            assert!(result.receipt_ref.is_some());
            assert!(vault.get_raw(&current)?.is_none());
        } else {
            assert_eq!(
                vault.get_raw(&current)?.unwrap().len(),
                crate::batch::ENTITY_METADATA_HEADER_LEN
            );
        }
        assert!(vault.project_intake_goal(project)?.is_none());
        assert!(vault.project(project)?.unwrap().goal.is_none());
        let mut edited = vault.project(project)?.unwrap();
        edited.budget = Some(EntityId::now().to_hex());
        vault.put_project(project, &edited, 4)?;
        // Deleting a closed old claim cannot clear a newer project head.
        vault
            .memory(human, EdgeActorClass::Human)
            .safe_delete(&first.to_hex(), SafeDeleteReason::UserDelete)
            .map_err(|_| invalid())?;
        assert!(vault.project_intake_goal(project)?.is_none());
        drop(vault);
        let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
        assert!(reopened.project_intake_goal(project)?.is_none());
    }
    Ok(())
}

#[test]
fn replayed_goal_tombstone_retains_no_dangling_pointer() -> Result<()> {
    for reason in [
        crate::deletion::TombstoneReason::UserDelete,
        crate::deletion::TombstoneReason::UserHardDelete,
    ] {
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
        let goal =
            vault.write_project_goal_from_intake(&owner, project, &transcript_record(), 2)?;
        let tombstone = crate::deletion::TombstoneValueV2 {
            reason,
            deleted_at: 3,
            request_id: [0x77; 16],
        }
        .encode();
        vault.apply_replayed_tombstone(&goal, &tombstone)?;
        assert!(vault.project_intake_goal(project)?.is_none());
        assert!(vault.project(project)?.unwrap().goal.is_none());
        vault.apply_replayed_tombstone(&goal, &tombstone)?;
        assert!(vault.project_intake_goal(project)?.is_none());
    }
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn receiving_vault_keeps_unverified_goal_out_of_authority() -> Result<()> {
    let origin_dir = tempfile::tempdir()?;
    let origin = Vault::open(origin_dir.path(), crate::VaultConfig::default())?;
    let project = origin.root_project()?;
    let human = EntityId::now();
    origin.put_entity(
        &human,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    let owner = origin.authenticate_owner(
        human,
        &human.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let goal = origin.write_project_goal_from_intake(&owner, project, &transcript_record(), 2)?;
    let body = origin.get_raw(&goal)?.ok_or_else(invalid)?;
    let receiver_dir = tempfile::tempdir()?;
    let receiver = Vault::open(receiver_dir.path(), crate::VaultConfig::default())?;
    let err = receiver
        .batch()
        .put_replicated(
            &goal,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 2, end: 2 },
            2,
            &body[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )
        .commit()
        .expect_err("origin's local intake marker does not travel as owner proof");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidProjectBody);
    assert!(
        crate::sync::quarantine::remote_rejection_reason(&err).is_some(),
        "Observer B retains the received op in its quarantine ledger instead of promoting it"
    );
    assert!(receiver.get_claim(&goal)?.is_none());
    assert!(
        receiver
            .project_intake_goal(receiver.root_project()?)?
            .is_none()
    );
    assert_eq!(
        origin.project_intake_goal(project)?,
        Some(transcript_record())
    );
    Ok(())
}

#[test]
fn superseded_goal_erases_after_its_project_is_deleted() -> Result<()> {
    use crate::memory::SafeDeleteReason;
    use crate::ports::EdgeStoreRead;
    for hard in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
        let human = EntityId::now();
        vault.put_entity(
            &human,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )?;
        let project = EntityId::now();
        vault.put_project(
            project,
            &ProjectRecord::new(project, Some(root), root, leader).unwrap(),
            1,
        )?;
        let owner = vault.authenticate_owner(
            human,
            &human.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let reason = || {
            if hard {
                SafeDeleteReason::UserHardDelete
            } else {
                SafeDeleteReason::UserDelete
            }
        };
        let first =
            vault.write_project_goal_from_intake(&owner, project, &transcript_record(), 2)?;
        let mut revised = transcript_record();
        revised.primary_axes[0].bound = ">= 95".into();
        let current = vault.write_project_goal_from_intake(&owner, project, &revised, 3)?;
        let memory = vault.memory(human, EdgeActorClass::Human);
        memory
            .safe_delete(&current.to_hex(), reason())
            .map_err(|_| invalid())?;
        if hard {
            vault.delete_entity_with_options(
                &project,
                crate::deletion::DeleteEntityOptions { purge: true },
            )?;
        } else {
            vault.delete_entity_with_reason(&project, crate::DeleteReason::UserDelete)?;
        }
        assert!(vault.project(project)?.is_none());
        let result = memory
            .safe_delete(&first.to_hex(), reason())
            .map_err(|_| invalid())?;
        assert!(result.existed);
        let marker = [
            b"project.goal_intake.admission/".as_slice(),
            first.as_bytes(),
        ]
        .concat();
        let assert_retired = |vault: &Vault| -> Result<()> {
            {
                let txn = vault.store.env.read_txn()?;
                assert!(vault.store.vault_meta.get(&txn, &marker)?.is_none());
                assert!(
                    vault
                        .store
                        .port_edge_get(&txn, &first, crate::edge::EdgeKind::ClaimOf, &project)?
                        .is_none()
                );
            }
            if hard {
                assert!(vault.get_raw(&first)?.is_none());
            } else {
                assert_eq!(
                    vault.get_raw(&first)?.unwrap().len(),
                    crate::batch::ENTITY_METADATA_HEADER_LEN
                );
            }
            // The erase never recreates the deleted project.
            assert!(vault.project(project)?.is_none());
            assert!(vault.project_intake_goal(project)?.is_none());
            Ok(())
        };
        assert_retired(&vault)?;
        let tombstone = crate::deletion::TombstoneValueV2 {
            reason: if hard {
                crate::deletion::TombstoneReason::UserHardDelete
            } else {
                crate::deletion::TombstoneReason::UserDelete
            },
            deleted_at: 5,
            request_id: [0x55; 16],
        }
        .encode();
        vault.apply_replayed_tombstone(&first, &tombstone)?;
        assert_retired(&vault)?;
    }
    Ok(())
}

#[test]
fn goal_limits_precedence_is_a_strict_manifest_row() -> Result<()> {
    use super::limits::GoalLimitsPrecedence;
    type Fields = Vec<(Value, Value)>;
    let manifest = || -> Result<Value> {
        rmpv::decode::read_value(&mut std::io::Cursor::new(
            crate::gate::default_policy_manifest().unwrap(),
        ))
        .map_err(|_| invalid())
    };
    let Value::Map(rows) = manifest()? else {
        unreachable!()
    };
    let shipped = rows
        .into_iter()
        .find(|(k, _)| k.as_str() == Some("goal_limits"))
        .ok_or_else(invalid)?
        .1;
    let decoded = GoalLimits::decode(&shipped).ok_or_else(invalid)?;
    assert_eq!(decoded, GoalLimits::default());
    assert_eq!(decoded.precedence, GoalLimitsPrecedence::NestedNarrowing);
    let edited = |edit: &dyn Fn(&mut Fields)| {
        let mut row = shipped.clone();
        let Value::Map(fields) = &mut row else {
            unreachable!()
        };
        edit(fields);
        GoalLimits::decode(&row)
    };
    let missing = |fields: &mut Fields| {
        fields.retain(|(k, _)| k.as_str() != Some("precedence"));
    };
    assert!(edited(&missing).is_none());
    assert!(
        edited(&|fields| {
            for (k, v) in fields.iter_mut() {
                if k.as_str() == Some("precedence") {
                    *v = Value::from("holder_then_default");
                }
            }
        })
        .is_none()
    );
    // Vault-level only: a scope, holder or project key is as unknown as any other.
    for key in ["unknown", "scope", "holder", "project"] {
        assert!(edited(&|fields| fields.push((Value::from(key), Value::from(1_u64)))).is_none());
        assert!(
            edited(&|fields| {
                for (k, _) in fields.iter_mut() {
                    if k.as_str() == Some("preferences") {
                        *k = Value::from(key);
                    }
                }
            })
            .is_none()
        );
    }

    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let resolve = |vault: &Vault| {
        crate::gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn()?)
    };
    let policy = resolve(&vault)?;
    assert_eq!(policy.goal_limits, Some(GoalLimits::default()));
    let with_limits = |limits: Value| -> Result<Vec<u8>> {
        let mut manifest = manifest()?;
        let Value::Map(ref mut rows) = manifest else {
            unreachable!()
        };
        rows.iter_mut()
            .find(|(k, _)| k.as_str() == Some("goal_limits"))
            .ok_or_else(invalid)?
            .1 = limits;
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &manifest).map_err(|_| invalid())?;
        Ok(bytes)
    };
    let first = GoalLimits {
        goal_bytes: 100,
        axes: 20,
        ..GoalLimits::default()
    };
    let second = GoalLimits {
        goal_bytes: 200,
        axes: 10,
        preferences: 3,
        ..GoalLimits::default()
    };
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &with_limits(first.encode())?,
    )?;
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &with_limits(second.encode())?,
    )?;
    let policy = resolve(&vault)?;
    assert!(!policy.diagnostics().loaded_manifest_forces_fail_closed());
    assert_eq!(
        policy.goal_limits(),
        GoalLimits {
            goal_bytes: 100,
            axes: 10,
            preferences: 3,
            ..GoalLimits::default()
        }
    );
    assert_eq!(
        policy.goal_limits().precedence,
        GoalLimitsPrecedence::NestedNarrowing
    );

    // A malformed row takes the existing fail-closed path.
    let mut malformed = first.encode();
    let Value::Map(fields) = &mut malformed else {
        unreachable!()
    };
    missing(fields);
    crate::test_util::put_policy_manifest_bytes(&vault, EntityId::now(), &with_limits(malformed)?)?;
    assert!(
        resolve(&vault)?
            .diagnostics()
            .loaded_manifest_forces_fail_closed()
    );
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
    let project = vault.root_project()?;
    assert!(
        vault
            .write_project_goal_from_intake(&owner, project, &transcript_record(), 2)
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());
    Ok(())
}
