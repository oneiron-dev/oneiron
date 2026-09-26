use super::*;
use crate::receipt::ReceiptRecord;
use crate::skill_reliability::{skill_reliability_posterior, skill_reliability_prior};

fn terminal(vault: &Vault, failed: bool) -> Result<String> {
    terminal_with_skills(vault, failed, &[FIXTURE_SKILL_ID])
}

fn terminal_with_skills(vault: &Vault, failed: bool, skills: &[&str]) -> Result<String> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
        kind: "attribution.sweep".to_owned(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("new")
    };
    for skill in skills {
        queue.append_manifest_entry(
            row.id,
            ManifestEntry::new(ManifestKind::Skill, *skill, "1.0.0", 11),
        )?;
    }
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "attribution.sweep",
        ClaimAttempt {
            lease_owner: "host".to_owned(),
            now: 12,
        },
    )?
    else {
        panic!("lease")
    };
    if failed {
        queue.fail(crate::attempt_queue::FailAttempt {
            id: row.id,
            lease_owner: "host".to_owned(),
            attempt_count: leased.attempt_count,
            reason: "failed check".to_owned(),
            now: 13,
        })?;
    } else {
        queue.complete(CompleteAttempt {
            id: row.id,
            lease_owner: "host".to_owned(),
            attempt_count: leased.attempt_count,
            now: 13,
        })?;
    }
    Ok(attempt_pack_receipt_id(&row.id))
}

#[test]
fn task_sweep_projects_defect_lapse_and_win_once_across_bounded_pages() -> Result<()> {
    struct Source {
        actor: EntityId,
        skill: EntityId,
        lapse: Option<String>,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, receipt: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: if self.lapse.as_deref() == Some(receipt.receipt_id.as_str()) {
                    FollowedState::Ignored
                } else {
                    FollowedState::Followed
                },
                skill_covered_step: true,
            }]))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let prior = skill_reliability_prior(&vault, &skill)?;
    terminal(&vault, true)?;
    let mut source = Source {
        actor,
        skill,
        lapse: None,
    };
    let defect = run_task_attribution_sweep(&vault, 1, &source)?;
    assert_eq!(defect.captured_evidence, 1);
    assert_eq!(defect.judgments, 1);
    let after_defect = skill_reliability_posterior(&vault, &skill)?.unwrap();
    assert_eq!(after_defect.beta, prior.beta + 1.0);
    assert!(after_defect.mean() < prior.mean());
    source.lapse = Some(terminal(&vault, true)?);
    terminal(&vault, false)?;
    let mut captures = 0;
    for _ in 0..3 {
        captures += run_task_attribution_sweep(&vault, 1, &source)?.captured_evidence;
    }
    assert_eq!(captures, 2);
    let after = skill_reliability_posterior(&vault, &skill)?.unwrap();
    assert_eq!(after.alpha, prior.alpha + 1.0);
    assert_eq!(after.beta, prior.beta + 1.0);
    let failures = vault
        .claims_for_subject(&actor)?
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).transpose())
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|body| body.predicate == crate::actor_claims::PREDICATE_ACTOR_FAILURE_MODE)
        .count();
    assert_eq!(failures, 1);
    let cursor = read_attribution_cursor(&vault)?;
    let rerun = run_task_attribution_sweep(&vault, 32, &source)?;
    assert_eq!(rerun.captured_evidence, 0);
    assert_eq!(rerun.judgments, 0);
    assert!(rerun.failures.is_empty());
    assert_eq!(read_attribution_cursor(&vault)?, cursor);
    assert_eq!(skill_reliability_posterior(&vault, &skill)?, Some(after));
    assert_eq!(attribution_judgments(&vault)?.len(), 2);
    Ok(())
}

#[test]
fn task_sweep_keeps_four_states_and_routes_stated_deviation_causes() -> Result<()> {
    use std::collections::HashMap;

    struct Source {
        actor: EntityId,
        skill: EntityId,
        states: HashMap<String, FollowedState>,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, receipt: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: self.states[&receipt.receipt_id].clone(),
                skill_covered_step: true,
            }]))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let prior = skill_reliability_prior(&vault, &skill)?;
    let followed = terminal(&vault, true)?;
    let partly = terminal(&vault, true)?;
    let ignored = terminal(&vault, true)?;
    let deviated = terminal(&vault, true)?;
    let states = HashMap::from([
        (followed.clone(), FollowedState::Followed),
        (partly.clone(), FollowedState::Partly),
        (ignored.clone(), FollowedState::Ignored),
        (
            deviated.clone(),
            FollowedState::DeviatedWithReason {
                reason: "the documented command is wrong for this input".to_owned(),
                cause: Some(DeviationCause::IncorrectInstruction),
            },
        ),
    ]);
    let source = Source {
        actor,
        skill,
        states: states.clone(),
    };
    let first = run_task_attribution_sweep(&vault, 64, &source)?;
    assert_eq!(first.captured_evidence, 4);
    assert_eq!(first.judgments, 3); // partly is unresolved, not a lapse
    assert!(first.failures.is_empty());
    let stored = crate::skill_attribution::codec::evidence_after(&vault, 0)?;
    for (_, row) in &stored {
        assert_eq!(row.followed_state, Some(states[&row.receipt_ref].clone()));
    }
    let judgments = attribution_judgments(&vault)?;
    let verdict_for = |receipt: &str| {
        judgments
            .iter()
            .find(|row| {
                row.evidence_receipts
                    .first()
                    .is_some_and(|id| id == receipt)
            })
            .map(|row| row.verdict)
    };
    assert_eq!(
        verdict_for(&followed),
        Some(AttributionVerdict::SkillDefect)
    );
    assert_eq!(verdict_for(&partly), None);
    assert_eq!(
        verdict_for(&ignored),
        Some(AttributionVerdict::ExecutionLapse)
    );
    assert_eq!(
        verdict_for(&deviated),
        Some(AttributionVerdict::SkillDefect)
    );
    let after = skill_reliability_posterior(&vault, &skill)?.unwrap();
    assert_eq!(after.beta, prior.beta + 2.0);
    assert_eq!(
        run_task_attribution_sweep(&vault, 64, &source)?.captured_evidence,
        0
    );
    assert_eq!(skill_reliability_posterior(&vault, &skill)?, Some(after));
    assert_eq!(attribution_judgments(&vault)?, judgments);
    Ok(())
}

#[test]
fn unresolved_deviation_reason_reaches_injected_judge() -> Result<()> {
    struct Source {
        actor: EntityId,
        skill: EntityId,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, _: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: FollowedState::DeviatedWithReason {
                    reason: "the instruction has no safe path for this input".to_owned(),
                    cause: None,
                },
                skill_covered_step: true,
            }]))
        }
    }
    struct Judge;
    impl AttributionJudge for Judge {
        fn judge(&self, evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            assert_eq!(
                evidence.followed_state,
                Some(FollowedState::DeviatedWithReason {
                    reason: "the instruction has no safe path for this input".to_owned(),
                    cause: None,
                })
            );
            assert_eq!(RuleAttributionJudge.judge(evidence)?, None);
            Ok(Some(AttributionVerdict::SkillDefect))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let receipt = terminal(&vault, true)?;
    let report =
        run_task_attribution_sweep_with_judge(&vault, 16, &Source { actor, skill }, &Judge)?;
    assert_eq!(report.judgments, 1);
    assert_eq!(
        attribution_judgments(&vault)?[0].evidence_receipts,
        vec![receipt]
    );
    Ok(())
}

#[test]
fn partial_per_skill_facts_cannot_mark_a_receipt_captured() -> Result<()> {
    struct Source {
        actor: EntityId,
        skills: Vec<EntityId>,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, _: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(
                self.skills
                    .iter()
                    .map(|skill| ReceiptAttributionFacts {
                        actor: self.actor,
                        skill: Some(*skill),
                        followed_state: FollowedState::Followed,
                        skill_covered_step: true,
                    })
                    .collect(),
            ))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let first = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let second = put_skill(&vault, EntityId::now(), "attribution.fixture.other")?;
    terminal_with_skills(
        &vault,
        true,
        &[FIXTURE_SKILL_ID, "attribution.fixture.other"],
    )?;
    let mut source = Source {
        actor,
        skills: vec![first],
    };
    let incomplete = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(incomplete.captured_evidence, 0);
    assert_eq!(incomplete.failures.len(), 1);
    source.skills.push(second);
    let complete = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(complete.captured_evidence, 2);
    assert_eq!(complete.judgments, 2);
    Ok(())
}

#[test]
fn ignored_success_is_not_a_contributing_skill_win() -> Result<()> {
    struct Source {
        actor: EntityId,
        skill: EntityId,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, _: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: FollowedState::Ignored,
                skill_covered_step: true,
            }]))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    terminal(&vault, false)?;
    let report = run_task_attribution_sweep(&vault, 8, &Source { actor, skill })?;
    assert_eq!(report.captured_evidence, 1);
    assert!(report.skills.is_empty());
    assert_eq!(skill_reliability_posterior(&vault, &skill)?, None);
    Ok(())
}

#[test]
fn stated_executor_deviation_mints_actor_failure_mode_without_skill_loss() -> Result<()> {
    struct Source {
        actor: EntityId,
        skill: EntityId,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, _: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: FollowedState::DeviatedWithReason {
                    reason: "I skipped the required check".to_owned(),
                    cause: Some(DeviationCause::ExecutorError),
                },
                skill_covered_step: true,
            }]))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let prior = skill_reliability_prior(&vault, &skill)?;
    terminal(&vault, true)?;
    let source = Source { actor, skill };
    let first = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(first.judgments, 1);
    assert!(first.skills.is_empty());
    assert_eq!(
        attribution_judgments(&vault)?[0].verdict,
        AttributionVerdict::ExecutionLapse
    );
    assert!(skill_reliability_posterior(&vault, &skill)?.is_none_or(|row| row.beta == prior.beta));
    let failures = vault
        .claims_for_subject(&actor)?
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).transpose())
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|row| row.predicate == crate::actor_claims::PREDICATE_ACTOR_FAILURE_MODE)
        .count();
    assert_eq!(failures, 1);
    let rerun = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(rerun.judgments, 0);
    assert_eq!(rerun.actor_claims.len(), 0);
    Ok(())
}
