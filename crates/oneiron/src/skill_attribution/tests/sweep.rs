use super::*;
use crate::receipt::ReceiptRecord;
use crate::skill_reliability::{skill_reliability_posterior_for_executor, skill_reliability_prior};

fn terminal(vault: &Vault, actor: EntityId, failed: bool) -> Result<String> {
    terminal_with_skills(vault, actor, failed, &[FIXTURE_SKILL_ID])
}

fn terminal_with_skills(
    vault: &Vault,
    actor: EntityId,
    failed: bool,
    skills: &[&str],
) -> Result<String> {
    let versions = skills
        .iter()
        .map(|skill| (*skill, "1.0.0"))
        .collect::<Vec<_>>();
    terminal_with_versions(vault, actor, failed, &versions)
}

fn terminal_with_versions(
    vault: &Vault,
    actor: EntityId,
    failed: bool,
    skills: &[(&str, &str)],
) -> Result<String> {
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
    vault.bind_actor_attempt(row.id, &actor)?;
    for (skill, version) in skills {
        queue.append_manifest_entry(
            row.id,
            ManifestEntry::new(ManifestKind::Skill, *skill, *version, 11),
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
    queue.set_executor_model(row.id, "host", leased.attempt_count, "fixture/model@1")?;
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
    terminal(&vault, actor, true)?;
    let mut source = Source {
        actor,
        skill,
        lapse: None,
    };
    let defect = run_task_attribution_sweep(&vault, 1, &source)?;
    assert_eq!(defect.captured_evidence, 1);
    assert_eq!(defect.judgments, 1);
    let after_defect =
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?.unwrap();
    assert_eq!(after_defect.beta, prior.beta + 1.0);
    assert!(after_defect.mean() < prior.mean());
    source.lapse = Some(terminal(&vault, actor, true)?);
    terminal(&vault, actor, false)?;
    let mut captures = 0;
    for _ in 0..3 {
        captures += run_task_attribution_sweep(&vault, 1, &source)?.captured_evidence;
    }
    assert_eq!(captures, 2);
    let after =
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?.unwrap();
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
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?,
        Some(after)
    );
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
    let followed = terminal(&vault, actor, true)?;
    let partly = terminal(&vault, actor, true)?;
    let ignored = terminal(&vault, actor, true)?;
    let deviated = terminal(&vault, actor, true)?;
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
    let after =
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?.unwrap();
    assert_eq!(after.beta, prior.beta + 2.0);
    assert_eq!(
        run_task_attribution_sweep(&vault, 64, &source)?.captured_evidence,
        0
    );
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?,
        Some(after)
    );
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
    let receipt = terminal(&vault, actor, true)?;
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
        actor,
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
    terminal(&vault, actor, false)?;
    let report = run_task_attribution_sweep(&vault, 8, &Source { actor, skill })?;
    assert_eq!(report.captured_evidence, 1);
    assert!(report.skills.is_empty());
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?,
        None
    );
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
    terminal(&vault, actor, true)?;
    let source = Source { actor, skill };
    let first = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(first.judgments, 1);
    assert!(first.skills.is_empty());
    assert_eq!(
        attribution_judgments(&vault)?[0].verdict,
        AttributionVerdict::ExecutionLapse
    );
    assert!(
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?
            .is_none_or(|row| row.beta == prior.beta)
    );
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

#[test]
fn wrong_revision_is_refused_before_capture_and_corrected_facts_project_once() -> Result<()> {
    struct Source {
        actor: EntityId,
        skill: EntityId,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, _: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: FollowedState::Followed,
                skill_covered_step: true,
            }]))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let old = put_skill_version(&vault, EntityId::now(), FIXTURE_SKILL_ID, "1.0.0")?;
    let new = put_skill_version(&vault, EntityId::now(), FIXTURE_SKILL_ID, "2.0.0")?;
    let prior = skill_reliability_prior(&vault, &old)?;
    terminal_with_versions(&vault, actor, true, &[(FIXTURE_SKILL_ID, "1.0.0")])?;
    let mut source = Source { actor, skill: new };
    let rejected = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(rejected.captured_evidence, 0);
    assert_eq!(rejected.failures.len(), 1);
    assert!(attribution_judgments(&vault)?.is_empty());
    source.skill = old;
    let accepted = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(accepted.captured_evidence, 1);
    assert_eq!(accepted.judgments, 1);
    assert_eq!(accepted.skills, vec![old]);
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &old, "fixture/model@1")?
            .unwrap()
            .beta,
        prior.beta + 1.0
    );
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &new, "fixture/model@1")?,
        None
    );
    assert_eq!(
        run_task_attribution_sweep(&vault, 8, &source)?.captured_evidence,
        0
    );
    Ok(())
}

#[test]
fn two_revisions_of_one_skill_in_one_receipt_both_receive_evidence() -> Result<()> {
    struct Source {
        actor: EntityId,
        skills: [EntityId; 2],
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
    let v1 = put_skill_version(&vault, EntityId::now(), FIXTURE_SKILL_ID, "1.0.0")?;
    let v2 = put_skill_version(&vault, EntityId::now(), FIXTURE_SKILL_ID, "2.0.0")?;
    terminal_with_versions(
        &vault,
        actor,
        true,
        &[(FIXTURE_SKILL_ID, "1.0.0"), (FIXTURE_SKILL_ID, "2.0.0")],
    )?;
    let source = Source {
        actor,
        skills: [v1, v2],
    };
    let first = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(first.captured_evidence, 2);
    assert_eq!(first.judgments, 2);
    assert_eq!(first.skills.len(), 2);
    for skill in [v1, v2] {
        let prior = skill_reliability_prior(&vault, &skill)?;
        assert_eq!(
            skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?
                .unwrap()
                .beta,
            prior.beta + 1.0
        );
    }
    assert_eq!(
        run_task_attribution_sweep(&vault, 8, &source)?.captured_evidence,
        0
    );
    Ok(())
}

#[test]
fn a_manifest_of_65_distinct_skills_captures_and_reruns_once() -> Result<()> {
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
                        followed_state: FollowedState::Ignored,
                        skill_covered_step: true,
                    })
                    .collect(),
            ))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let mut source = Source {
        actor,
        skills: Vec::new(),
    };
    let mut names = Vec::new();
    for index in 0..65 {
        let name = format!("attribution.fixture.skill.{index}");
        source
            .skills
            .push(put_skill(&vault, EntityId::now(), &name)?);
        names.push(name);
    }
    let entries: Vec<_> = names.iter().map(String::as_str).collect();
    terminal_with_skills(&vault, actor, true, &entries)?;
    let first = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(first.captured_evidence, 65);
    assert_eq!(first.judgments, 65);
    assert!(first.failures.is_empty());
    let rerun = run_task_attribution_sweep(&vault, 8, &source)?;
    assert_eq!(rerun.captured_evidence, 0);
    assert_eq!(rerun.judgments, 0);
    assert_eq!(attribution_judgments(&vault)?.len(), 65);
    Ok(())
}

fn install_attribution_limits(
    vault: &Vault,
    reason_bytes: u64,
    receipts_per_pass: u64,
    holder: Option<(EntityId, u64)>,
) -> Result<()> {
    install_attribution_limits_with_id(
        vault,
        crate::gate::default_policy_manifest_id()?,
        reason_bytes,
        receipts_per_pass,
        holder,
    )
}

fn install_attribution_limits_with_id(
    vault: &Vault,
    id: EntityId,
    reason_bytes: u64,
    receipts_per_pass: u64,
    holder: Option<(EntityId, u64)>,
) -> Result<()> {
    use std::io::Cursor;
    let raw = crate::gate::default_policy_manifest().unwrap();
    let mut manifest = rmpv::decode::read_value(&mut Cursor::new(raw)).expect("shipped manifest");
    let Value::Map(entries) = &mut manifest else {
        panic!("manifest map")
    };
    let (_, limits) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("attribution_limits"))
        .expect("shipped attribution limits row");
    let mut rows = vec![
        (Value::from("precedence"), Value::from("nested_narrowing")),
        (Value::from("reason_max_bytes"), Value::from(reason_bytes)),
        (
            Value::from("receipts_per_pass"),
            Value::from(receipts_per_pass),
        ),
    ];
    if let Some((actor, max_bytes)) = holder {
        rows.push((
            Value::from("holder_reason_bytes"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_ref"), Value::from(actor.to_hex())),
                (Value::from("max_bytes"), Value::from(max_bytes)),
            ])]),
        ));
    }
    *limits = Value::Map(rows);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &manifest).expect("encode manifest");
    crate::test_util::put_policy_manifest_bytes(vault, id, &encoded)
}

#[test]
fn policy_reason_budget_preserves_utf8_boundary_and_old_evidence() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let receipt = terminal(&vault, actor, true)?;
    // The old 1,024-byte engine limit would refuse this valid stated reason.
    let reason = "é".repeat(600); // 1,200 UTF-8 bytes, exactly the policy bound.
    install_attribution_limits(&vault, 1200, 1, Some((actor, 8192)))?;
    let row = OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 13)
        .with_skill(skill)
        .with_followed_state(FollowedState::DeviatedWithReason {
            reason,
            cause: Some(DeviationCause::IncorrectInstruction),
        });
    record_attribution_evidence(&vault, &row)?;
    let oversized = OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 13)
        .with_skill(skill)
        .with_followed_state(FollowedState::DeviatedWithReason {
            reason: "é".repeat(601),
            cause: Some(DeviationCause::IncorrectInstruction),
        });
    assert!(
        matches!(
            record_attribution_evidence(&vault, &oversized),
            Err(Error::InvalidClaimBody(_))
        ),
        "a holder override cannot widen the vault's 1,200-byte budget"
    );
    // Lowering current admission policy must not make a recorded reason
    // undecodable or silently reclassify evidence captured under the old row.
    install_attribution_limits(&vault, 500, 1, None)?;
    let stored = crate::skill_attribution::codec::evidence_after(&vault, 0)?;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].1.followed_state, row.followed_state);
    let judgments = run_attribution_projector(&vault, 0)?;
    assert_eq!(judgments.len(), 1);
    assert_eq!(judgments[0].verdict, AttributionVerdict::SkillDefect);
    Ok(())
}

#[test]
fn policy_work_budget_bounds_receipt_pages_not_valid_manifest_size() -> Result<()> {
    struct Source {
        actor: EntityId,
        skill: EntityId,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, _: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: FollowedState::Followed,
                skill_covered_step: true,
            }]))
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    terminal(&vault, actor, true)?;
    terminal(&vault, actor, true)?;
    install_attribution_limits(&vault, 2048, 1, None)?;
    let source = Source { actor, skill };
    let first = run_task_attribution_sweep(&vault, 16, &source)?;
    assert_eq!(first.scanned, 1);
    assert_eq!(first.captured_evidence, 1);
    let second = run_task_attribution_sweep(&vault, 16, &source)?;
    assert_eq!(second.scanned, 1);
    assert_eq!(second.captured_evidence, 1);
    Ok(())
}

#[test]
fn policy_limits_narrow_across_manifests_and_holder_cannot_widen_vault() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    install_attribution_limits(&vault, 1800, 16, Some((actor, 700)))?;
    install_attribution_limits_with_id(&vault, EntityId::now(), 900, 1, Some((actor, 8192)))?;
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    let limits = policy.attribution_limits().expect("trusted policy");
    assert_eq!(limits.reason_max_bytes, 900);
    assert_eq!(limits.receipts_per_pass, 1);
    assert_eq!(limits.reason_bytes_for(&actor), 700);
    assert_eq!(limits.reason_bytes_for(&EntityId::now()), 900);
    Ok(())
}

#[test]
fn vault_policy_can_raise_the_shipped_default_before_other_packs_narrow_it() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let receipt = terminal(&vault, actor, true)?;
    install_attribution_limits(&vault, 8192, 64, None)?;
    let reason = "reason ".repeat(700); // 4,900 bytes, above shipped default.
    let row = OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 13)
        .with_skill(skill)
        .with_followed_state(FollowedState::DeviatedWithReason {
            reason,
            cause: Some(DeviationCause::IncorrectInstruction),
        });
    record_attribution_evidence(&vault, &row)?;
    assert_eq!(
        crate::skill_attribution::codec::evidence_after(&vault, 0)?[0]
            .1
            .followed_state,
        row.followed_state
    );
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    let limits = policy.attribution_limits().expect("trusted policy");
    assert_eq!(limits.reason_max_bytes, 8192);
    assert_eq!(limits.receipts_per_pass, 64);
    Ok(())
}

#[test]
fn callable_sweep_projects_pair_claim_and_shared_selection_from_real_invocations() -> Result<()> {
    use crate::code_run::CodeRunDeterminism;
    use crate::engine_executor::{
        JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
        SelfDispatchResponse,
    };
    use crate::skill::{SkillCallContract, SkillRole, execute_callable_skill};
    use crate::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
    struct Runtime;
    impl JsCodeModeRuntime for Runtime {
        fn run_step(
            &mut self,
            _: JsCodeModeStep<'_>,
            _: &mut dyn JsCodeModeHost,
        ) -> Result<JsCodeModeStepOutcome> {
            Ok(JsCodeModeStepOutcome::complete("{\"value\":42}"))
        }
    }
    struct Host;
    impl JsCodeModeHost for Host {
        fn dispatch_self(&mut self, _: crate::code_run::SelfCall) -> Result<SelfDispatchResponse> {
            Err(Error::InvalidConfig("fixture has no host effects".into()))
        }
    }
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
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = EntityId::now();
    let files = vec![
        HubFile::new("SKILL.md", b"---\nname: fixture.callable-sweep\ndescription: callable fixture\nversion: 1\nrole: callable\ncall:\n  reference: scripts/run.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"value\":\"integer\"}\n---\nBody\n".to_vec()),
        HubFile::new("scripts/run.js", b"finish(JSON.stringify({value:skillArgs.value+1}));".to_vec()),
    ];
    let hash = crate::skill::canonical_skill_tree_hash(
        files
            .iter()
            .map(|f| (f.path.as_str(), f.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        "fixture.callable-sweep",
        "callable fixture",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: "scripts/run.js".into(),
            arguments: serde_json::json!({"value":"integer"}),
            returns: serde_json::json!({"value":"integer"}),
        }),
    )
    .with_content_hash(hash);
    let mut package = HubPackage::new(record.clone(), files, SkillCapabilitySurface::default());
    package.format = SkillPackageFormat::Native;
    vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, &skill, &record, at(1), 1)?;
        vault.persist_hub_package_in_txn(txn, &skill, &package)
    })?;
    let mut active = record;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&skill, &active, at(2), 2)?;
    let prior = skill_reliability_prior(&vault, &skill)?;
    let make_receipt = |executor: &str, now: u64, failed: bool| -> Result<String> {
        let queue = AttemptQueue::new(&vault);
        let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
            kind: "attribution.callable".into(),
            payload: vec![],
            dedupe_key: None,
            run_id: None,
            now,
        })?
        else {
            panic!("new callable attempt")
        };
        let ClaimOutcome::Claimed(leased) = queue.claim_kind(
            "attribution.callable",
            ClaimAttempt {
                lease_owner: "fixture-host".into(),
                now: now + 1,
            },
        )?
        else {
            panic!("leased callable attempt")
        };
        vault.bind_actor_attempt(row.id, &actor)?;
        execute_callable_skill(
            &vault,
            &leased,
            &skill,
            executor,
            &serde_json::json!({"value":41}),
            &mut Runtime,
            &mut Host,
            EntityId::now(),
            0,
            CodeRunDeterminism::new(1_700_000_000_000, [1; 32]),
            now + 2,
        )?;
        if failed {
            queue.fail(crate::attempt_queue::FailAttempt {
                id: row.id,
                lease_owner: "fixture-host".into(),
                attempt_count: leased.attempt_count,
                reason: "failed check".into(),
                now: now + 3,
            })?;
        } else {
            queue.complete(CompleteAttempt {
                id: row.id,
                lease_owner: "fixture-host".into(),
                attempt_count: leased.attempt_count,
                now: now + 3,
            })?;
        }
        Ok(attempt_pack_receipt_id(&row.id))
    };
    let mut source = Source {
        actor,
        skill,
        lapse: None,
    };
    let pair = |executor: &str| -> Result<crate::skill_reliability::SkillReliabilityPosterior> {
        Ok(skill_reliability_posterior_for_executor(&vault, &skill, executor)?.unwrap_or(prior))
    };
    let win = make_receipt("model-a@1", 10, false)?;
    run_task_attribution_sweep(&vault, 32, &source)?;
    let pair_a = pair("model-a@1")?;
    assert_eq!(pair_a.alpha, prior.alpha + 1.0);
    assert_eq!(pair("model-b@1")?, prior);
    assert!(
        crate::skill_reliability::attributed_outcome_receipts(
            &vault,
            &vault.store.env.read_txn()?,
            &skill
        )?
        .contains(&win)
    );
    let claims = vault.claims_for_subject(&skill)?;
    assert!(
        claims
            .iter()
            .filter_map(|id| vault.get_claim(id).ok().flatten())
            .any(
                |body| body.predicate == crate::skill_reliability::PREDICATE_SKILL_RELIABILITY
                    && body.lifecycle == crate::claim::ClaimLifecycleStatus::Active
                    && body
                        .value
                        .as_map()
                        .and_then(|entries| entries
                            .iter()
                            .find(|(key, _)| key.as_str() == Some("executor")))
                        .and_then(|(_, value)| value.as_str())
                        == Some("model-a@1")
                    && body
                        .evidence
                        .as_ref()
                        .and_then(Value::as_array)
                        .is_some_and(|e| e.iter().any(|v| v.as_str() == Some(win.as_str())))
            )
    );
    let defect = make_receipt("model-a@1", 20, true)?;
    run_task_attribution_sweep(&vault, 32, &source)?;
    assert_eq!(pair("model-a@1")?.beta, prior.beta + 1.0);
    source.lapse = Some(make_receipt("model-a@1", 30, true)?);
    let second = make_receipt("model-b@1", 40, false)?;
    run_task_attribution_sweep(&vault, 32, &source)?;
    assert_eq!(pair("model-a@1")?.beta, prior.beta + 1.0);
    assert_eq!(pair("model-b@1")?.alpha, prior.alpha + 1.0);
    let before = pair("model-a@1")?;
    run_task_attribution_sweep(&vault, 32, &source)?;
    assert_eq!(pair("model-a@1")?, before);
    assert!(
        crate::skill_reliability::attributed_outcome_receipts(
            &vault,
            &vault.store.env.read_txn()?,
            &skill
        )?
        .contains(&defect)
    );
    assert!(
        crate::skill_reliability::attributed_outcome_receipts(
            &vault,
            &vault.store.env.read_txn()?,
            &skill
        )?
        .contains(&second)
    );
    Ok(())
}

/// ARCH-0056 §5 #unclear (owner, 2026-10-08): a verdict the judge holds below
/// the `attribution_unclear_floor` setting (seeded at 0.6) is `unclear`. It
/// changes no reliability row and files exactly one row in the unclear ledger,
/// with the judge's note, for the Dreamer to cluster. The floor is a setting
/// row: once the owner pins it lower, the same confidence counts.
#[test]
fn an_unclear_verdict_changes_no_reliability_and_files_one_note() -> Result<()> {
    use crate::learning_setting::{
        ATTRIBUTION_UNCLEAR_FLOOR, SettingMode, SettingRow, put_setting_row, setting_value,
    };

    struct Source {
        actor: EntityId,
        skill: EntityId,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, _: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: FollowedState::Followed,
                skill_covered_step: true,
            }]))
        }
    }
    /// Leans to the skill's defect, but only at 0.4.
    struct Unsure;
    impl AttributionJudge for Unsure {
        fn judge(&self, _: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            Ok(Some(AttributionVerdict::SkillDefect))
        }
        fn judge_hunks(&self, request: &JudgeRequest<'_>) -> Result<Option<Vec<HunkVerdict>>> {
            assert!(request.hunks.is_empty(), "a failed attempt carries no edit");
            Ok(Some(vec![
                HunkVerdict::with_confidence(AttributionVerdict::SkillDefect, 0.4)
                    .with_note("the upstream API may have failed, not the skill"),
            ]))
        }
    }

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let source = Source { actor, skill };
    assert_eq!(setting_value(&vault, &ATTRIBUTION_UNCLEAR_FLOOR)?, 0.6);

    let receipt = terminal(&vault, actor, true)?;
    let report = run_task_attribution_sweep_with_judge(&vault, 16, &source, &Unsure)?;
    assert_eq!(report.captured_evidence, 1);
    assert_eq!(report.judgments, 0, "an unclear verdict charges nobody");
    assert!(attribution_judgments(&vault)?.is_empty());
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?,
        None,
        "no reliability row moves"
    );
    let filed = unclear_attributions(&vault)?;
    assert_eq!(filed.len(), 1, "one row in the unclear ledger");
    assert_eq!(filed[0].lane, AttributionLane::Attempt);
    assert_eq!(filed[0].evidence_receipts, vec![receipt]);
    assert_eq!(filed[0].notes.len(), 1);
    let note = &filed[0].notes[0];
    assert_eq!(note.reason, UnclearReason::BelowFloor);
    assert_eq!(note.leaning, Some(AttributionVerdict::SkillDefect));
    assert_eq!(
        note.note.as_deref(),
        Some("the upstream API may have failed, not the skill")
    );
    assert_eq!(filed[0].share(), 1.0, "the whole outcome holds");

    let pin = SettingRow {
        key: ATTRIBUTION_UNCLEAR_FLOOR.key.to_owned(),
        mode: SettingMode::Pin,
        value: 0.3,
        weight_runs: None,
        at: 200,
        why: "this judge is calibrated low".to_owned(),
    };
    // Seeds and pins are the owner's: an agent cannot move the floor.
    let agent = crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Agent);
    assert!(put_setting_row(&vault, &agent, &pin).is_err());
    assert_eq!(setting_value(&vault, &ATTRIBUTION_UNCLEAR_FLOOR)?, 0.6);
    let owner = crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Human);
    put_setting_row(&vault, &owner, &pin)?;
    assert_eq!(setting_value(&vault, &ATTRIBUTION_UNCLEAR_FLOOR)?, 0.3);
    let prior = skill_reliability_prior(&vault, &skill)?;
    terminal(&vault, actor, true)?;
    let report = run_task_attribution_sweep_with_judge(&vault, 16, &source, &Unsure)?;
    assert_eq!(
        report.judgments, 1,
        "above the pinned floor the defect counts"
    );
    let after =
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?.unwrap();
    assert_eq!(after.beta, prior.beta + 1.0);
    assert_eq!(
        unclear_attributions(&vault)?.len(),
        1,
        "a counted verdict files no note"
    );

    // Replaying the held evidence under the pinned floor settles it: the
    // outcome is judged now, so its note leaves the unclear ledger (Sol review,
    // 10-08: a replay used to leave both ledgers holding one outcome).
    run_attribution_projector_with_judge(&vault, 0, &Unsure)?;
    assert_eq!(attribution_judgments(&vault)?.len(), 2);
    assert!(unclear_attributions(&vault)?.is_empty());
    Ok(())
}

/// ARCH-0056 §5 #label-lanes: an outside fact can break an attempt, so
/// `environment` is a valid attempt-lane answer — it blames nobody and files
/// nothing. `preference_shift` is amendment-only: on a failed attempt it does
/// not fit, so it holds as `unclear` and leaves a note saying so.
#[test]
fn environment_fits_a_failed_attempt_and_taste_does_not() -> Result<()> {
    struct Source {
        actor: EntityId,
        skill: EntityId,
    }
    impl ReceiptAttributionSource for Source {
        fn facts(&self, _: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>> {
            Ok(Some(vec![ReceiptAttributionFacts {
                actor: self.actor,
                skill: Some(self.skill),
                followed_state: FollowedState::Followed,
                skill_covered_step: true,
            }]))
        }
    }
    struct Says(AttributionVerdict);
    impl AttributionJudge for Says {
        fn judge(&self, _: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            Ok(Some(self.0))
        }
    }

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, EntityId::now())?;
    let skill = put_skill(&vault, EntityId::now(), FIXTURE_SKILL_ID)?;
    let source = Source { actor, skill };

    terminal(&vault, actor, true)?;
    let report = run_task_attribution_sweep_with_judge(
        &vault,
        16,
        &source,
        &Says(AttributionVerdict::Environment),
    )?;
    assert_eq!(report.judgments, 0, "an outside fact blames nobody");
    assert!(
        unclear_attributions(&vault)?.is_empty(),
        "and is not unclear"
    );
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "fixture/model@1")?,
        None
    );

    terminal(&vault, actor, true)?;
    let report = run_task_attribution_sweep_with_judge(
        &vault,
        16,
        &source,
        &Says(AttributionVerdict::PreferenceShift),
    )?;
    assert_eq!(report.judgments, 0);
    let filed = unclear_attributions(&vault)?;
    assert_eq!(filed.len(), 1);
    assert_eq!(filed[0].notes[0].reason, UnclearReason::OutsideLane);
    assert_eq!(
        filed[0].notes[0].leaning,
        Some(AttributionVerdict::PreferenceShift)
    );
    Ok(())
}
