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
    let raw = crate::gate::default_policy_manifest();
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
            reason: reason.clone(),
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
            reason: reason.clone(),
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
