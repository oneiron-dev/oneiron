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
