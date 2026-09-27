use super::*;
use crate::skill_reliability::{
    project_skill_reliability, record_resident_skill_contributing_win,
    record_skill_contributing_win, skill_reliability_posterior,
};

fn resident_receipt(
    vault: &Vault,
    resident: &EntityId,
    skill: &EntityId,
    failed: bool,
) -> Result<String> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
        kind: "resident.skill.test".into(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("new attempt")
    };
    vault.load_resident_skill_pack(row.id, resident, skill, 11)?;
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "resident.skill.test",
        ClaimAttempt {
            lease_owner: "resident-test".into(),
            now: 12,
        },
    )?
    else {
        panic!("claim")
    };
    if failed {
        queue.fail(crate::attempt_queue::FailAttempt {
            id: row.id,
            lease_owner: "resident-test".into(),
            attempt_count: leased.attempt_count,
            reason: "failed".into(),
            now: 13,
        })?;
    } else {
        queue.complete(CompleteAttempt {
            id: row.id,
            lease_owner: "resident-test".into(),
            attempt_count: leased.attempt_count,
            now: 13,
        })?;
    }
    Ok(attempt_pack_receipt_id(&row.id))
}

fn scoped_receipt(
    vault: &Vault,
    resident: Option<&EntityId>,
    shared: Option<&EntityId>,
    failed: bool,
) -> Result<(crate::attempt_queue::AttemptId, String)> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
        kind: "resident.shared-skill".into(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 30,
    })?
    else {
        panic!("new attempt")
    };
    if let Some(resident) = resident {
        vault.bind_resident_attempt(row.id, resident)?;
    }
    if let Some(skill) = shared {
        vault.load_attempt_skill_pack(row.id, skill, 31)?;
    } else if resident.is_none() {
        // An unbound but stamped receipt: negative tests must not pass only
        // because the citation never existed.
        queue.append_manifest_entry(
            row.id,
            ManifestEntry::new(ManifestKind::SkillIndex, "index", "1", 31),
        )?;
    }
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "resident.shared-skill",
        ClaimAttempt {
            lease_owner: "resident-shared".into(),
            now: 32,
        },
    )?
    else {
        panic!("claim")
    };
    if failed {
        queue.fail(crate::attempt_queue::FailAttempt {
            id: row.id,
            lease_owner: "resident-shared".into(),
            attempt_count: leased.attempt_count,
            reason: "failed".into(),
            now: 33,
        })?;
    } else {
        queue.complete(CompleteAttempt {
            id: row.id,
            lease_owner: "resident-shared".into(),
            attempt_count: leased.attempt_count,
            now: 33,
        })?;
    }
    Ok((row.id, attempt_pack_receipt_id(&row.id)))
}

#[test]
fn attribution_and_self_model_do_not_cross_resident_forks() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let a = put_actor(&vault, EntityId::now())?;
    let b = put_actor(&vault, EntityId::now())?;
    let base = EntityId::now();
    let parent = SkillRecord::new(
        "resident.shared",
        "shared instructions",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    );
    vault.put_skill_record(&base, &parent, at(1), 1)?;
    let mut active = parent;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&base, &active, at(2), 2)?;
    let a_skill = EntityId::now();
    let b_skill = EntityId::now();
    for (resident, skill, name) in [(a, a_skill, "resident.a"), (b, b_skill, "resident.b")] {
        let mut fork = vault.fork_skill_for_resident(&resident, &base, &skill, name, at(20), 20)?;
        fork.lifecycle_status = SkillLifecycle::Active;
        vault.update_skill_record(&skill, &fork, at(21), 21)?;
    }
    let a_receipt = resident_receipt(&vault, &a, &a_skill, true)?;
    let b_receipt = resident_receipt(&vault, &b, &b_skill, true)?;
    // A resident may not charge its failed attempt to another resident's fork.
    assert!(
        record_attribution_evidence(
            &vault,
            &evidence(&b_receipt, a, b_skill, AttemptOutcome::Failed, true, true,)
        )
        .is_err()
    );
    // Nor may it charge the shared parent or a different revision's receipt.
    assert!(
        record_attribution_evidence(
            &vault,
            &evidence(&b_receipt, b, a_skill, AttemptOutcome::Failed, true, true,)
        )
        .is_err()
    );
    record_attribution_evidence(
        &vault,
        &evidence(&a_receipt, a, a_skill, AttemptOutcome::Failed, true, true),
    )?;
    record_attribution_evidence(
        &vault,
        &evidence(&b_receipt, b, b_skill, AttemptOutcome::Failed, false, true),
    )?;
    assert!(
        crate::actor_claims::write_actor_claim(
            &vault,
            crate::actor_claims::ActorClaimRow::SkillFit {
                actor: a,
                skill: b_skill,
                fit: 0.5
            },
            &crate::actor_claims::ActorClaimEvidence::task(vec![a_receipt], 25)?,
        )
        .is_err()
    );
    assert!(
        crate::actor_claims::write_actor_claim(
            &vault,
            crate::actor_claims::ActorClaimRow::Lesson {
                actor: a,
                text: "check".into()
            },
            &crate::actor_claims::ActorClaimEvidence::task(vec![b_receipt], 25)?,
        )
        .is_err()
    );
    let judgments = run_attribution_projector(&vault, 0)?;
    assert_eq!(judgments.len(), 2);
    assert_eq!(judgments[0].subject, a_skill);
    assert_eq!(judgments[1].subject, b);
    assert_eq!(
        project_skill_reliability(&vault, &judgments)?,
        vec![a_skill]
    );
    assert_eq!(skill_reliability_posterior(&vault, &b_skill)?, None);
    assert_eq!(skill_reliability_posterior(&vault, &base)?, None);
    crate::actor_claims::project_actor_claims_from_judgments(&vault, &judgments)?;
    assert!(vault.claims_for_subject(&a)?.iter().all(|id| {
        vault
            .get_claim(id)
            .expect("read")
            .is_none_or(|body| body.predicate != crate::actor_claims::PREDICATE_ACTOR_FAILURE_MODE)
    }));
    assert!(vault.claims_for_subject(&b)?.iter().any(|id| {
        vault
            .get_claim(id)
            .expect("read")
            .is_some_and(|body| body.predicate == crate::actor_claims::PREDICATE_ACTOR_FAILURE_MODE)
    }));
    let win = resident_receipt(&vault, &a, &a_skill, false)?;
    assert!(record_skill_contributing_win(&vault, &a_skill, &win, 30).is_err());
    assert!(record_resident_skill_contributing_win(&vault, &b, &a_skill, &win, 30).is_err());
    record_resident_skill_contributing_win(&vault, &a, &a_skill, &win, 30)?;
    assert_eq!(skill_reliability_posterior(&vault, &b_skill)?, None);
    Ok(())
}

#[test]
fn shared_and_skillless_receipts_cannot_cross_or_skip_resident_ownership() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let a = put_actor(&vault, EntityId::now())?;
    let b = put_actor(&vault, EntityId::now())?;
    // First use, before either actor has a fork or a bound attempt: a real
    // unbound receipt cannot be assigned to either resident by assertion.
    let (_, first_unbound) = scoped_receipt(&vault, None, None, true)?;
    assert!(crate::receipt::attempt_pack_receipt(&vault, &first_unbound)?.is_some());
    for actor in [a, b] {
        assert!(
            record_attribution_evidence(
                &vault,
                &OutcomeEvidence::new(&first_unbound, actor, AttemptOutcome::Failed, 35)
                    .with_routing_facts(false, true)
            )
            .is_err()
        );
        assert!(
            crate::actor_claims::write_actor_claim(
                &vault,
                crate::actor_claims::ActorClaimRow::Lesson {
                    actor,
                    text: "first use".into()
                },
                &crate::actor_claims::ActorClaimEvidence::task(vec![first_unbound.clone()], 35)?,
            )
            .is_err()
        );
    }
    let shared = EntityId::now();
    let record = SkillRecord::new(
        "resident.shared",
        "shared instructions",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    );
    vault.put_skill_record(&shared, &record, at(1), 1)?;
    let mut active = record;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&shared, &active, at(2), 2)?;
    // Both are registered residents; an unstamped terminal receipt never
    // becomes either diary's evidence merely because its claimant says so.
    for resident in [a, b] {
        let fork = EntityId::now();
        vault.fork_skill_for_resident(
            &resident,
            &shared,
            &fork,
            &format!("resident.{}", resident.to_hex()),
            at(3),
            3,
        )?;
    }
    let (attempt, shared_receipt) = scoped_receipt(&vault, Some(&a), Some(&shared), true)?;
    assert!(
        vault.bind_resident_attempt(attempt, &b).is_err(),
        "closed attempt is immutable"
    );
    assert!(
        record_attribution_evidence(
            &vault,
            &evidence(
                &shared_receipt,
                b,
                shared,
                AttemptOutcome::Failed,
                true,
                true
            )
        )
        .is_err()
    );
    assert!(
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(&shared_receipt, b, AttemptOutcome::Failed, 35)
                .with_routing_facts(false, true)
        )
        .is_err()
    );
    record_attribution_evidence(
        &vault,
        &evidence(
            &shared_receipt,
            a,
            shared,
            AttemptOutcome::Failed,
            true,
            true,
        ),
    )?;
    let (_, shared_win) = scoped_receipt(&vault, Some(&a), Some(&shared), false)?;
    assert!(
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(&shared_win, b, AttemptOutcome::Succeeded, 35)
                .with_skill(shared)
                .with_routing_facts(true, true)
        )
        .is_err()
    );
    let (_, skillless) = scoped_receipt(&vault, Some(&a), None, true)?;
    assert!(
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(&skillless, b, AttemptOutcome::Failed, 35)
                .with_routing_facts(false, true)
        )
        .is_err()
    );
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&skillless, a, AttemptOutcome::Failed, 35)
            .with_routing_facts(false, true),
    )?;
    let (_, unbound) = scoped_receipt(&vault, None, None, true)?;
    assert!(crate::receipt::attempt_pack_receipt(&vault, &skillless)?.is_some());
    assert!(crate::receipt::attempt_pack_receipt(&vault, &unbound)?.is_some());
    for resident in [a, b] {
        assert!(
            record_attribution_evidence(
                &vault,
                &OutcomeEvidence::new(&unbound, resident, AttemptOutcome::Failed, 35)
                    .with_routing_facts(false, true)
            )
            .is_err()
        );
        assert!(
            crate::actor_claims::write_actor_claim(
                &vault,
                crate::actor_claims::ActorClaimRow::Lesson {
                    actor: resident,
                    text: "check".into()
                },
                &crate::actor_claims::ActorClaimEvidence::task(vec![unbound.clone()], 35)?,
            )
            .is_err()
        );
    }
    assert!(
        crate::actor_claims::write_actor_claim(
            &vault,
            crate::actor_claims::ActorClaimRow::Lesson {
                actor: b,
                text: "check".into()
            },
            &crate::actor_claims::ActorClaimEvidence::task(vec![shared_receipt], 35)?,
        )
        .is_err()
    );
    Ok(())
}
