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
