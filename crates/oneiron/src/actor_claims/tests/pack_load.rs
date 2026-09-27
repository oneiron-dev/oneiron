use super::*;
use crate::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};

#[test]
fn terminal_receipt_keeps_index_pull_and_actor_claim_in_load_order() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "pack.loaded")?;
    let claim = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "read the source".to_owned(),
        },
        &task_evidence(&vault, 30),
    )?;
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatcher.dispatch_default_base(
        None,
        Some("pack-run".to_owned()),
        Some("pack-run".to_owned()),
        40,
    )?
    else {
        panic!("new dispatch")
    };
    assert_eq!(status.attempt.manifest.len(), 1);
    assert_eq!(status.attempt.manifest[0].kind, ManifestKind::SkillIndex);
    let AgentDispatchOutcome::Existing(existing) = dispatcher.dispatch_default_base(
        None,
        Some("pack-run".to_owned()),
        Some("pack-run".to_owned()),
        40,
    )?
    else {
        panic!("deduped dispatch")
    };
    assert_eq!(existing.attempt.manifest, status.attempt.manifest);
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "dreamer",
        ClaimAttempt {
            lease_owner: "pack-worker".to_owned(),
            now: 41,
        },
    )?
    else {
        panic!("claim dispatch")
    };
    let loaded = vault.load_attempt_skill(
        status.attempt.id,
        &skill,
        "pack-worker",
        leased.attempt_count,
        "fixture/model@1",
        41,
    )?;
    assert_eq!(loaded.skill_id, "pack.loaded");
    assert_eq!(
        vault
            .load_attempt_actor_claim(status.attempt.id, &claim, 42)?
            .predicate,
        PREDICATE_ACTOR_LESSON
    );
    queue.complete(CompleteAttempt {
        id: leased.id,
        lease_owner: "pack-worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 44,
    })?;
    let receipt =
        crate::receipt::attempt_pack_receipt(&vault, &attempt_pack_receipt_id(&leased.id))?
            .unwrap();
    let entries = receipt.pack_manifest_entries().unwrap();
    assert_eq!(
        entries.iter().map(|entry| entry.kind).collect::<Vec<_>>(),
        vec![
            ManifestKind::SkillIndex,
            ManifestKind::Skill,
            ManifestKind::ActorClaim
        ]
    );
    assert_eq!(
        entries.iter().map(|entry| entry.at).collect::<Vec<_>>(),
        vec![40, 41, 42]
    );
    assert_eq!(entries[2].reference, claim.to_hex());
    assert_eq!(entries, queue.get(leased.id)?.unwrap().manifest);
    assert_eq!(
        receipt.pack_manifest_skills(),
        Some(vec!["pack.loaded@1.0.0".to_owned()])
    );
    assert!(
        vault
            .load_attempt_skill(
                leased.id,
                &skill,
                "pack-worker",
                leased.attempt_count,
                "fixture/model@1",
                45
            )
            .is_err()
    );
    assert_eq!(
        crate::receipt::attempt_pack_receipt(&vault, &receipt.receipt_id)?.unwrap(),
        receipt
    );
    Ok(())
}

#[test]
fn real_skill_load_credits_only_the_executor_that_ran_each_slice_and_rerun() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill = put_skill(&vault, "pack.swap")?;
    let queue = AttemptQueue::new(&vault);
    let prior = crate::skill_reliability::skill_reliability_prior(&vault, &skill)?;
    for model in ["old@1", "new@2", "new@2"] {
        let crate::attempt_queue::EnqueueOutcome::Enqueued(attempt) =
            queue.enqueue(crate::attempt_queue::EnqueueAttempt {
                kind: "pack.model-run".to_owned(),
                payload: vec![],
                dedupe_key: None,
                run_id: None,
                now: 50,
            })?
        else {
            panic!("fresh run")
        };
        assert!(
            vault
                .load_attempt_skill_pack(attempt.id, &skill, "model-worker", 1, model, 50,)
                .is_err(),
            "a queued attempt cannot load a model-driven skill"
        );
        assert!(queue.get(attempt.id)?.unwrap().manifest.is_empty());
        let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
            lease_owner: "model-worker".to_owned(),
            now: 51,
        })?
        else {
            panic!("leased")
        };
        // The production load atomically binds the executor and skill bytes.
        vault.load_attempt_skill_pack(
            attempt.id,
            &skill,
            "model-worker",
            leased.attempt_count,
            model,
            52,
        )?;
        assert!(
            vault
                .load_attempt_skill_pack(
                    attempt.id,
                    &skill,
                    "stale-worker",
                    leased.attempt_count,
                    model,
                    52,
                )
                .is_err()
        );
        queue.complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "model-worker".to_owned(),
            attempt_count: leased.attempt_count,
            now: 53,
        })?;
        let receipt_id = attempt_pack_receipt_id(&attempt.id);
        let receipt = crate::receipt::attempt_pack_receipt(&vault, &receipt_id)?.unwrap();
        assert_eq!(receipt.fields.get("model").map(String::as_str), Some(model));
        crate::skill_reliability::record_skill_contributing_win(&vault, &skill, &receipt_id, 54)?;
        crate::skill_reliability::project_skill_reliability_for_executor(
            &vault, &skill, model, 55,
        )?;
    }
    let old = crate::skill_reliability::skill_executor_reliability(&vault, &skill, "old@1")?;
    let new = crate::skill_reliability::skill_executor_reliability(&vault, &skill, "new@2")?;
    assert_eq!(old.runs, 1);
    assert_eq!(old.posterior.alpha, prior.alpha + 1.0);
    assert_eq!(new.runs, 2);
    assert_eq!(new.posterior.alpha, prior.alpha + 2.0);
    assert_eq!(
        crate::skill_reliability::skill_executor_reliability(&vault, &skill, "new@3")?.runs,
        0
    );
    Ok(())
}
