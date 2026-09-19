use super::*;
use crate::receipt::ReceiptRecord;
use crate::skill_reliability::{skill_reliability_posterior, skill_reliability_prior};

fn terminal(vault: &Vault, failed: bool) -> Result<String> {
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
    queue.append_manifest_entry(
        row.id,
        ManifestEntry::new(ManifestKind::Skill, FIXTURE_SKILL_ID, "1.0.0", 11),
    )?;
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
                followed_skill: self.lapse.as_deref() != Some(receipt.receipt_id.as_str()),
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
    let failures: Vec<_> = vault
        .claims_for_subject(&actor)?
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).transpose())
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|body| body.predicate == crate::actor_claims::PREDICATE_ACTOR_FAILURE_MODE)
        .collect();
    assert_eq!(failures.len(), 1);
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
