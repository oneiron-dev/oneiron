use super::*;
use crate::receipt::ReceiptRecord;
use crate::skill_reliability::{skill_reliability_posterior_for_executor, skill_reliability_prior};

fn terminal(vault: &Vault, actor: EntityId, failed: bool) -> Result<String> {
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
                followed_skill: self.lapse.as_deref() != Some(receipt.receipt_id.as_str()),
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
                followed_skill: self.lapse.as_deref() != Some(receipt.receipt_id.as_str()),
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
