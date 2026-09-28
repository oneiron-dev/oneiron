//! Recipe read, trust and commit-to-settlement recovery regressions.
use super::*;
use crate::attempt_queue::{AttemptQueue, AttemptState, CleanupAttemptLeases};
use crate::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_hub::HubFile;
use crate::store::GateDecisionId;
use std::cell::Cell;
use std::rc::Rc;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    subject: EntityId,
    evidence: EntityId,
    skill: EntityId,
    attempt: DreamerAdmittedAttempt,
}

fn time(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

fn turn(text: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(
        &mut bytes,
        &Value::Map(vec![
            ("txt".into(), text.into()),
            ("spkr".into(), "user".into()),
        ]),
    )
    .map_err(|_| invalid())?;
    Ok(bytes)
}

impl Fixture {
    fn new(read_grant: Option<EdgeActorClass>) -> Result<Self> {
        Self::new_with_claim(read_grant, None)
    }
    fn new_with_claim(
        read_grant: Option<EdgeActorClass>,
        claim_source: Option<(ClaimSource, ClaimSource)>,
    ) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
        crate::test_util::provision_engine_machines(&vault);
        let actor = vault.dreamer_authority()?;
        let agent = EntityId::now();
        let owner = EntityId::now();
        let subject = EntityId::now();
        let evidence = EntityId::now();
        for id in [agent, owner, subject] {
            vault.put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                time(1),
                1,
                b"fixture person",
            )?;
        }
        if let Some((source, taint)) = claim_source {
            let observed = source == ClaimSource::Observed && taint == ClaimSource::ToolOutput;
            let mut claim = ClaimBody::new(
                if observed {
                    "actor.scope_note"
                } else {
                    "profile.source"
                },
                ClaimSubject::Entity(subject),
                "retained claim evidence".into(),
                if observed { 1.0 } else { 0.9 },
                if observed {
                    ClaimApprovalStatus::Auto
                } else {
                    ClaimApprovalStatus::Approved
                },
                ClaimLifecycleStatus::Active,
            )?;
            claim.source = Some(source);
            claim.scope = Some(Value::Map(vec![(
                "evidence_taint".into(),
                taint.as_str().into(),
            )]));
            if observed {
                claim.evidence = Some(Value::Map(vec![("grounded".into(), true.into())]));
            }
            vault
                .batch()
                .put_replicated(
                    &evidence,
                    ENTITY_TYPE_CLAIM,
                    time(1),
                    1,
                    &crate::claim::encode_claim_body(&claim)?,
                )
                .commit()?;
        } else {
            vault.put_entity(
                &evidence,
                ENTITY_TYPE_TURN,
                time(1),
                1,
                &turn("retained evidence")?,
            )?;
        }
        if let Some(class) = read_grant {
            let granted = match class {
                EdgeActorClass::System => actor,
                EdgeActorClass::Agent => WriteActor::new(agent, class),
                _ => return Err(invalid()),
            };
            vault.install_read_permit_for_test(granted)?;
        }
        let skill = EntityId::now();
        let proposal = SkillRecord::new(
            "weave.recipe",
            "One owner-admitted weave",
            "v1",
            ClaimApprovalStatus::Proposed,
            SkillLifecycle::Candidate,
            ClaimSource::Generated,
            0.5,
            true,
            false,
            Vec::new(),
            Value::Map(vec![("asked".into(), true.into())]),
        );
        vault
            .memory(agent, EdgeActorClass::Agent)
            .skill_save_with_source(
                skill,
                &proposal,
                vec![HubFile::new(
                    "SKILL.md",
                    b"---\nname: weave.recipe\n---\nDraft from evidence.\n",
                )],
                None,
                2,
            )
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        let owner =
            vault.authenticate_owner(owner, "principal:recipe", true, GateDecisionId::now())?;
        vault.admit_and_enqueue_weave_recipe(&owner, skill, subject, evidence, 3)?;
        let outcome =
            DreamerRunnerStore::new(&vault).admit_next_weave_recipe(AdmitDreamerAttempt {
                lease_owner: "worker".into(),
                now: 4,
                budget_id: "wake".into(),
                budget_total_units: 1_000,
                reserve_units: 100,
                started_milestone: None,
            })?;
        let DreamerAdmissionOutcome::Admitted(attempt) = outcome else {
            return Err(invalid());
        };
        Ok(Self {
            _dir: dir,
            vault,
            subject,
            evidence,
            skill,
            attempt: *attempt,
        })
    }
    fn run(&self, runtime: &mut CountingRuntime) -> Result<DreamerAttemptExecution> {
        let mut executor = WeaveRecipeExecutor {
            inner: Unreachable,
            runtime,
        };
        let deadline = crate::dreamer_wake::WakePassDeadline::new(180_000);
        crate::dreamer_wake::block_on_ready(executor.execute(
            &self.attempt,
            &mut WakeAttemptContext {
                vault: &self.vault,
                deadline: &deadline,
                budget_id: "wake",
                now_ms: 5_000,
                prepared_wake: None,
                prepared_attempt: None,
            },
        ))
    }
    fn output(&self) -> Result<ClaimBody> {
        self.vault
            .get_claim(&claim_id(&self.attempt)?)?
            .ok_or_else(invalid)
    }
}

struct Unreachable;
impl DreamerAttemptExecutor for Unreachable {
    async fn execute(
        &mut self,
        _: &DreamerAdmittedAttempt,
        _: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        panic!("recipe went to ordinary executor")
    }
}
struct CountingRuntime {
    calls: Rc<Cell<u32>>,
    panic: bool,
}
impl CountingRuntime {
    fn new() -> Self {
        Self {
            calls: Rc::new(Cell::new(0)),
            panic: false,
        }
    }
}
impl WeaveRecipeRuntime for CountingRuntime {
    fn executor(&self) -> Result<&str> {
        Ok("counting-runtime@1")
    }
    fn draft(&mut self, _: &str, _: &[u8]) -> Result<WeaveRecipeDraft> {
        if self.panic {
            panic!("a settled recipe must not run the interpreter");
        }
        self.calls.set(self.calls.get() + 1);
        Ok(WeaveRecipeDraft {
            predicate: "profile.weave_note".into(),
            value: "derived note".into(),
            confidence: 0.8,
        })
    }
}

#[test]
fn read_grant_is_live_and_bound_to_the_system_class() -> Result<()> {
    for grant in [None, Some(EdgeActorClass::Agent)] {
        let fixture = Fixture::new(grant)?;
        let mut runtime = CountingRuntime::new();
        assert!(fixture.run(&mut runtime).is_err());
        assert_eq!(runtime.calls.get(), 0);
        assert!(
            fixture
                .vault
                .get_claim(&claim_id(&fixture.attempt)?)?
                .is_none()
        );
    }
    let fixture = Fixture::new(Some(EdgeActorClass::System))?;
    // The owner may revoke the scoped grant after admission. Neither the
    // cached policy frontier nor the queued skill grants evidence access.
    crate::test_util::put_policy_manifest_bytes(
        &fixture.vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest()?,
    )?;
    let mut runtime = CountingRuntime::new();
    assert!(fixture.run(&mut runtime).is_err());
    assert_eq!(runtime.calls.get(), 0);
    Ok(())
}

#[test]
fn committed_result_resumes_without_runtime_skill_or_evidence() -> Result<()> {
    let fixture = Fixture::new(Some(EdgeActorClass::System))?;
    let mut runtime = CountingRuntime::new();
    assert_eq!(
        fixture.run(&mut runtime)?,
        DreamerAttemptExecution::Completed { completed_units: 0 }
    );
    let initial = fixture.output()?;
    let decision_count = fixture.vault.store.gate_decisions(1_000)?.len();
    assert_eq!(runtime.calls.get(), 1);
    // Simulate crash before queue completion, then let the ordinary lease
    // cleanup and wake driver re-admit the SAME attempt id.
    let current = AttemptQueue::new(&fixture.vault)
        .get(fixture.attempt.status.attempt.id)?
        .ok_or_else(invalid)?;
    let now = current.updated_at.saturating_add(20);
    let report = AttemptQueue::new(&fixture.vault).cleanup_leases(CleanupAttemptLeases {
        now,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(
        report.stale_requeued, 1,
        "state={:?} updated_at={} now={}",
        current.state, current.updated_at, now
    );
    let mut stale = fixture
        .vault
        .get_skill_record(&fixture.skill)?
        .ok_or_else(invalid)?;
    stale.lifecycle_status = SkillLifecycle::Stale;
    fixture
        .vault
        .update_skill_record(&fixture.skill, &stale, time(now + 1), now + 1)?;
    fixture.vault.delete_entity(&fixture.evidence)?;
    let mut worker = WeaveRecipeExecutor {
        inner: Unreachable,
        runtime: CountingRuntime {
            calls: runtime.calls.clone(),
            panic: true,
        },
    };
    let mut driver = crate::dreamer_wake::DreamerWakeDriver::new(
        &fixture.vault,
        "wake",
        crate::dreamer_wake::WakePassDeadline::new(180_000),
    );
    let report = crate::dreamer_wake::block_on_ready(driver.run_wake_pass(
        crate::dreamer_wake::RunWakePass {
            trigger: crate::dreamer_wake::WakeTrigger::Event,
            scope: crate::dreamer_runner::DreamerConsolidationScope::Micro,
            local_node_id: 1,
            lease_owner: "recovered".into(),
            budget_total_units: 1_000,
            reserve_units: 100,
            now: now + 2,
            host_scope: None,
        },
        &mut worker,
        &crate::dreamer_wake::WakeCancellation::new(),
    ))?;
    assert_eq!(report.completed, 1);
    assert_eq!(runtime.calls.get(), 1);
    assert_eq!(fixture.output()?, initial);
    assert_eq!(
        fixture.vault.store.gate_decisions(1_000)?.len(),
        decision_count
    );
    let row = DreamerRunnerStore::new(&fixture.vault)
        .status(fixture.attempt.status.attempt.id)?
        .ok_or_else(invalid)?;
    assert_eq!(row.attempt.state, AttemptState::Completed);
    Ok(())
}

#[test]
fn a_colliding_claim_without_a_result_cannot_satisfy_retry() -> Result<()> {
    let fixture = Fixture::new(Some(EdgeActorClass::System))?;
    let id = claim_id(&fixture.attempt)?;
    let forged = ClaimBody::new(
        "profile.weave_note",
        ClaimSubject::Entity(fixture.subject),
        "forged".into(),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    fixture
        .vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            time(5),
            5,
            &crate::claim::encode_claim_body(&forged)?,
        )
        .commit()?;
    let mut runtime = CountingRuntime::new();
    assert!(fixture.run(&mut runtime).is_err());
    assert_eq!(runtime.calls.get(), 0);
    Ok(())
}

#[test]
fn recipe_persists_source_meet_and_transitive_taint() -> Result<()> {
    for (source, taint, expected) in [
        (
            ClaimSource::Imported,
            ClaimSource::Imported,
            ClaimSource::Imported,
        ),
        (
            ClaimSource::ToolOutput,
            ClaimSource::ToolOutput,
            ClaimSource::ToolOutput,
        ),
        (
            ClaimSource::UserStated,
            ClaimSource::UserStated,
            ClaimSource::Generated,
        ),
        (
            ClaimSource::Observed,
            ClaimSource::Observed,
            ClaimSource::Generated,
        ),
        (
            ClaimSource::Inferred,
            ClaimSource::Inferred,
            ClaimSource::Generated,
        ),
        // A valid engine-owned actor claim records observation origin beside
        // a lower-trust ancestry. The recipe must not erase that ancestry.
        (
            ClaimSource::Observed,
            ClaimSource::ToolOutput,
            ClaimSource::ToolOutput,
        ),
    ] {
        let fixture = Fixture::new_with_claim(Some(EdgeActorClass::System), Some((source, taint)))?;
        let mut runtime = CountingRuntime::new();
        assert_eq!(
            fixture.run(&mut runtime)?,
            DreamerAttemptExecution::Completed { completed_units: 0 }
        );
        assert_eq!(runtime.calls.get(), 1);
        let body = fixture.output()?;
        assert_eq!(body.source, Some(expected));
        assert_eq!(claim_evidence_taint(&body), Some(expected));
        let Value::Map(entries) = body.evidence.as_ref().ok_or_else(invalid)? else {
            return Err(invalid());
        };
        let cited = entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some("candidate_evidence")).then_some(value))
            .ok_or_else(invalid)?;
        let decoded = crate::dreamer_consolidation::decode_consolidation_evidence(cited)?
            .ok_or_else(invalid)?;
        assert_eq!(decoded.refs, [fixture.evidence]);
        assert_eq!(decoded.source_meet, expected);
        assert_eq!(
            crate::claim::claim_evidence_admissible(&body),
            expected != ClaimSource::Generated,
        );
        // The emitted CLAIM retains the class even when cited on a later pass.
        assert_eq!(
            crate::dreamer_consolidation::evidence_chain_source(
                &fixture.vault,
                &[],
                &[claim_id(&fixture.attempt)?]
            )?,
            expected
        );
    }
    Ok(())
}

struct ChangingEvidence<'a> {
    vault: &'a Vault,
    evidence: EntityId,
}
impl WeaveRecipeRuntime for ChangingEvidence<'_> {
    fn executor(&self) -> Result<&str> {
        Ok("changing-evidence@1")
    }
    fn draft(&mut self, _: &str, _: &[u8]) -> Result<WeaveRecipeDraft> {
        self.vault.put_entity(
            &self.evidence,
            ENTITY_TYPE_TURN,
            time(6),
            6,
            &turn("a later revision")?,
        )?;
        Ok(WeaveRecipeDraft {
            predicate: "profile.weave_note".into(),
            value: "stale answer".into(),
            confidence: 0.8,
        })
    }
}

#[test]
fn changed_source_between_draft_and_commit_refuses_the_write() -> Result<()> {
    let fixture = Fixture::new(Some(EdgeActorClass::System))?;
    let mut worker = WeaveRecipeExecutor {
        inner: Unreachable,
        runtime: ChangingEvidence {
            vault: &fixture.vault,
            evidence: fixture.evidence,
        },
    };
    let deadline = crate::dreamer_wake::WakePassDeadline::new(180_000);
    let result = crate::dreamer_wake::block_on_ready(worker.execute(
        &fixture.attempt,
        &mut WakeAttemptContext {
            vault: &fixture.vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 5_000,
            prepared_wake: None,
            prepared_attempt: None,
        },
    ));
    assert!(result.is_err());
    assert!(
        fixture
            .vault
            .get_claim(&claim_id(&fixture.attempt)?)?
            .is_none()
    );
    Ok(())
}

#[test]
fn changed_committed_result_does_not_resolve_a_crashed_try() -> Result<()> {
    let fixture = Fixture::new(Some(EdgeActorClass::System))?;
    let mut runtime = CountingRuntime::new();
    fixture.run(&mut runtime)?;
    // No write door replaces the Dreamer's signed claim, so the committed
    // result's record is what changes.
    let attempt = fixture.attempt.status.attempt.id;
    fixture.vault.with_write_txn(|txn| {
        let mut result = RESULT
            .get(&fixture.vault.store, &*txn, &attempt)?
            .ok_or_else(invalid)?;
        result.claim_hash = [0xAB; 32];
        RESULT.put(&fixture.vault.store, txn, &attempt, &result)
    })?;
    runtime.panic = true;
    assert!(fixture.run(&mut runtime).is_err());
    assert_eq!(
        runtime.calls.get(),
        1,
        "a corrupted cached result never reruns the interpreter"
    );
    Ok(())
}
