//! Engine-level proofs of the weave recipe's promises (FIX [WEAVE-PROMISES-UNPROVEN-AT-DOOR]).
//!
//! The served door tests (`crates/oneiron-server/tests/vault_weave_doors.rs`) prove the HTTP
//! boundary only: admission and parking, because the server supplies no weave interpreter. These
//! tests drive the engine's own recipe executor (`WeaveRecipeExecutor`) with a scripted
//! interpreter, on the public paths an agent-authored recipe takes: the agent saves a Candidate
//! skill, the owner admits it, the System Dreamer leases and runs it.
//! - P1, ARCH-0026 (canon mirror llms-full.txt:343332): "A weave recipe without a live System
//!   read grant is refused before it runs." A read row the owner removed, bound to the agent
//!   class, or emptied of scope before the admission, and a row the owner removes after it, each
//!   refuse the recipe before the interpreter drafts.
//! - ND-040, resume (ARCH-0026 :343324, "resumes across process restarts"): a committed result
//!   settles after a lost lease with no interpreter, a Stale skill and deleted evidence, and
//!   writes nothing again.
//! - ND-040, changed source (ARCH-0026 :343324, derived claims land "with provenance"): a source
//!   edited between the draft and its commit refuses the write.
//! - ARCH-0073 §6, "a re-mention restores the archived record" (FIX
//!   DREAMER-DIRECT-CLAIM-WRITERS-LAND-ON-ARCHIVED-PERSON): an output about a subject PERSON the
//!   vault cleanup archived after the admission restores her in the output's own write.
//!
//! The two ND-040 tests port the quarantined unit tests of `src/dreamer_wake/recipe/tests.rs`
//! (FIX [LIBTEST-QUARANTINE-DREAMER-WAKE-RECIPE-TESTS]) onto public paths. P2 (llms-full.txt
//! :346026, "The weave re-derives arcs from retained spans") is not claimed here: on this head an
//! Arc derives from closed sittings' summary lines (`scope_summary::arc`), not from the weave
//! recipe, which requests Scope summaries over retained conversations.
//!
//! Run on the fleet only: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test weave_recipe_promises`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::{AttemptQueue, AttemptState, CleanupAttemptLeases};
use oneiron::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource};
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use oneiron::dreamer_wake::{WeaveRecipeDraft, WeaveRecipeExecutor, WeaveRecipeRuntime};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::HubFile;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::{
    DreamerAttemptExecution, DreamerAttemptExecutor, DreamerConsolidationScope, DreamerWakeDriver,
    EdgeActorClass, EntityId, Error, Result, RunWakePass, TimeRange, Vault, WakeAttemptContext,
    WakeCancellation, WakePassDeadline, WakeTrigger,
};

/// The scripted interpreter's output predicate: no other writer in the fixture uses it.
const PREDICATE: &str = "profile.weave_note";
const BUDGET: &str = "weave-promises";
/// Gate receipts read per count; the fixture writes far fewer.
const RECEIPT_LIMIT: usize = 1_000;

fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

fn turn(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(
        &mut bytes,
        &rmpv::Value::Map(vec![
            ("txt".into(), text.into()),
            ("spkr".into(), "user".into()),
        ]),
    )
    .expect("encode the TURN fixture");
    bytes
}

/// Polls `future` to its end. The recipe executor never pends; a wake pass pends only at its
/// attempt-boundary self-wakes, so polling again at once is correct.
fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("the future pends on something other than an attempt-boundary yield");
}

/// How the owner leaves the Dreamer without a live read row.
#[derive(Clone, Copy, Debug)]
enum WithheldRead {
    /// The Dreamer's `core:read` row removed.
    Removed,
    /// The row bound to the agent class: the System Dreamer no longer matches it.
    AgentClass,
    /// The row's scope emptied: every axis denies.
    EmptyScope,
}

/// The owner's edit of the Dreamer's read row through the owner policy door, every other row
/// kept as it was.
fn withhold_dreamer_read(vault: &Vault, owner: EntityId, how: WithheldRead) -> Result<()> {
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let listed =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = listed
        .manifests
        .into_iter()
        .find(|view| view.manifest_ref == listed.default_manifest_ref)
        .expect("the fixture vault holds its default policy");
    let dreamer = vault.dreamer_authority()?.entity_ref().to_hex();
    let names_dreamer = |row: &PolicyScopedGrantRow| {
        row.actor_ref.as_deref() == Some(dreamer.as_str()) && row.effector == "core:read"
    };
    let mut manifest = default.manifest;
    let rows = manifest
        .scoped_grants
        .as_mut()
        .expect("the default policy has scoped grants");
    assert!(
        rows.iter().any(names_dreamer),
        "the fixture policy ships the Dreamer's read row"
    );
    match how {
        WithheldRead::Removed => rows.retain(|row| !names_dreamer(row)),
        WithheldRead::AgentClass => {
            for row in rows.iter_mut() {
                if names_dreamer(row) {
                    row.actor_class = Some("agent".to_owned());
                }
            }
        }
        WithheldRead::EmptyScope => {
            for row in rows.iter_mut() {
                if names_dreamer(row) {
                    row.scope = Default::default();
                }
            }
        }
    }
    put_policy_manifest_as_owner(
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref),
            expected_body_hash: Some(default.body_hash),
            manifest,
        },
    )?;
    Ok(())
}

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    subject: EntityId,
    evidence: EntityId,
    skill: EntityId,
    attempt: DreamerAdmittedAttempt,
}

impl Fixture {
    /// A vault with one retained TURN and an agent-authored recipe over it that the owner
    /// admitted, its attempt leased. `withheld` edits the Dreamer's read row before the
    /// admission.
    fn new(withheld: Option<WithheldRead>) -> Result<Self> {
        let dir = tempfile::tempdir().expect("tempdir");
        // The existing door: engine machines provisioned, the shipped policy with the
        // Dreamer's rows. No model is called.
        let vault = open_dreamer_vault(dir.path(), "weave-promises-reader")?;
        vault.dreamer_authority()?;
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let agent = EntityId::now();
        let subject = EntityId::now();
        let evidence = EntityId::now();
        for id in [agent, owner, subject] {
            vault.put_entity(&id, ENTITY_TYPE_PERSON, at(1), 1, b"fixture person")?;
        }
        vault.put_entity(
            &evidence,
            ENTITY_TYPE_TURN,
            at(1),
            1,
            &turn("retained evidence"),
        )?;
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
            rmpv::Value::Map(vec![("asked".into(), true.into())]),
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
            .expect("the agent authors the candidate recipe");
        if let Some(how) = withheld {
            withhold_dreamer_read(&vault, owner, how)?;
        }
        let proof =
            vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
        let queued = vault.admit_and_enqueue_weave_recipe(&proof, skill, subject, evidence, 3)?;
        assert!(
            matches!(queued, EnqueueDreamerAttemptOutcome::Enqueued(_)),
            "the owner's admission queues one recipe attempt: {queued:?}"
        );
        let admitted =
            DreamerRunnerStore::new(&vault).admit_next_weave_recipe(AdmitDreamerAttempt {
                lease_owner: "first-worker".into(),
                now: 4,
                budget_id: BUDGET.into(),
                budget_total_units: 1_000,
                reserve_units: 100,
                started_milestone: None,
            })?;
        let attempt = match admitted {
            DreamerAdmissionOutcome::Admitted(attempt) => *attempt,
            other => panic!("the fixture admits its recipe attempt: {other:?}"),
        };
        Ok(Self {
            vault,
            _dir: dir,
            owner,
            subject,
            evidence,
            skill,
            attempt,
        })
    }

    /// One direct run of the leased attempt through the recipe executor.
    fn execute<R: WeaveRecipeRuntime>(&self, runtime: &mut R) -> Result<DreamerAttemptExecution> {
        let mut executor = WeaveRecipeExecutor {
            inner: NoOrdinaryWork,
            runtime,
        };
        let deadline = WakePassDeadline::new(180_000);
        block_on_ready(executor.execute(
            &self.attempt,
            &mut WakeAttemptContext {
                vault: &self.vault,
                deadline: &deadline,
                cancel: None,
                device_cancel: None,
                budget_id: BUDGET,
                now_ms: 5_000,
                prepared_wake: None,
                prepared_attempt: None,
                spend_meter: None,
            },
        ))
    }

    /// The recipe's output claims on its subject.
    fn outputs(&self) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut outputs = Vec::new();
        for id in self.vault.claims_for_subject(&self.subject)? {
            if let Some(body) = self.vault.get_claim(&id)?
                && body.predicate == PREDICATE
            {
                outputs.push((id, body));
            }
        }
        Ok(outputs)
    }

    /// Gate receipts that name the recipe's output predicate.
    fn output_gate_count(&self) -> Result<usize> {
        let receipts = self
            .vault
            .receipts(ReceiptQuery::new(RECEIPT_LIMIT).with_kind(ReceiptKind::Gate))?;
        assert!(
            receipts.len() < RECEIPT_LIMIT,
            "the receipt read is not truncated"
        );
        Ok(receipts
            .iter()
            .filter(|row| row.fields.get("predicate").map(String::as_str) == Some(PREDICATE))
            .count())
    }
}

fn ids(outputs: &[(EntityId, ClaimBody)]) -> Vec<EntityId> {
    outputs.iter().map(|(id, _)| *id).collect()
}

/// The ordinary worker: every attempt in these fixtures is the recipe's.
struct NoOrdinaryWork;
impl DreamerAttemptExecutor for NoOrdinaryWork {
    async fn execute(
        &mut self,
        _: &DreamerAdmittedAttempt,
        _: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        panic!("the fixture dispatches only the weave recipe")
    }
}

/// A scripted interpreter that counts its drafts.
#[derive(Default)]
struct CountingRuntime {
    drafts: usize,
}
impl WeaveRecipeRuntime for CountingRuntime {
    fn executor(&self) -> Result<&str> {
        Ok("weave-promises@1")
    }
    fn draft(&mut self, _: &str, _: &[u8]) -> Result<WeaveRecipeDraft> {
        self.drafts += 1;
        Ok(WeaveRecipeDraft {
            predicate: PREDICATE.into(),
            value: "derived note".into(),
            confidence: 0.8,
        })
    }
}

/// ARCH-0026 (llms-full.txt:343332): "A weave recipe without a live System read grant is
/// refused before it runs." "Runs" is the interpreter's draft; its identity is read earlier, to
/// stamp the skill load. Each case starts from a fresh vault.
#[test]
fn recipe_without_a_live_system_read_grant_never_drafts_or_writes() -> Result<()> {
    let cases = [
        (Some(WithheldRead::Removed), None),
        (Some(WithheldRead::AgentClass), None),
        (Some(WithheldRead::EmptyScope), None),
        (None, Some(WithheldRead::Removed)),
    ];
    for (before_admission, after_admission) in cases {
        let fixture = Fixture::new(before_admission)?;
        if let Some(how) = after_admission {
            withhold_dreamer_read(&fixture.vault, fixture.owner, how)?;
        }
        let case =
            format!("withheld before admission {before_admission:?}, after {after_admission:?}");
        let mut runtime = CountingRuntime::default();
        let refused = fixture.execute(&mut runtime);
        assert_eq!(
            runtime.drafts, 0,
            "P1: without a live System read grant the interpreter never drafts ({case})"
        );
        assert!(
            matches!(refused, Err(Error::InvalidClaimBody(_))),
            "P1: the recipe is refused at its evidence read ({case}): {refused:?}"
        );
        assert!(
            fixture.outputs()?.is_empty(),
            "P1: a refused recipe lands no output claim ({case})"
        );
    }
    Ok(())
}

/// ND-040, ARCH-0026 (llms-full.txt:343324): a recipe "resumes across process restarts". A
/// result committed with its claim settles after the lease is lost, with no interpreter, a
/// Stale skill and deleted evidence, and writes no claim or Gate receipt again.
#[test]
fn committed_recipe_resumes_without_runtime_live_skill_or_evidence() -> Result<()> {
    let fixture = Fixture::new(None)?;
    let mut runtime = CountingRuntime::default();
    let first = fixture.execute(&mut runtime)?;
    assert!(
        matches!(first, DreamerAttemptExecution::Completed { .. }),
        "ND-040 resume: the first run commits its result: {first:?}"
    );
    assert_eq!(
        runtime.drafts, 1,
        "ND-040 resume: the first run drafts once"
    );
    let landed = fixture.outputs()?;
    assert_eq!(
        landed.len(),
        1,
        "ND-040 resume: the first run lands one output claim"
    );
    assert!(
        fixture.output_gate_count()? > 0,
        "ND-040 resume: the output's Gate receipt is counted"
    );

    // The crash window: result and claim committed, the queue row not settled.
    let id = fixture.attempt.status.attempt.id;
    let queue = AttemptQueue::new(&fixture.vault);
    let leased = queue.get(id)?.expect("the attempt row");
    let now = leased.updated_at.saturating_add(20);
    let cleanup = queue.cleanup_leases(CleanupAttemptLeases {
        now,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(
        cleanup.stale_requeued, 1,
        "ND-040 resume: the lost lease requeues the attempt"
    );
    let mut stale = fixture
        .vault
        .get_skill_record(&fixture.skill)?
        .expect("the recipe skill");
    stale.lifecycle_status = SkillLifecycle::Stale;
    fixture
        .vault
        .update_skill_record(&fixture.skill, &stale, at(now + 1), now + 1)?;
    fixture.vault.delete_entity(&fixture.evidence)?;
    let before = fixture.outputs()?;
    let gates_before = fixture.output_gate_count()?;

    let mut recovered = WeaveRecipeExecutor {
        inner: NoOrdinaryWork,
        runtime: None::<&mut dyn WeaveRecipeRuntime>,
    };
    let mut driver = DreamerWakeDriver::new(&fixture.vault, BUDGET, WakePassDeadline::new(180_000));
    let report = block_on_ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Event,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            lease_owner: "recovered-worker".into(),
            budget_total_units: 1_000,
            reserve_units: 100,
            now: now + 2,
            host_scope: None,
            destination_bound: None,
        },
        &mut recovered,
        &WakeCancellation::new(),
    ))
    .unwrap_or_else(|error| panic!("ND-040 resume: the recovery pass runs: {error:?}"));
    assert_eq!(
        report.completed, 1,
        "ND-040 resume: the pass settles the recovered recipe from its saved result: {report:?}"
    );
    let status = DreamerRunnerStore::new(&fixture.vault)
        .status(id)?
        .expect("the attempt status");
    assert_eq!(
        status.attempt.state,
        AttemptState::Completed,
        "ND-040 resume: the same attempt reaches Completed"
    );
    assert_eq!(runtime.drafts, 1, "ND-040 resume: no interpreter ran again");
    let after = fixture.outputs()?;
    assert_eq!(
        after, before,
        "ND-040 resume: settling the saved result rewrites no output claim"
    );
    assert_eq!(
        ids(&after),
        ids(&landed),
        "ND-040 resume: the output keeps its id, with no duplicate"
    );
    assert_eq!(
        fixture.output_gate_count()?,
        gates_before,
        "ND-040 resume: settling the saved result writes no output Gate receipt"
    );
    Ok(())
}

/// An interpreter that edits its source TURN while it drafts, then answers from the old read.
struct ChangingEvidence<'a> {
    vault: &'a Vault,
    evidence: EntityId,
    drafts: usize,
}
impl WeaveRecipeRuntime for ChangingEvidence<'_> {
    fn executor(&self) -> Result<&str> {
        Ok("changing-evidence@1")
    }
    fn draft(&mut self, _: &str, _: &[u8]) -> Result<WeaveRecipeDraft> {
        self.drafts += 1;
        self.vault.put_entity(
            &self.evidence,
            ENTITY_TYPE_TURN,
            at(6),
            6,
            &turn("a later revision"),
        )?;
        Ok(WeaveRecipeDraft {
            predicate: PREDICATE.into(),
            value: "stale answer".into(),
            confidence: 0.8,
        })
    }
}

/// ND-040, ARCH-0026 (llms-full.txt:343324): derived claims land "with provenance". The writer
/// reads the source again in its own transaction, so a source changed between the draft and
/// the commit refuses the stale draft.
#[test]
fn changed_source_between_recipe_draft_and_commit_refuses_the_write() -> Result<()> {
    let fixture = Fixture::new(None)?;
    let mut runtime = ChangingEvidence {
        vault: &fixture.vault,
        evidence: fixture.evidence,
        drafts: 0,
    };
    let refused = fixture.execute(&mut runtime);
    assert_eq!(
        runtime.drafts, 1,
        "ND-040 changed source: the interpreter drafts once"
    );
    assert_eq!(
        fixture.vault.get(&fixture.evidence)?,
        Some(turn("a later revision")),
        "ND-040 changed source: the source edit committed before the landing"
    );
    assert!(
        matches!(refused, Err(Error::InvalidClaimBody(_))),
        "ND-040 changed source: the changed source refuses the stale draft: {refused:?}"
    );
    assert!(
        fixture.outputs()?.is_empty(),
        "ND-040 changed source: no stale output claim commits"
    );
    assert_eq!(
        fixture.output_gate_count()?,
        0,
        "ND-040 changed source: the refusal writes no output Gate receipt"
    );
    Ok(())
}

/// ARCH-0073 §6, "a re-mention restores the archived record" (FIX
/// DREAMER-DIRECT-CLAIM-WRITERS-LAND-ON-ARCHIVED-PERSON): the vault cleanup archives the
/// recipe's subject PERSON after the owner admitted the recipe. The output the recipe lands
/// about her is a new mention of her, and its own write restores her, as the promotion
/// writer's claim does.
#[test]
fn recipe_output_about_an_archived_person_restores_her() -> Result<()> {
    let fixture = Fixture::new(None)?;
    archive_as_cleanup(&fixture.vault, &fixture.subject)?;
    assert!(
        fixture.vault.archived_entity(&fixture.subject)?.is_some(),
        "the cleanup's archive marker stands on the subject"
    );
    let mut runtime = CountingRuntime::default();
    let ran = fixture.execute(&mut runtime)?;
    assert!(
        matches!(ran, DreamerAttemptExecution::Completed { .. }),
        "the recipe commits its result: {ran:?}"
    );
    assert!(
        fixture.vault.archived_entity(&fixture.subject)?.is_none(),
        "the output is a new mention of her: it restored her, and she bears no archive marker"
    );
    assert_eq!(
        fixture.outputs()?.len(),
        1,
        "the recipe lands one output claim about her"
    );
    Ok(())
}
