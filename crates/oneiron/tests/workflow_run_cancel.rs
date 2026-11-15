//! L1-03 PR 1 (PLAN-L1-03 D8): a saved workflow run names its state, and the
//! owner can ask it to stop.
//!
//! - `vault.workflows.status` answers `state`: `running` until the run's root
//!   ends, then `completed`, `failed` or `cancelled`.
//! - `vault.workflows.cancel` cancels the step that waits to run and ends the
//!   run `cancelled`; no later step starts. A repeated cancel changes nothing.
//! - A step a worker holds is asked to land, never killed. When it completes,
//!   its result stays (a cancel never undoes committed work, ARCH-0028
//!   `#mcp-tasks`), the run ends `cancelled`, and its next step never starts.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test workflow_run_cancel`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::sync::Arc;

use oneiron::agent_def::workflow::WorkflowDefinition;
use oneiron::agent_dispatch::{AgentDispatcher, WorkflowProgress};
use oneiron::attempt_queue::{
    AttemptCancelReceiptKind, AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef,
    AttemptState,
};
use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::task_verb::sdk::{
    WorkflowDispatchRequest, WorkflowRunRequest, WorkflowRunState, WorkflowRunView,
    cancel_workflow_run_as, dispatch_workflow_as, read_workflow_run_as,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// A rooted vault with its owner's proof and one dispatched run of a saved
/// two-step workflow.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    run: WorkflowRunView,
}

impl Fixture {
    fn new(name: &str) -> Result<Self, TestError> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        vault.ensure_host_root_slip(&issuer)?;
        let first = saved_agent(&vault, &format!("{name}.first"))?;
        let second = saved_agent(&vault, &format!("{name}.second"))?;
        let workflow = EntityId::now();
        vault.save_workflow(
            &workflow,
            &WorkflowDefinition::new(name, vec![first, second])?,
            2,
        )?;
        let run = dispatch_workflow_as(
            &vault,
            &owner_proof,
            WorkflowDispatchRequest {
                workflow_ref: workflow,
                intent_key: name.to_owned(),
                briefing: "Write the two notes.".to_owned(),
                context_spec: None,
                task_ref: None,
            },
        )?;
        Ok(Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
            run,
        })
    }

    fn root(&self) -> Result<AttemptId, TestError> {
        Ok(AttemptId::from_bytes(self.run.root_attempt_ref.as_bytes())?)
    }

    fn request(&self) -> WorkflowRunRequest {
        WorkflowRunRequest {
            root_attempt_ref: self.run.root_attempt_ref,
        }
    }

    fn status(&self) -> Result<WorkflowRunView, TestError> {
        Ok(read_workflow_run_as(
            &self.vault,
            &self.owner_proof,
            self.request(),
        )?)
    }

    fn cancel(&self) -> Result<WorkflowRunView, TestError> {
        Ok(cancel_workflow_run_as(
            &self.vault,
            &self.owner_proof,
            self.request(),
        )?)
    }

    fn attempt(&self, attempt_ref: EntityId) -> Result<AttemptRecord, TestError> {
        Ok(AttemptQueue::new(&self.vault)
            .get(AttemptId::from_bytes(attempt_ref.as_bytes())?)?
            .ok_or("the attempt is stored")?)
    }

    /// Runs the run's active step as a host does: claims it, calls `during`
    /// while it is leased, delivers `result`, and pumps the run.
    fn run_step(&self, result: &str, during: impl FnOnce()) -> Result<WorkflowProgress, TestError> {
        let now = self.vault.now_recorded_at();
        Ok(AgentDispatcher::new(&self.vault).run_workflow_step(
            self.root()?,
            "test-host",
            now,
            |_status, _context| {
                during();
                AttemptResultRef::new(result)
            },
        )?)
    }

    /// Whether the run's next host pass would run a step: a pass that finds
    /// one fails the test.
    fn assert_no_step_runs(&self) -> TestResult {
        let now = self.vault.now_recorded_at();
        let progress = AgentDispatcher::new(&self.vault).run_workflow_step(
            self.root()?,
            "test-host",
            now,
            |_status, _context| panic!("a stopped run released another step"),
        )?;
        assert!(
            matches!(progress, WorkflowProgress::Stopped(_)),
            "a host pass over the stopped run runs nothing: {progress:?}"
        );
        Ok(())
    }
}

/// A custom agent definition the pump can dispatch: the seeded default's
/// shape with its own id.
fn saved_agent(vault: &Vault, name: &str) -> Result<EntityId, TestError> {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("the default agent is seeded")?;
    definition.logical_id = None;
    definition.agent_id = format!("test.cancel.{name}");
    definition.instructions = Some("Write one note.".to_owned());
    definition.skills.clear();
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

#[test]
fn workflow_status_names_the_run_state_from_running_to_completed() -> TestResult {
    let fixture = Fixture::new("state-runs")?;
    assert_eq!(
        fixture.run.state,
        WorkflowRunState::Running,
        "the dispatch answers a running run"
    );
    assert_eq!(fixture.status()?.state, WorkflowRunState::Running);

    let progress = fixture.run_step("artifact:first", || {})?;
    assert!(
        matches!(progress, WorkflowProgress::Advanced(_)),
        "the first step's result releases the second: {progress:?}"
    );
    assert_eq!(
        fixture.status()?.state,
        WorkflowRunState::Running,
        "a run with a step left still runs"
    );

    let progress = fixture.run_step("artifact:second", || {})?;
    assert_eq!(progress, WorkflowProgress::Completed);
    let done = fixture.status()?;
    assert_eq!(
        done.state,
        WorkflowRunState::Completed,
        "the run's root completed"
    );
    assert_eq!(
        done.results
            .iter()
            .map(|result| result.result_ref.as_str())
            .collect::<Vec<_>>(),
        vec!["artifact:first", "artifact:second"]
    );
    let wire = serde_json::to_value(&done)?;
    assert_eq!(
        wire["state"], "completed",
        "the wire names the state in snake case"
    );
    Ok(())
}

#[test]
fn workflow_cancel_of_a_queued_step_ends_the_run_cancelled() -> TestResult {
    let fixture = Fixture::new("cancel-queued")?;
    let leaf = fixture.run.active_attempt_ref;
    assert_eq!(fixture.attempt(leaf)?.state, AttemptState::Queued);

    let cancelled = fixture.cancel()?;

    assert_eq!(
        fixture.attempt(leaf)?.state,
        AttemptState::Cancelled,
        "the step that waited to run is cancelled"
    );
    assert_eq!(
        cancelled.state,
        WorkflowRunState::Cancelled,
        "the run ends cancelled, not failed"
    );
    assert_eq!(
        fixture.attempt(fixture.run.root_attempt_ref)?.state,
        AttemptState::Cancelled
    );
    assert!(cancelled.results.is_empty(), "no step completed");
    assert_eq!(
        cancelled.active_attempt_ref, leaf,
        "the cursor stays on the cancelled step: no second step was released"
    );
    let root = fixture.root()?;
    assert!(
        !AgentDispatcher::new(&fixture.vault)
            .open_workflow_roots()?
            .contains(&root),
        "the cancelled run is no open run"
    );
    fixture.assert_no_step_runs()?;

    let root_before = fixture.attempt(fixture.run.root_attempt_ref)?;
    let leaf_before = fixture.attempt(leaf)?;
    let again = fixture.cancel()?;
    assert_eq!(
        serde_json::to_value(&again)?,
        serde_json::to_value(&cancelled)?,
        "a repeated cancel answers the same run"
    );
    assert_eq!(
        (
            fixture.attempt(fixture.run.root_attempt_ref)?,
            fixture.attempt(leaf)?
        ),
        (root_before, leaf_before),
        "a repeated cancel writes nothing"
    );
    Ok(())
}

#[test]
fn workflow_cancel_of_a_running_step_asks_it_to_land_and_keeps_its_result() -> TestResult {
    let fixture = Fixture::new("cancel-running")?;
    let leaf = fixture.run.active_attempt_ref;
    let owner = fixture.owner.to_hex();
    let seen = RefCell::new(None);

    let progress = fixture.run_step("artifact:first", || {
        // The step is leased now: the cancel can only ask it to land.
        let view = fixture.cancel().expect("the owner's cancel is admitted");
        let step = fixture.attempt(leaf).expect("the step is stored");
        let root = fixture
            .attempt(fixture.run.root_attempt_ref)
            .expect("the root is stored");
        *seen.borrow_mut() = Some((view, step, root));
    })?;

    let (view, step, root) = seen.into_inner().ok_or("the step ran")?;
    assert_eq!(
        step.state,
        AttemptState::Leased,
        "the held step keeps running"
    );
    assert!(
        step.cancel_receipts().iter().any(|receipt| {
            receipt.kind == AttemptCancelReceiptKind::SoftRequested && receipt.actor == owner
        }),
        "the held step is asked to land, in the owner's name"
    );
    assert_eq!(
        view.state,
        WorkflowRunState::Running,
        "the run runs on until its held step answers"
    );
    assert!(!root.state.is_terminal(), "the root is not yet ended");

    assert!(
        matches!(progress, WorkflowProgress::Stopped(_)),
        "the step's completion ends the run instead of releasing the next step: {progress:?}"
    );
    let ended = fixture.status()?;
    assert_eq!(ended.state, WorkflowRunState::Cancelled);
    assert_eq!(
        ended
            .results
            .iter()
            .map(|result| result.result_ref.as_str())
            .collect::<Vec<_>>(),
        vec!["artifact:first"],
        "the step that completed keeps its result: a cancel never undoes committed work"
    );
    assert_eq!(
        fixture.attempt(leaf)?.state,
        AttemptState::Completed,
        "the asked step completed as it was"
    );
    assert_eq!(
        ended.active_attempt_ref, leaf,
        "the second step was never released"
    );
    fixture.assert_no_step_runs()?;
    Ok(())
}
