//! [WORKFLOW-PARK-FAIL-RETRYABLE] (the Engine's ruling of 13 Nov 01:22): a
//! workflow step whose `self.use` call a verb pre-hook asked about saves its
//! park (the tool checkpoint with its Hook pause) after the hook saved the
//! ask. When that save fails on a store fault, the step is tried again: the
//! ladder requeues the same leaf from the cursor checkpoint it saved before
//! its tools ran, so the retried call builds the same invocation and finds
//! the same ask, never a second one. Any other park failure still ends the
//! leaf.
//!
//! [WORKFLOW-PARK-RESUMED-CALL-RETRY] (the Engine's ruling of 13 Nov 20:19):
//! a call resumed from its own park (its first pre-hook's ask answered
//! proceed) that parks again on a second pre-hook's ask leaves the first
//! park's wait in its committed checkpoint. When that second park's save
//! fails on a store fault, the ladder requeues the same leaf with that wait
//! kept, and the retry resumes the same call.
//!
//! Reaches the pump's claim, the host's park fault and the failure ladder
//! through `oneiron_server::test_doors::workflow_park`, and the hook's ask
//! (`ask::open`, the owner's answer, `ask::retry`) through
//! `oneiron::test_doors::verb_hook_ask`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test workflow_park_save_retry`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::agent_def::workflow::WorkflowDefinition;
use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
use oneiron::attempt_queue::{AttemptId, AttemptState};
use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::verb_hook_ask::{HookAsk, SavedAsk};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::test_doors::workflow_park::{
    ParkFault, StepTry, claim_step, fail_park, park_step, resume_step,
};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// The verb the step's `self.use` call presents at the hook boundary.
const VERB: &str = "self.use";
/// The `self.use` calls of the step's round answered before the one the
/// hook asks about: the cursor checkpoint's `use_ordinal`.
const ANSWERED_USES: u64 = 2;

/// A rooted, served vault with its owner and the owner's proof, and one
/// workflow of one step dispatched.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    root: AttemptId,
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
        let agent = saved_agent(&vault, name)?;
        let workflow = EntityId::now();
        vault.save_workflow(&workflow, &WorkflowDefinition::new(name, vec![agent])?, 2)?;
        let dispatcher = AgentDispatcher::new(&vault);
        dispatcher.dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some(name.to_owned()),
            run_id: Some(name.to_owned()),
            now: 10,
        })?;
        let [root] = dispatcher.open_workflow_roots()?[..] else {
            return Err("expected the one dispatched workflow".into());
        };
        Ok(Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
            root,
        })
    }

    /// The owner's asking pre-hook on the step's `self.use`, bound as a
    /// pack's bind writes it.
    fn hook(&self) -> Result<HookAsk, TestError> {
        Ok(HookAsk::on_verb(
            &self.vault,
            self.owner,
            &self.owner_proof,
            VERB,
        )?)
    }

    /// The step's first try, with the hook's ask saved under its next
    /// `self.use` call's invocation, and the ask's id.
    fn first_try_asked(&self, hook: &HookAsk) -> Result<(StepTry, EntityId), TestError> {
        let first = claim_step(&self.vault, self.root, 20, ANSWERED_USES)?
            .ok_or("the step's first try runs")?;
        let asked = hook.ask(&self.vault, &first.actor, first.next_use)?;
        Ok((first, asked))
    }
}

/// A custom agent definition the pump can dispatch: the seeded default's
/// shape with its own instructions. A fresh UUIDv7 id: the seeded system
/// agents hold `[0xA1; 16]` through `[0xA6; 16]`.
fn saved_agent(vault: &Vault, name: &str) -> Result<EntityId, TestError> {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("the default agent is seeded")?;
    definition.logical_id = None;
    definition.agent_id = format!("test.park.{name}");
    definition.instructions = Some("Use the saved key.".to_owned());
    definition.skills.clear();
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// What the step's next try finds for its `self.use` call before the
/// hook's chain runs, with the try; `Stopped` when no try ran.
fn retried_call(
    fixture: &Fixture,
    hook: &HookAsk,
) -> Result<(SavedAsk, Option<StepTry>), TestError> {
    let retry = claim_step(&fixture.vault, fixture.root, 22, ANSWERED_USES)?;
    let found = match &retry {
        Some(retry) => hook.retry(&fixture.vault, &retry.actor, retry.next_use)?,
        None => SavedAsk::Stopped("no try of the step ran again: its leaf ended".to_owned()),
    };
    Ok((found, retry))
}

#[test]
fn a_park_whose_save_fails_on_storage_retries_the_same_leaf_and_finds_the_same_ask() -> TestResult {
    let fixture = Fixture::new("park-storage")?;
    let hook = fixture.hook()?;
    let (first, asked) = fixture.first_try_asked(&hook)?;

    let settled = fail_park(&fixture.vault, fixture.root, &first, ParkFault::Storage, 21)?;
    let (found, retry) = retried_call(&fixture, &hook)?;

    assert_eq!(
        found,
        SavedAsk::Pending { ask: asked },
        "the retried self.use call builds the first try's invocation, so it finds the ask the \
         hook saved and parks on it: reused, never a second ask"
    );
    let retry = retry.ok_or("the step was tried again")?;
    assert_eq!(
        retry.next_use, first.next_use,
        "the retry's call has the first try's invocation"
    );
    assert_eq!(
        retry.leaf, first.leaf,
        "the ladder requeues the same leaf from its cursor checkpoint, not a fresh row"
    );
    assert_eq!(
        (retry.use_ordinal, retry.waits),
        (ANSWERED_USES, false),
        "the retry starts from the cursor saved before the park, which waits on nothing"
    );
    assert_eq!(retry.failures, 1, "the ladder counts the failed park once");
    assert_eq!(
        (settled.retried, settled.reason),
        (true, Some("workflow_step_park_save_failed")),
        "a park whose save failed on the store is retried, and its evidence names a park \
         save, not a model call"
    );
    Ok(())
}

#[test]
fn an_ask_answered_proceed_during_the_backoff_lets_the_retried_call_run_with_no_park() -> TestResult
{
    let fixture = Fixture::new("park-proceed")?;
    let hook = fixture.hook()?;
    let (first, asked) = fixture.first_try_asked(&hook)?;

    fail_park(&fixture.vault, fixture.root, &first, ParkFault::Storage, 21)?;
    hook.answer_proceed(&fixture.vault, asked)?;
    let (found, _retry) = retried_call(&fixture, &hook)?;

    assert_eq!(
        found,
        SavedAsk::Resume { ask: asked },
        "an ask answered proceed while the step waited out its backoff lets the retried call \
         run on that answer, with no park and no second ask"
    );
    Ok(())
}

#[test]
fn a_resumed_calls_second_park_whose_save_fails_on_storage_retries_the_same_leaf_on_its_wait()
-> TestResult {
    let fixture = Fixture::new("park-resumed")?;
    let hook = fixture.hook()?;
    let (first, asked) = fixture.first_try_asked(&hook)?;
    park_step(&fixture.vault, &first, asked, 21)?;
    hook.answer_proceed(&fixture.vault, asked)?;
    resume_step(&fixture.vault, fixture.root, 22)?;
    let resumed = claim_step(&fixture.vault, fixture.root, 23, ANSWERED_USES)?
        .ok_or("the step's call resumes once its ask is answered")?;
    assert_eq!(
        (resumed.leaf, resumed.resumes, resumed.use_ordinal),
        (first.leaf, Some(first.next_use), ANSWERED_USES + 1),
        "the resumed try holds the first park's wait: its call's invocation and ordinal"
    );

    // The resumed call's second pre-hook asks; that park's save fails on the
    // store, with the first park's wait still in the committed checkpoint.
    let settled = fail_park(
        &fixture.vault,
        fixture.root,
        &resumed,
        ParkFault::Storage,
        24,
    )?;
    let (found, retry) = retried_after(&fixture, &hook, 25, first.next_use)?;

    assert_eq!(
        (settled.retried, settled.reason),
        (true, Some("workflow_step_park_save_failed")),
        "a resumed call's park whose save failed on the store is retried, not ended"
    );
    let retry = retry.ok_or("the step was tried again")?;
    assert_eq!(
        retry.leaf, first.leaf,
        "the ladder requeues the same leaf, not a fresh row"
    );
    assert_eq!(
        (retry.resumes, retry.use_ordinal),
        (Some(first.next_use), ANSWERED_USES + 1),
        "the retry keeps the resumed call's wait: the same invocation and use ordinal"
    );
    assert_eq!(retry.failures, 1, "the ladder counts the failed park once");
    assert_eq!(
        found,
        SavedAsk::Resume { ask: asked },
        "the retried call resumes on the first ask's proceed answer, with no fresh ask"
    );
    Ok(())
}

/// The step's next try at `now` and what its call under `invocation` finds
/// before the hook's chain runs; `Stopped` when no try ran.
fn retried_after(
    fixture: &Fixture,
    hook: &HookAsk,
    now: u64,
    invocation: oneiron::runtime_hooks::InvocationId,
) -> Result<(SavedAsk, Option<StepTry>), TestError> {
    let retry = claim_step(&fixture.vault, fixture.root, now, ANSWERED_USES)?;
    let found = match &retry {
        Some(retry) => hook.retry(&fixture.vault, &retry.actor, invocation)?,
        None => SavedAsk::Stopped("no try of the step ran again: its leaf ended".to_owned()),
    };
    Ok((found, retry))
}

#[test]
fn a_park_whose_save_is_refused_still_ends_the_leaf() -> TestResult {
    let fixture = Fixture::new("park-refused")?;
    let hook = fixture.hook()?;
    let (first, _asked) = fixture.first_try_asked(&hook)?;

    let settled = fail_park(&fixture.vault, fixture.root, &first, ParkFault::Refused, 21)?;

    assert_eq!(
        (settled.retried, settled.reason),
        (false, None),
        "a park refused by its save (a fence, a fenced meter, a missing route) is not retried"
    );
    assert_ne!(
        settled.state,
        AttemptState::Queued,
        "the refused park's leaf is not queued again"
    );
    assert!(
        claim_step(&fixture.vault, fixture.root, 22, ANSWERED_USES)?.is_none(),
        "no try of the step runs after a refused park"
    );
    Ok(())
}
