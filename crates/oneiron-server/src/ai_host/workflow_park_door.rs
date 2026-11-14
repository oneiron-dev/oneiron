//! Door for `tests/workflow_park_save_retry.rs` ([WORKFLOW-PARK-FAIL-RETRYABLE]):
//! a workflow step's leaf claimed as the pump claims it, with the cursor
//! checkpoint a step saves before its tools run; a park whose save failed,
//! turned into the step's fault as the host turns it and settled through the
//! pump's failure ladder (`step_failure::settle`); and the next try of the
//! leaf, claimed the same way, with the invocation its `self.use` call
//! builds from its checkpoint. For [WORKFLOW-PARK-RESUMED-CALL-RETRY]: a
//! try's park saved as the step saves it (the checkpoint with its wait and
//! the leaf's Hook pause), and the pump's resume of that pause once its ask
//! is answered. Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::BTreeMap;

use oneiron::agent_dispatch::{
    AgentDispatcher, WorkflowToolCursor, WorkflowToolProgress, WorkflowToolTranscript,
    WorkflowToolWait, agent_dispatch_run_actor,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::failure_ladder::FailureLadderOutcome;
use oneiron::runtime_hooks::InvocationId;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, Error,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, Vault, WriteActor,
};

use super::step::{StepFault, park_save_fault, self_use_invocation};
use super::step_failure::{FailedStep, settle};

/// The lease owner the door claims steps as.
const LEASE_OWNER: &str = "workflow-park-door";

/// How a park's failed save is turned into the step's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkFault {
    /// The store failed under the save (`Error::Storage`).
    Storage,
    /// The save was refused (`Error::InvalidConfig`), as a fence, a fenced
    /// meter or a missing checkpoint route refuses it.
    Refused,
}

impl ParkFault {
    fn error(self) -> Error {
        match self {
            Self::Storage => Error::Storage(heed::Error::Io(std::io::Error::other(
                "the park's write failed",
            ))),
            Self::Refused => {
                Error::InvalidConfig("workflow checkpoint route is missing".to_owned())
            }
        }
    }
}

/// A try of a step's leaf, claimed as the pump claims it.
#[derive(Debug, Clone)]
pub struct StepTry {
    pub leaf: AttemptId,
    /// The lease generation the try holds.
    pub lease_count: u32,
    /// The step's run actor: who its `self.use` calls run as.
    pub actor: WriteActor,
    /// The cursor's `use_ordinal` in the checkpoint the try starts from.
    pub use_ordinal: u64,
    /// The cursor's checkpoint parks on a wait.
    pub waits: bool,
    /// The invocation of the call this try resumes: its checkpoint's wait,
    /// whose park's hold was released before the claim.
    pub resumes: Option<InvocationId>,
    /// The leaf's failures the ladder counts (`workflow_tool_failure_count`).
    pub failures: usize,
    /// The invocation the try's next `self.use` call builds, as the step
    /// builds it: its cursor's `use_ordinal` plus one.
    pub next_use: InvocationId,
}

/// What the ladder did with a failed park.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledPark {
    /// The ladder tried the step again (`FailureLadderOutcome::Retried`).
    pub retried: bool,
    /// The stable reason the step's retryable evidence carries, when the
    /// fault was retryable.
    pub reason: Option<&'static str>,
    /// The leaf's state after the settle.
    pub state: AttemptState,
}

/// Claims `root`'s active leaf as the pump does and reads the try: on its
/// first try it saves the cursor checkpoint a step saves after
/// `answered_uses` answered `self.use` calls. `None` when no leaf ran (the
/// workflow ended).
///
/// # Errors
///
/// Storage, or a claim, checkpoint or context refusal.
pub fn claim_step(
    vault: &Vault,
    root: AttemptId,
    now: u64,
    answered_uses: u64,
) -> oneiron::Result<Option<StepTry>> {
    let dispatcher = AgentDispatcher::new(vault);
    let mut seen = None;
    for _ in 0..4 {
        let progress = dispatcher.run_workflow_step_output_with_confession(
            root,
            LEASE_OWNER,
            now,
            |status, _context| {
                let leased = &status.attempt;
                let actor = agent_dispatch_run_actor(&status.input, leased.id)?;
                let saved = match dispatcher.workflow_tool_checkpoint(leased)? {
                    Some(saved) => saved.progress,
                    None => {
                        let progress = cursor_progress(vault, &actor, leased.id, answered_uses)?;
                        dispatcher.save_workflow_tool_progress(
                            leased,
                            &transcript()?,
                            progress.clone(),
                        )?;
                        progress
                    }
                };
                seen = Some(StepTry {
                    leaf: leased.id,
                    lease_count: leased.attempt_count,
                    actor,
                    use_ordinal: saved.cursor.use_ordinal,
                    waits: saved.wait.is_some(),
                    resumes: saved
                        .wait
                        .as_ref()
                        .map(|wait| InvocationId(wait.invocation)),
                    failures: dispatcher.workflow_tool_failure_count(leased)?,
                    next_use: self_use_invocation(
                        leased.id,
                        saved.cursor.use_ordinal.saturating_add(1),
                    )?,
                });
                // The step stops here, its lease held, as a step whose park
                // failed returns at once.
                Err(Error::InvalidConfig("the door holds the step".to_owned()))
            },
        );
        if seen.is_some() {
            return Ok(seen);
        }
        progress?;
    }
    Ok(None)
}

/// The step `held` fails its park with `fault`: the host turns the error
/// into the step's fault (`step::park_save_fault`) and the pump hands it to
/// the ladder (`step_failure::settle`) with no backoff.
///
/// # Errors
///
/// Storage, or the ladder's refusal.
pub fn fail_park(
    vault: &Vault,
    root: AttemptId,
    held: &StepTry,
    fault: ParkFault,
    now: u64,
) -> oneiron::Result<SettledPark> {
    let StepFault { retry, .. } = park_save_fault(fault.error());
    let outcome = settle(
        vault,
        root,
        &FailedStep {
            leaf: held.leaf,
            lease_count: held.lease_count,
            retry,
        },
        LEASE_OWNER,
        0,
        now,
    )?;
    let state = AttemptQueue::new(vault)
        .get(held.leaf)?
        .ok_or_else(|| Error::InvalidConfig("the failed leaf is missing".to_owned()))?
        .state;
    Ok(SettledPark {
        retried: matches!(outcome, FailureLadderOutcome::Retried { .. }),
        reason: retry.map(|cause| cause.stable_reason()),
        state,
    })
}

/// The step `held` parks its next `self.use` call on `ask`, as the step
/// saves a park: the call's ordinal in the cursor, the wait on the call's
/// invocation, and the leaf held on that invocation's hook, in one writer.
///
/// # Errors
///
/// Storage, or the checkpoint writer's refusal.
pub fn park_step(vault: &Vault, held: &StepTry, ask: EntityId, now: u64) -> oneiron::Result<()> {
    let dispatcher = AgentDispatcher::new(vault);
    let leased = AttemptQueue::new(vault)
        .get(held.leaf)?
        .ok_or_else(|| Error::InvalidConfig("the held leaf is missing".to_owned()))?;
    let mut progress = dispatcher
        .workflow_tool_checkpoint(&leased)?
        .ok_or_else(|| Error::InvalidConfig("the held try saved no checkpoint".to_owned()))?
        .progress;
    progress.cursor.use_ordinal = progress
        .cursor
        .use_ordinal
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("workflow tool ordinal"))?;
    progress.wait = Some(WorkflowToolWait {
        invocation: held.next_use.0,
        ask,
    });
    dispatcher.park_workflow_tool(&leased, &transcript()?, progress, now)
}

/// The pump's pass over `root`'s hook pause: once the pause's ask is
/// answered, the leaf is released to its next claim.
///
/// # Errors
///
/// Storage, or a checkpoint refusal.
pub fn resume_step(vault: &Vault, root: AttemptId, now: u64) -> oneiron::Result<()> {
    AgentDispatcher::new(vault)
        .resume_workflow_tool(root, now)
        .map(|_| ())
}

/// The cursor a step saves after `answered_uses` answered `self.use` calls
/// of its round, with no wait.
fn cursor_progress(
    vault: &Vault,
    actor: &WriteActor,
    leaf: AttemptId,
    answered_uses: u64,
) -> oneiron::Result<WorkflowToolProgress> {
    let budget = vault
        .policy_budget_guard(
            super::step::step_run_id(leaf)?,
            10_000,
            1,
            BudgetExhaustionPolicy::Suspend,
            actor.clone(),
        )?
        .checkpoint()
        .map_err(|denied| Error::InvalidConfig(format!("workflow checkpoint budget: {denied}")))?;
    Ok(WorkflowToolProgress {
        cursor: WorkflowToolCursor {
            assistant_message: 1,
            tool_index: usize::try_from(answered_uses).unwrap_or(usize::MAX),
            use_ordinal: answered_uses,
            round: 1,
            capture_completed: false,
        },
        wait: None,
        budget,
        budget_units: 10_000,
        spend_scope: None,
        known_sources: Vec::new(),
        sources_complete: false,
        planner_craft_rows: None,
        no_record_at_arrival: false,
    })
}

/// A step's request with its user turn and the assistant turn whose three
/// `self.use` calls run. The cursor's `tool_index` counts the answered ones,
/// so the turn holds at least that many calls, as a step's saved turn does.
fn transcript() -> oneiron::Result<WorkflowToolTranscript> {
    let purpose = CallPurpose::Other {
        name: "workflow_step".to_owned(),
    };
    let text = |role: LlmMessageRole, text: &str| LlmMessage {
        role,
        content: vec![ContentPart::Text {
            text: text.to_owned(),
            signature: None,
        }],
    };
    let mut assistant = text(LlmMessageRole::Assistant, "Using it.");
    assistant
        .content
        .extend((1..=3).map(|use_number| ContentPart::ToolCall {
            call_id: format!("self-use-{use_number}"),
            name: "self.use".to_owned(),
            input: serde_json::json!({ "use": use_number }),
            signature: None,
        }));
    Ok(WorkflowToolTranscript {
        request: LlmRequest {
            model: ModelId::new("fake/park-retry@1")
                .map_err(|error| Error::InvalidConfig(format!("model id: {error:?}")))?,
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(
                    &purpose,
                    ModelTierRef("workflow_step".to_owned()),
                ),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: ModelLocality::OwnServer,
                host_keyless: false,
                host_paid: false,
            },
            messages: vec![
                text(LlmMessageRole::User, "Use the saved key three times."),
                assistant,
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        },
        objectives: Vec::new(),
        answer: None,
    })
}
