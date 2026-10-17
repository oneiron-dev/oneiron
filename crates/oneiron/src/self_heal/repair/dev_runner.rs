//! Dev-time Coach jobs over the existing BYO runner and human patch-review doors.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimSource, ScopedReadResult};
use crate::dispatch_byoa::{
    ByoEndpointBackendFactory, ByoaConnectorSpec, ByoaDispatchOutcome, ByoaDispatcher,
    ByoaEgressPort, ByoaError, ByoaResult, DispatchByoa, DreamerProviderAdapter,
    DreamerProviderInput,
};
use crate::self_heal::healer_host::HealerRegistration;
use crate::{EntityId, Error, Result};

use super::super::invariant_canonical::canonical_invariant_value;
use super::super::{DiagnosticEvent, MAX_EVIDENCE_REFS, validate_ref};
use super::{RepairActor, RepairBundle, RepairOperation, RepairProposal};

/// A review target, never a repository handle or migration executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DevRunnerTarget {
    Code { repo_ref: String },
    Schema { schema_ref: String },
}

impl DevRunnerTarget {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Code { repo_ref } => validate_ref(repo_ref),
            Self::Schema { schema_ref } => validate_ref(schema_ref),
        }
    }

    fn operation(self, patch_ref: String) -> RepairOperation {
        match self {
            Self::Code { repo_ref } => RepairOperation::DevPatch {
                repo_ref,
                patch_ref,
            },
            Self::Schema { schema_ref } => RepairOperation::SchemaPatch {
                schema_ref,
                patch_ref,
            },
        }
    }
}

/// Content-free projection. No trace text, chat, run labels, paths or credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevRunnerFailure {
    #[serde(with = "crate::self_heal::receipt_serde::id")]
    pub diagnostic_ref: EntityId,
    pub detector_id: String,
    pub event_class: String,
    pub source: String,
    pub expected: Value,
    pub actual: Value,
    pub delta: Value,
    pub replay_content_hash: String,
    #[serde(with = "crate::self_heal::receipt_serde::ids")]
    pub evidence_refs: Vec<EntityId>,
    pub valid_from: u64,
    pub valid_to: Option<u64>,
}

impl DevRunnerFailure {
    fn from_event(id: EntityId, event: &DiagnosticEvent) -> Result<Self> {
        let invariant = |value: &rmpv::Value| {
            serde_json::to_value(canonical_invariant_value(value)?)
                .map_err(|_| Error::InvariantViolation("dev runner invariant encoding"))
        };
        Ok(Self {
            diagnostic_ref: id,
            detector_id: event.detector_id.clone(),
            event_class: event.event_class.as_str().into(),
            source: event.source.as_str().into(),
            expected: invariant(&event.expected)?,
            actual: invariant(&event.actual)?,
            delta: invariant(&event.delta)?,
            replay_content_hash: crate::entity_id::bytes_to_hex_lower(&event.replay.content_hash),
            evidence_refs: event.evidence_refs.clone(),
            valid_from: event.valid_from,
            valid_to: event.valid_to,
        })
    }
}

/// Host-authored job configuration. `provider_input.task` supplies the instructions;
/// the engine packages them separately from the sanitized diagnostic data.
#[derive(Debug, Clone)]
pub struct DevRunnerRequest {
    pub run_ref: String,
    pub session_tag: String,
    pub target_predicate: String,
    pub target: DevRunnerTarget,
    pub diagnostic_refs: Vec<EntityId>,
    pub provider_input: DreamerProviderInput,
    pub user_login: bool,
    pub task_ref: Option<EntityId>,
    pub parent_attempt_id: Option<AttemptId>,
    pub now: u64,
}

/// The ordinary durable attempt and the mandatory receipt for its corpus read.
#[derive(Debug, Clone)]
pub struct DevRunnerDispatch {
    pub dispatch: ByoaDispatchOutcome,
    pub failure_corpus: ScopedReadResult<Vec<DevRunnerFailure>>,
}

// Kept in the connector's final task argument, so completion survives a host
// restart without a parallel job store. Runner output cannot replace this input.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevRunnerTask {
    instructions: String,
    #[serde(with = "crate::self_heal::receipt_serde::id")]
    actor_ref: EntityId,
    run_ref: String,
    session_tag: String,
    target_predicate: String,
    target: DevRunnerTarget,
    failure_corpus: ScopedReadResult<Vec<DevRunnerFailure>>,
}

impl HealerRegistration<'_> {
    /// Dispatch a coding runner with only scoped, content-free diagnostic data.
    /// The host executes and captures this attempt through `execute_cli` and
    /// `capture_terminal_exhaust`. Those doors retain the checkout, fence,
    /// egress, budget and exhaust rules of every other foreign runner.
    ///
    /// The adapter must produce a CLI connector with the supplied task as its
    /// final argv member, as the standard named adapters do. Existing argv
    /// byte limits apply; callers select the diagnostics for each job.
    pub fn dispatch_dev_runner<B, E>(
        &self,
        dispatcher: &mut ByoaDispatcher<'_, B, E>,
        provider: &dyn DreamerProviderAdapter,
        request: DevRunnerRequest,
    ) -> ByoaResult<DevRunnerDispatch>
    where
        B: ByoEndpointBackendFactory,
        E: ByoaEgressPort,
    {
        let actor = self.require_dev_runner(dispatcher.vault())?;
        validate_ref(&request.run_ref)?;
        validate_ref(&request.session_tag)?;
        crate::claim::validate_session_tag(&request.session_tag)?;
        crate::claim::validate_predicate(&request.target_predicate, true)?;
        request.target.validate()?;
        let failure_corpus = self.dev_runner_corpus(&request.diagnostic_refs)?;
        let mut input = request.provider_input;
        let task = DevRunnerTask {
            instructions: input.task,
            actor_ref: actor.entity_ref(),
            run_ref: request.run_ref.clone(),
            session_tag: request.session_tag,
            target_predicate: request.target_predicate,
            target: request.target,
            failure_corpus: failure_corpus.clone(),
        };
        let task_json = serde_json::to_string(&task)
            .map_err(|_| Error::InvariantViolation("dev runner task encoding"))?;
        input.task = task_json.clone();
        let connector = provider.connector(input)?;
        let ByoaConnectorSpec::CliSandbox(spec) = &connector else {
            return Err(ByoaError::Backend(
                "dev runner requires a CLI connector".into(),
            ));
        };
        if spec.argv.last() != Some(&task_json) {
            return Err(ByoaError::Backend(
                "dev runner adapter replaced the task".into(),
            ));
        }
        let dispatch = dispatcher.dispatch(DispatchByoa {
            user_login: request.user_login,
            connector,
            task_ref: request.task_ref,
            parent_attempt_id: request.parent_attempt_id,
            run_id: Some(request.run_ref),
            dedupe_key: None,
            now: request.now,
        })?;
        Ok(DevRunnerDispatch {
            dispatch,
            failure_corpus,
        })
    }

    /// Convert a completed runner's captured diff into a review-only proposal.
    /// Target, session and citations come from persisted engine input, never
    /// stdout. Empty diffs and unsuccessful attempts cannot propose a patch.
    /// The artifact reference keeps the full diff available for human review.
    /// Only `Vault::review_patch_pr` records an owner-ratified release; neither
    /// this method nor that review method applies code or runs a migration.
    pub fn propose_dev_runner_patch<B, E>(
        &self,
        dispatcher: &ByoaDispatcher<'_, B, E>,
        attempt_id: AttemptId,
    ) -> ByoaResult<RepairBundle>
    where
        B: ByoEndpointBackendFactory,
        E: ByoaEgressPort,
    {
        let actor = self.require_dev_runner(dispatcher.vault())?;
        let (record, connector, exhaust) = dispatcher.completed_cli_exhaust(attempt_id)?;
        let task: DevRunnerTask = connector
            .argv
            .last()
            .and_then(|json| serde_json::from_str(json).ok())
            .ok_or_else(|| Error::InvalidConfig("attempt is not a dev runner job".into()))?;
        if task.actor_ref != actor.entity_ref()
            || record.run_id.as_deref() != Some(task.run_ref.as_str())
        {
            return Err(Error::InvalidConfig("dev runner identity mismatch".into()).into());
        }
        if exhaust.diff_bundle.as_ref().is_none_or(Vec::is_empty) {
            return Err(Error::InvalidConfig("dev runner produced no patch".into()).into());
        }
        let diagnostic_refs: Vec<_> = task
            .failure_corpus
            .value
            .iter()
            .map(|failure| failure.diagnostic_ref)
            .collect();
        // Recheck current scoped access, including policy changes since dispatch.
        let current = self.dev_runner_corpus(&diagnostic_refs)?;
        if current.value != task.failure_corpus.value {
            return Err(Error::InvalidConfig("dev runner failure corpus changed".into()).into());
        }
        let patch_ref = record
            .result_ref
            .ok_or_else(|| Error::InvalidConfig("dev runner has no captured patch".into()))?
            .into_string();
        let proposal_id = crate::codebase::entity_id_from_hash_material(
            b"oneiron:self-heal:dev-runner-proposal:v1",
            &[actor.entity_ref().as_bytes(), attempt_id.as_bytes()],
        )?;
        Ok(self.submit(
            &task.run_ref,
            &task.session_tag,
            RepairProposal {
                proposal_id,
                diagnostic_refs,
                actor: RepairActor {
                    actor_class: actor.actor_class().gate_actor_class().into(),
                    actor_ref: actor.entity_ref(),
                },
                source: ClaimSource::Generated,
                target_predicate: task.target_predicate,
                operation: task.target.operation(patch_ref),
                session_tag: task.session_tag.clone(),
            },
        )?)
    }

    fn dev_runner_corpus(
        &self,
        diagnostic_refs: &[EntityId],
    ) -> Result<ScopedReadResult<Vec<DevRunnerFailure>>> {
        let requested: BTreeSet<_> = diagnostic_refs.iter().copied().collect();
        if requested.is_empty()
            || requested.len() != diagnostic_refs.len()
            || requested.len() > MAX_EVIDENCE_REFS
        {
            return Err(Error::InvalidConfig(
                "invalid dev runner diagnostic refs".into(),
            ));
        }
        let corpus = self.failure_corpus()?;
        let events: BTreeMap<_, _> = corpus.value.into_iter().collect();
        let value = requested
            .into_iter()
            .map(|id| {
                let event = events.get(&id).ok_or_else(|| {
                    Error::InvalidConfig("dev runner diagnostic is unavailable in scope".into())
                })?;
                DevRunnerFailure::from_event(id, event)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ScopedReadResult {
            value,
            receipt: corpus.receipt,
        })
    }
}
