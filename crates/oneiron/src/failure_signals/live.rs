//! Live tier-1 counting (OF-380, FIX 2146). Each failure an engine producer
//! observed counts once, under the class it names, the moment its witness
//! exists: a detector's captured diagnostic, a fresh durable step a
//! deterministic fallback answered, a fresh durable step whose call failed,
//! and an agent dispatch's failed try (settled through the failure ladder's
//! door, or parked on a provider outage). A successful call is a witness,
//! never a count. The dedupe mark and the count land in one write: a step by
//! its claim, a diagnostic by its id, any other failure by an id over its
//! attempt, lease generation, step, call and kind, so a fresh retry is an
//! event of its own and a memo or a recovered read is none.
//!
//! A count names the affected agent only when the producer's own evidence
//! does: a diagnostic's actor, a step's host-owned envelope actor checked
//! against its attempt's dispatch, a dispatch's decoded target. It is the
//! seeded system definition by its compiled roster identity, or a custom
//! one by its stored id and version. Anything else is unattributed rather
//! than charged to the observing system or the owner. A count that fails is
//! logged by kind and never changes the work it observed.

use super::witness::WitnessKind;
use super::{
    AgentKind, AgentSurface, FailureClassV1, FailureSignalInput, FailureTaxonomy,
    VersionedComponent,
};
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::llm::{DurableStepContext, DurableStepError, LlmError};
use crate::self_heal::{DiagnosticEvent, DiagnosticEventClass};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Each observation already counted, and the time it observed. Nightly scans
/// capture the same content-addressed diagnostic again; it counts once.
/// Key: id16, the observation's id: a diagnostic's, a step claim's, or an
/// attempt failure's event id.
const COUNTED: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::FAILURE_SIGNALS_TIER1_COUNTED);

/// The agent name and version an unattributed count exports in clear.
pub(super) const UNATTRIBUTED: &str = "unattributed";

/// Domain separator for an attempt failure's event id.
const ATTEMPT_FAILURE_DOMAIN: &[u8] = b"oneiron.failure-signals.attempt-failure.v1\0";

/// The detector name an attempt failure's count reads under.
pub(super) const ATTEMPT_FAILURE_DETECTOR: &str = "attempt.failure.v1";

/// Each compiled T1 detector's tier-1 class (`None`: never counted) and
/// surface. An owner's consent refusal is the owner's choice, not an agent
/// failure; a storm of pending asks is, and so is a tray backlog at the
/// consent depth. A detector absent here is a model-graded window, counted
/// by its family's event class.
const T1_DETECTORS: [(&str, Option<FailureClassV1>, AgentSurface); 6] = [
    ("consent.denied.v1", None, AgentSurface::Other),
    (
        "retrieval.miss.v1",
        Some(FailureClassV1::MemoryMiss),
        AgentSurface::Other,
    ),
    (
        "consolidation.error.v1",
        Some(FailureClassV1::TaskFailure),
        AgentSurface::Background,
    ),
    (
        "consent.storm.v1",
        Some(FailureClassV1::Other),
        AgentSurface::Other,
    ),
    (
        "consent.queue_depth.v1",
        Some(FailureClassV1::Other),
        AgentSurface::Other,
    ),
    (
        "predicate.drift.v1",
        Some(FailureClassV1::Other),
        AgentSurface::Other,
    ),
];

/// A model-graded window's class, from the event class its host family set.
const fn window_class(class: DiagnosticEventClass) -> Option<FailureClassV1> {
    match class {
        DiagnosticEventClass::ConsentDenied | DiagnosticEventClass::AgentBlocked => None,
        DiagnosticEventClass::RetrievalMiss => Some(FailureClassV1::MemoryMiss),
        DiagnosticEventClass::ConsolidationError | DiagnosticEventClass::DreamerRunDegenerate => {
            Some(FailureClassV1::TaskFailure)
        }
        DiagnosticEventClass::SilentConversationDegradation => {
            Some(FailureClassV1::SilentDegradation)
        }
        _ => Some(FailureClassV1::Other),
    }
}

/// How an agent dispatch's try failed, as its host settled it (FIX 2146).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchFailure {
    /// The try failed through the failure ladder's lease-fenced door: it was
    /// retried, or it ended.
    Settled,
    /// A model call no provider answered parked the try.
    ProviderOutage,
}

impl DispatchFailure {
    const fn kind(self) -> &'static str {
        match self {
            Self::Settled => "dispatch.settled",
            Self::ProviderOutage => "dispatch.provider_outage",
        }
    }
}

/// One failure on a committed attempt that no step claim stands for: the
/// try, its lease generation, the step and call that failed (zeros for the
/// whole try) and what happened.
struct AttemptFailure {
    attempt: AttemptId,
    lease: u32,
    step: [u8; 32],
    call: u32,
    kind: &'static str,
}

impl AttemptFailure {
    /// The event's id, over all of it.
    fn id(&self) -> Result<EntityId> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ATTEMPT_FAILURE_DOMAIN);
        hasher.update(self.attempt.as_bytes());
        hasher.update(&self.lease.to_be_bytes());
        hasher.update(&self.step);
        hasher.update(&self.call.to_be_bytes());
        hasher.update(&(self.kind.len() as u64).to_be_bytes());
        hasher.update(self.kind.as_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        EntityId::from_bytes(id)
    }
}

/// The agent a dispatch attempt's decoded target names; `None` for a row
/// that is no agent dispatch this can read.
fn dispatched_agent(record: &AttemptRecord) -> Option<EntityId> {
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    decode_agent_dispatch_input(&payload.input)
        .ok()?
        .target
        .agent_definition_ref()
        .ok()
}

/// The agent a step's host-owned envelope `actor` names, checked against its
/// attempt's dispatch: a dispatched agent's step counts for that agent only
/// when the actor is the dispatch's target. Never the step's claim subject.
pub(super) fn step_agent(record: &AttemptRecord, actor: EntityId) -> Option<EntityId> {
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Some(actor);
    }
    (dispatched_agent(record)? == actor).then_some(actor)
}

/// An attempt failure's evidence, re-read from base: its attempt, under the
/// lease generation it failed in.
pub(super) fn verify_attempt_failure(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    lease: u32,
) -> Result<()> {
    let Some(record) = AttemptQueue::new(vault).get_in_txn(rtxn, attempt)? else {
        return Err(Error::InvalidConfig(
            "failed attempt is no longer live".into(),
        ));
    };
    if record.attempt_count != lease {
        return Err(Error::InvalidConfig(
            "failed attempt was leased again".into(),
        ));
    }
    Ok(())
}

impl Vault {
    /// The count one captured diagnostic records, or `None` when its
    /// detector is not an agent failure. It names the agent the diagnostic's
    /// own actor is, when that is an agent definition.
    pub(super) fn diagnostic_input(&self, event: &DiagnosticEvent) -> Option<FailureSignalInput> {
        let (class, surface) = match T1_DETECTORS
            .iter()
            .find(|(id, _, _)| *id == event.detector_id)
        {
            Some((_, class, surface)) => (*class, *surface),
            None => (window_class(event.event_class), AgentSurface::Other),
        };
        Some(self.affected_agent_input(class?, surface, event.actor_ref))
    }

    /// The count of a `class` failure on `surface`, for the agent `agent`
    /// names (FIX 2146): a seeded system definition by its compiled roster
    /// identity, a custom one by its stored id and version. No agent, or one
    /// that is no agent definition, is unattributed.
    pub(super) fn affected_agent_input(
        &self,
        class: FailureClassV1,
        surface: AgentSurface,
        agent: Option<EntityId>,
    ) -> FailureSignalInput {
        let (agent_kind, component, agent_ref) = match agent.map(|id| self.agent_identity(id)) {
            Some(Ok(Some((kind, component, id)))) => (kind, component, Some(id)),
            Some(Err(error)) => {
                tracing::debug!(kind = ?error.kind(), "a failure's agent did not resolve");
                (AgentKind::Unattributed, unattributed(), None)
            }
            Some(Ok(None)) | None => (AgentKind::Unattributed, unattributed(), None),
        };
        FailureSignalInput {
            taxonomy: FailureTaxonomy::V1(class),
            agent_surface: surface,
            agent_kind,
            agent: component,
            agent_ref,
        }
    }

    /// The export identity of the agent definition `id`; `None` when `id`
    /// is no agent definition.
    fn agent_identity(
        &self,
        id: EntityId,
    ) -> Result<Option<(AgentKind, VersionedComponent, EntityId)>> {
        if let Some((name, version)) = crate::agent_def::system_export_identity(&id)? {
            let component = VersionedComponent {
                name: name.to_owned(),
                version: version.to_owned(),
            };
            return Ok(Some((AgentKind::System, component, id)));
        }
        match self.get_agent_definition(&id) {
            Ok(Some(definition)) => {
                let component = VersionedComponent {
                    name: definition.agent_id,
                    version: definition.version,
                };
                Ok(Some((AgentKind::Custom, component, id)))
            }
            Ok(None) | Err(Error::Artifact(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Counts the observation `id` once, its dedupe mark and its count in
    /// one write: of two passes, only the first counts it. A witness that
    /// no longer verifies, or none, counts nothing. An agent the record door
    /// refuses to name (an identity past its bound) still counts,
    /// unattributed, as it did before it was named.
    pub(super) fn count_tier1_observation(
        &self,
        id: EntityId,
        input: FailureSignalInput,
        observed_at: u64,
    ) -> Result<()> {
        let Some(observation) = self.tier1_observation(id)? else {
            return Ok(());
        };
        let named = input.agent_kind != AgentKind::Unattributed;
        let fallback = FailureSignalInput {
            agent_kind: AgentKind::Unattributed,
            agent: unattributed(),
            agent_ref: None,
            ..input.clone()
        };
        let dimensions = match self.failure_signal_dimensions(&observation, input) {
            Err(Error::InvalidConfig(_)) if named => {
                self.failure_signal_dimensions(&observation, fallback)
            }
            dimensions => dimensions,
        };
        let dimensions = match dimensions {
            Ok(Some(dimensions)) => dimensions,
            Ok(None) | Err(Error::InvalidConfig(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        let (key, json) = super::count_key(&dimensions)?;
        self.with_write_txn_grouped(|txn| {
            if COUNTED.contains(&self.store, txn, &id)? {
                return Ok(());
            }
            COUNTED.put(&self.store, txn, &id, &observed_at)?;
            super::add_count_in_txn(self, txn, &key, &json)
        })
    }

    /// Counts an agent dispatch's failed try once (FIX 2146), after its
    /// host's lease-fenced transition committed, for the agent its decoded
    /// dispatch targets. `lease` is the lease generation it failed in, `now`
    /// Unix seconds. A count that fails is logged by kind and changes
    /// nothing the host did.
    pub fn count_dispatch_failure(
        &self,
        attempt: AttemptId,
        lease: u32,
        failure: DispatchFailure,
        now: u64,
    ) {
        if let Err(error) = self.try_count_dispatch_failure(attempt, lease, failure, now) {
            tracing::warn!(kind = ?error.kind(), "a dispatch failure was not counted");
        }
    }

    fn try_count_dispatch_failure(
        &self,
        attempt: AttemptId,
        lease: u32,
        failure: DispatchFailure,
        now: u64,
    ) -> Result<()> {
        if !self.config.failure_signals.exports() {
            return Ok(());
        }
        let Some(record) = AttemptQueue::new(self).get(attempt)? else {
            return Ok(());
        };
        if record.attempt_count != lease {
            return Ok(());
        }
        let event = AttemptFailure {
            attempt,
            lease,
            step: [0; 32],
            call: 0,
            kind: failure.kind(),
        };
        let agent = dispatched_agent(&record);
        self.count_attempt_failure(&event, agent, AgentSurface::Task, now)
    }

    /// Counts a fresh durable step whose call failed once (FIX 2146): a
    /// provider's failure, or an answer the step refused. `error` is `None`
    /// for a failure the caller already knows is the model call's; a
    /// deadline, a spent budget or a storage error is no failed execution.
    /// It counts for the agent the step's host-owned envelope actor names,
    /// checked against its attempt's dispatch. A count that fails is logged
    /// by kind and never fails the step.
    pub(crate) fn count_failed_step(
        &self,
        ctx: &DurableStepContext<'_>,
        step: [u8; 32],
        error: Option<&DurableStepError>,
    ) {
        let failed = match error {
            None => true,
            Some(DurableStepError::Llm(LlmError::BudgetDenied(_))) => false,
            Some(DurableStepError::Llm(_) | DurableStepError::SpentSchemaValidation { .. }) => true,
            Some(DurableStepError::SchemaValidation { attempts, .. }) => *attempts > 0,
            Some(_) => false,
        };
        if !failed {
            return;
        }
        if let Err(error) = self.try_count_failed_step(ctx, step) {
            tracing::warn!(kind = ?error.kind(), "a failed step was not counted");
        }
    }

    fn try_count_failed_step(&self, ctx: &DurableStepContext<'_>, step: [u8; 32]) -> Result<()> {
        if !self.config.failure_signals.exports() {
            return Ok(());
        }
        let Some(record) = AttemptQueue::new(self).get(ctx.attempt_id)? else {
            return Ok(());
        };
        if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND
            || record.run_id != ctx.run_id
        {
            return Ok(());
        }
        let event = AttemptFailure {
            attempt: ctx.attempt_id,
            lease: record.attempt_count,
            step,
            call: 0,
            kind: "step.failed",
        };
        let agent = step_agent(&record, ctx.envelope_actor.entity_ref());
        self.count_attempt_failure(&event, agent, AgentSurface::Background, ctx.now_ms / 1_000)
    }

    /// Registers the failure's witness, bound to its committed attempt and
    /// lease generation, and counts it once as a task failure.
    fn count_attempt_failure(
        &self,
        event: &AttemptFailure,
        agent: Option<EntityId>,
        surface: AgentSurface,
        at: u64,
    ) -> Result<()> {
        let id = event.id()?;
        let observed_at = i64::try_from(at)
            .map_err(|_| Error::ArithmeticOverflow("failure signal observation time"))?;
        self.register_tier1_witness(
            id,
            WitnessKind::AttemptFailure {
                attempt_id: event.attempt,
                lease: event.lease,
                observed_at,
            },
        )?;
        let input = self.affected_agent_input(FailureClassV1::TaskFailure, surface, agent);
        self.count_tier1_observation(id, input, at)
    }
}

/// The unattributed agent component.
fn unattributed() -> VersionedComponent {
    VersionedComponent {
        name: UNATTRIBUTED.into(),
        version: UNATTRIBUTED.into(),
    }
}
