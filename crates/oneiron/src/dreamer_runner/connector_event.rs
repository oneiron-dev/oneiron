//! Connector wake delivery retains its typed event; it is not a partition job.
use super::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::attempt_queue::AttemptId;
use crate::connector_key::events::ConnectorEvent;
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
use crate::{ClaimSource, EntityId, Error, Result, Vault};
use rmpv::Value;

pub const CONNECTOR_EVENT_QUEUE_KIND: &str = "dreamer.connector_event";
pub const CONNECTOR_EVENT_FACET: &str = "connector_event";

/// The event consumer receives data, never executable instructions or a grant.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorEventWake {
    pub agent: EntityId,
    pub event: ConnectorEvent,
}
impl ConnectorEventWake {
    pub fn from_attempt(attempt: &DreamerAdmittedAttempt) -> Result<Self> {
        if attempt.status.attempt.kind != CONNECTOR_EVENT_QUEUE_KIND
            || attempt.status.payload.attempt_type != CONNECTOR_EVENT_FACET
        {
            return Err(invalid());
        }
        let Value::Map(fields) = &attempt.status.payload.input else {
            return Err(invalid());
        };
        if fields.len() != 3 {
            return Err(invalid());
        }
        let one = |name: &str| -> Result<&Value> {
            let mut values = fields.iter().filter(|(key, _)| key.as_str() == Some(name));
            let (_, value) = values.next().ok_or_else(invalid)?;
            if values.next().is_some() {
                return Err(invalid());
            }
            Ok(value)
        };
        if one("source")?.as_str() != Some("tool_output") {
            return Err(invalid());
        }
        let Value::Binary(agent) = one("agent_ref")? else {
            return Err(invalid());
        };
        let agent = EntityId::from_bytes(agent.as_slice().try_into().map_err(|_| invalid())?)?;
        let event: ConnectorEvent =
            serde_json::from_str(one("connector_event")?.as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        if [
            &event.event_id,
            &event.connector,
            &event.event_kind,
            &event.predicate,
        ]
        .iter()
        .any(|s| s.trim().is_empty() || s.contains('\0'))
        {
            return Err(invalid());
        }
        Ok(Self { agent, event })
    }
    /// The agent a connector-event input names, read as
    /// [`Self::from_attempt`] reads it: the `agent_ref` of the three-field
    /// `tool_output` map. The event body is not validated here; only the
    /// agent is needed, and only it is returned.
    pub(crate) fn agent_of_input(input: &Value) -> Result<EntityId> {
        let Value::Map(fields) = input else {
            return Err(invalid());
        };
        if fields.len() != 3 {
            return Err(invalid());
        }
        let one = |name: &str| -> Result<&Value> {
            let mut values = fields.iter().filter(|(key, _)| key.as_str() == Some(name));
            let (_, value) = values.next().ok_or_else(invalid)?;
            if values.next().is_some() {
                return Err(invalid());
            }
            Ok(value)
        };
        if one("source")?.as_str() != Some("tool_output") {
            return Err(invalid());
        }
        let Value::Binary(agent) = one("agent_ref")? else {
            return Err(invalid());
        };
        EntityId::from_bytes(agent.as_slice().try_into().map_err(|_| invalid())?)
    }
    pub const fn source(&self) -> ClaimSource {
        ClaimSource::ToolOutput
    }
}
fn invalid() -> Error {
    Error::InvalidConfig("invalid connector event wake".into())
}
impl DreamerRunnerStore<'_> {
    pub(crate) fn enqueue_connector_event_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        payload: DreamerAttemptPayload,
        dedupe: Option<String>,
        run: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        if payload.attempt_type != CONNECTOR_EVENT_FACET {
            return Err(invalid());
        }
        self.enqueue_kind_in_txn(txn, CONNECTOR_EVENT_QUEUE_KIND, payload, dedupe, run, now)
    }
    /// Host event executors use the same budget admission and settlement path.
    pub fn admit_next_connector_event(
        &self,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(CONNECTOR_EVENT_QUEUE_KIND, input)
    }
}

/// What a host runs for one connector wake (OF-218): the hand-off of the
/// target agent's reply to the host's durable reply work (FIX 2405). The
/// pass never generates, sends or waits on a model call; the host's reply
/// worker does, off the pass, and its reply crosses
/// [`Vault::dispatch_connector_reply`](crate::Vault::dispatch_connector_reply),
/// so gate, budget, window, intent ledger and receipt all apply.
pub trait ConnectorEventResponder {
    /// Hands `wake`'s reply off and returns at once: queues one durable
    /// reply job for the agent and event (see
    /// [`Vault::enqueue_connector_reply_job`](crate::Vault::enqueue_connector_reply_job)),
    /// or answers that the event is not one it replies to. `parent` is the
    /// wake attempt handing off.
    ///
    /// # Errors
    /// The job could not be queued; the driver parks the attempt.
    fn handoff(
        &mut self,
        vault: &Vault,
        wake: &ConnectorEventWake,
        parent: AttemptId,
        now: u64,
    ) -> Result<ConnectorEventReplyHandoff>;
}

/// What a responder's hand-off did with one wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorEventReplyHandoff {
    /// The event is not one the agent answers here.
    NoReply,
    /// The reply is queued as this job; the job carries its spend.
    Queued { job: AttemptId },
}

/// Wraps the Dreamer's executor chain with the connector-event arm.
///
/// Installed by the production factory always, responder or not: a typed
/// connector wake reaching the partition decoder is a decode error and a
/// parked driver. With no responder a wake is delivered and settled at zero
/// units; a surface-born event already sits in the agent's inbox.
pub struct ConnectorEventExecutor<'p, E> {
    inner: E,
    responder: Option<&'p mut dyn ConnectorEventResponder>,
}

impl<'p, E> ConnectorEventExecutor<'p, E> {
    #[must_use]
    pub fn new(inner: E, responder: Option<&'p mut dyn ConnectorEventResponder>) -> Self {
        Self { inner, responder }
    }
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for ConnectorEventExecutor<'_, E> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if attempt.status.attempt.kind != CONNECTOR_EVENT_QUEUE_KIND {
            return self.inner.execute(attempt, ctx).await;
        }
        let wake = ConnectorEventWake::from_attempt(attempt)?;
        let Some(responder) = self.responder.as_deref_mut() else {
            tracing::info!(
                agent = %wake.agent.to_hex(),
                connector = %wake.event.connector,
                "connector wake delivered with no responder installed"
            );
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        };
        // The pass hands the reply off and settles at once: it spent nothing,
        // and the job carries the model spend and the send's outcome.
        let parent = attempt.status.attempt.id;
        match responder.handoff(ctx.vault, &wake, parent, crate::unix_seconds_now())? {
            ConnectorEventReplyHandoff::NoReply => {}
            ConnectorEventReplyHandoff::Queued { job } => {
                tracing::info!(
                    agent = %wake.agent.to_hex(),
                    ?job,
                    "connector reply handed to the reply worker"
                );
            }
        }
        Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
    }
}
