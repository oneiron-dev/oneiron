//! Connector wake delivery retains its typed event; it is not a partition job.
use super::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerParkCause, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::connector_key::events::ConnectorEvent;
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
use crate::outbound::{
    ConnectorReply, ConnectorReplyDispatch, OutboundDispatchError, OutboundDispatchOutcome,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
    connector_reply_request,
};
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
        .any(|s| s.trim().is_empty() || s.len() > 256 || s.contains('\0'))
        {
            return Err(invalid());
        }
        Ok(Self { agent, event })
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

/// What a host runs for one connector wake (OF-218): the target agent's turn
/// on the event, and the sink its reply leaves through. The executor never
/// sends on its own; a reply crosses
/// [`Vault::dispatch_connector_reply`](crate::Vault::dispatch_connector_reply),
/// so gate, budget, window, intent ledger and receipt all apply.
pub trait ConnectorEventResponder {
    /// Runs `wake.agent` on the event. `Ok(None)`: the agent wrote no reply.
    ///
    /// # Errors
    /// The turn could not run; the driver parks the attempt.
    fn reply(&mut self, vault: &Vault, wake: &ConnectorEventWake)
    -> Result<Option<ConnectorReply>>;

    /// The host's sink for the reply's channel and thread, its per-send plan
    /// keyed by `dispatch.request.intent_ref`.
    ///
    /// # Errors
    /// The host has no transport for this channel.
    fn sink(
        &mut self,
        wake: &ConnectorEventWake,
        dispatch: &ConnectorReplyDispatch,
    ) -> Result<&mut dyn OutboundExecutionSink>;
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
        let Some(reply) = responder.reply(ctx.vault, &wake)? else {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        };
        let dispatch = connector_reply_request(&wake.event, &reply)?;
        let sink = responder.sink(&wake, &dispatch)?;
        let result = ctx
            .vault
            .dispatch_connector_reply(&wake.event, &reply, &mut BorrowedSink(sink))
            .map_err(|err| match err {
                OutboundDispatchError::Engine(err) => err,
                other => Error::InvalidConfig(format!("connector reply dispatch: {other}")),
            })?;
        // A reply that did not leave parks the wake; its resume re-sends the
        // kept body, never a second model call. An ambiguous send may have
        // landed, so it waits for a look rather than an automatic resend.
        Ok(match result.outcome {
            OutboundDispatchOutcome::DeliveredToChannel
            | OutboundDispatchOutcome::Degraded
            | OutboundDispatchOutcome::Suppressed
            | OutboundDispatchOutcome::LetGo => {
                DreamerAttemptExecution::Completed { completed_units: 0 }
            }
            OutboundDispatchOutcome::Held => DreamerAttemptExecution::Park {
                reason: format!(
                    "connector reply held: {}",
                    result.gate_reason_codes.join(",")
                ),
                cause: DreamerParkCause::Signal,
            },
            OutboundDispatchOutcome::Failed => DreamerAttemptExecution::Park {
                reason: "connector reply failed".to_owned(),
                cause: DreamerParkCause::ProviderUnavailable,
            },
            OutboundDispatchOutcome::Ambiguous => DreamerAttemptExecution::Park {
                reason: "connector reply ambiguous".to_owned(),
                cause: DreamerParkCause::Other,
            },
        })
    }
}

/// A host's borrowed sink, sized for the generic dispatch door.
struct BorrowedSink<'a>(&'a mut dyn OutboundExecutionSink);

impl OutboundExecutionSink for BorrowedSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.0.execute(request)
    }
}
