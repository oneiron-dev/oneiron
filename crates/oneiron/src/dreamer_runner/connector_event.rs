//! Connector wake delivery retains its typed event; it is not a partition job.
use super::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::connector_key::events::ConnectorEvent;
use crate::{ClaimSource, EntityId, Error, Result};
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
