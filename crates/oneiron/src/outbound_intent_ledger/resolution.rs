//! One delivery-knowledge reducer for a logical outbound send.
use super::{
    IntentEscalationReason, IntentLedgerError, IntentLedgerRecord, IntentLedgerResult, IntentState,
    RecordedOutboundOutcome,
};

/// What is known about delivery, independent of the latest attempt or stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnconfirmedDelivery {
    DefiniteNonDelivery,
    Unresolved,
}

/// Permission for a future attempt is separate from evidence about past sends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetryDisposition {
    Idempotent,
    DefiniteOnly,
    NoAutomaticRetry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntentResolution {
    Pending {
        delivery: UnconfirmedDelivery,
        retry: RetryDisposition,
    },
    Delivered,
    Stopped {
        delivery: UnconfirmedDelivery,
        reason: IntentEscalationReason,
    },
}

impl IntentResolution {
    pub(crate) fn from_record(record: &IntentLedgerRecord) -> IntentLedgerResult<Self> {
        match (record.state, record.recorded_outcome) {
            (IntentState::Done, Some(RecordedOutboundOutcome::Acked)) => Ok(Self::Delivered),
            (
                IntentState::Pending,
                latest @ (None | Some(RecordedOutboundOutcome::DefiniteNonDelivery)),
            ) => {
                let delivery = if record.delivery_uncertain || latest.is_none() {
                    UnconfirmedDelivery::Unresolved
                } else {
                    UnconfirmedDelivery::DefiniteNonDelivery
                };
                let retry = if record.idempotency_supported {
                    RetryDisposition::Idempotent
                } else if latest.is_some() {
                    RetryDisposition::DefiniteOnly
                } else {
                    RetryDisposition::NoAutomaticRetry
                };
                Ok(Self::Pending { delivery, retry })
            }
            (IntentState::Abandoned, Some(RecordedOutboundOutcome::Abandoned(reason))) => {
                let delivery = if record.delivery_uncertain {
                    UnconfirmedDelivery::Unresolved
                } else {
                    UnconfirmedDelivery::DefiniteNonDelivery
                };
                Ok(Self::Stopped { delivery, reason })
            }
            _ => Err(IntentLedgerError::InvalidRecord(
                "outbound intent has no delivery resolution",
            )),
        }
    }
}

/// Exact immutable binding carried by a scheduled connector TASK. The index
/// selects a candidate; it is never itself proof that a TASK owns that row.
pub(crate) struct ConnectorIntentBinding<'a> {
    pub(crate) intent: &'a crate::outbound::OutboundIntent,
    pub(crate) actor_ref: crate::entity_id::EntityId,
    pub(crate) actor_class: &'a str,
    pub(crate) counterparty_ref: Option<&'a str>,
    pub(crate) originating_session_ref: Option<&'a str>,
    pub(crate) calendar_invite: Option<&'a crate::calendar::invite::CalendarInvitePayload>,
}

impl ConnectorIntentBinding<'_> {
    pub(crate) fn verify(&self, record: &IntentLedgerRecord) -> IntentLedgerResult<()> {
        let frozen: serde_json::Value = serde_json::from_slice(record.payload())
            .map_err(|_| IntentLedgerError::InvalidRecord("invalid frozen connector binding"))?;
        let intent = serde_json::to_value(self.intent)
            .map_err(|_| IntentLedgerError::InvalidRecord("invalid connector TASK intent"))?;
        let fields = intent.as_object().ok_or(IntentLedgerError::InvalidRecord(
            "connector TASK intent must be an object",
        ))?;
        let matches_intent = fields
            .iter()
            .all(|(key, value)| frozen.get(key) == Some(value));
        let matches_frozen = frozen.get("actor_ref")
            == Some(&serde_json::json!(self.actor_ref.to_hex()))
            && frozen.get("actor_entity_ref") == Some(&serde_json::json!(self.actor_ref.to_hex()))
            && frozen.get("actor_class") == Some(&serde_json::json!(self.actor_class))
            && frozen.get("counterparty_ref") == Some(&serde_json::json!(self.counterparty_ref))
            && frozen.get("originating_session_ref")
                == Some(&serde_json::json!(self.originating_session_ref))
            && frozen
                .get("calendar_invite")
                .unwrap_or(&serde_json::Value::Null)
                == &serde_json::json!(self.calendar_invite);
        if !matches_intent || !matches_frozen || record.server != self.intent.channel {
            return Err(IntentLedgerError::InvalidRecord(
                "connector TASK does not match frozen logical send",
            ));
        }
        Ok(())
    }
}
