//! One delivery-knowledge reducer for a logical outbound send.
use super::{
    CallAccounting, IntentEscalationReason, IntentLedgerError, IntentLedgerRecord,
    IntentLedgerResult, IntentState, RecordedOutboundOutcome,
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
    /// The provider accepted the send as a remote task (FIX 7960): it is
    /// never sent again, and its delivery is not yet known.
    Deferred,
}

impl IntentResolution {
    pub(crate) fn from_record(record: &IntentLedgerRecord) -> IntentLedgerResult<Self> {
        Self::reduce(
            record.state,
            record.recorded_outcome,
            record.delivery_uncertain,
            record.idempotency_supported,
        )
    }

    /// The resolution of a call a restore kept only the accounting of
    /// (KS7-5, FIX 12117). Its idempotency is not kept, so none is assumed.
    pub(crate) fn from_accounting(accounting: &CallAccounting) -> IntentLedgerResult<Self> {
        Self::reduce(
            accounting.state,
            accounting.recorded_outcome,
            accounting.delivery_uncertain,
            false,
        )
    }

    fn reduce(
        state: IntentState,
        recorded_outcome: Option<RecordedOutboundOutcome>,
        delivery_uncertain: bool,
        idempotency_supported: bool,
    ) -> IntentLedgerResult<Self> {
        match (state, recorded_outcome) {
            (IntentState::Done, Some(RecordedOutboundOutcome::Acked)) => Ok(Self::Delivered),
            (IntentState::Deferred, Some(RecordedOutboundOutcome::Deferred)) => Ok(Self::Deferred),
            (
                IntentState::Pending,
                latest @ (None | Some(RecordedOutboundOutcome::DefiniteNonDelivery)),
            ) => {
                let delivery = if delivery_uncertain || latest.is_none() {
                    UnconfirmedDelivery::Unresolved
                } else {
                    UnconfirmedDelivery::DefiniteNonDelivery
                };
                let retry = if idempotency_supported {
                    RetryDisposition::Idempotent
                } else if latest.is_some() {
                    RetryDisposition::DefiniteOnly
                } else {
                    RetryDisposition::NoAutomaticRetry
                };
                Ok(Self::Pending { delivery, retry })
            }
            (IntentState::Abandoned, Some(RecordedOutboundOutcome::Abandoned(reason))) => {
                let delivery = if delivery_uncertain {
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
        // An erased row has no frozen request left to bind against (FIX
        // 10957): its terminal state is the authority, and `from_record`
        // settles it as that stop instead of erroring the reconcile.
        if super::payload::payload_erased(record.payload())? {
            return Ok(());
        }
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
