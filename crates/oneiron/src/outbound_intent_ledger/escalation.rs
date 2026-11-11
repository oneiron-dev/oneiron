//! Why a send stopped and needs its caller: the typed escalation reasons a
//! ledger row records when it is abandoned.

/// Machine-readable reason that requires caller escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentEscalationReason {
    NonIdempotentAmbiguous,
    NonIdempotentPending,
    ConnectorRevoked,
    BindingInvalid,
    PreviouslyAbandoned,
    CorruptLedgerRow,
    DedupeReservationReplaced,
    DedupeSuppressed,
    /// The owner stopped the try that admitted the send (FIX 7188): the row
    /// keeps what it knew of its delivery.
    OwnerStopped,
    /// The owner set the tool to `never allow` (DEC-0006) before this
    /// request was sent: it stops, keeping what it knew of its delivery.
    ConnectorSlateNeverAllow,
    /// The actor that admitted this send was erased before it settled: its
    /// request is gone and it is never sent again, keeping what it knew of
    /// its delivery (FIX 9283).
    ActorErased,
    /// The person a send went to was erased before it settled: its request
    /// is gone and it is never sent again (FIX 10953).
    RecipientErased,
    /// The owner erased this call's frozen request (KS7-4b): it is never
    /// sent again, and the row keeps only its evidence.
    OwnerErased,
    /// The provider reported that the remote task it accepted the send as
    /// failed or was cancelled (FIX 7960).
    RemoteTaskFailed,
    /// The owner whose word admitted this send is no longer a live owner of
    /// the vault (FIX 11591): the send that authority stood on stops before
    /// any transport, keeping what it knew of its delivery.
    OwnerNotLive,
    /// The grant this send was admitted under no longer stands (FIX 11591):
    /// the send stops before any transport, keeping what it knew of its
    /// delivery.
    GrantNotStanding,
    /// This machine does not hold its connector-send TASK's send executor
    /// lease (FIX 4747): it stood down, and its local send, which certainly
    /// never went, stops here and gives its reserved budget back. The shared
    /// TASK stays the lease holder's to send.
    SendExecutorStoodDown,
}

impl IntentEscalationReason {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::NonIdempotentAmbiguous => "non_idempotent_ambiguous",
            Self::NonIdempotentPending => "non_idempotent_pending",
            Self::ConnectorRevoked => "connector_revoked",
            Self::BindingInvalid => "binding_invalid",
            Self::PreviouslyAbandoned => "previously_abandoned",
            Self::CorruptLedgerRow => "corrupt_ledger_row",
            Self::DedupeReservationReplaced => "dedupe_reservation_replaced",
            Self::DedupeSuppressed => "dedupe_suppressed",
            Self::OwnerStopped => "owner_stopped",
            Self::ConnectorSlateNeverAllow => "connector_key_slate_never_allow",
            Self::ActorErased => "actor_erased",
            Self::RecipientErased => "recipient_erased",
            Self::OwnerErased => "owner_erased",
            Self::RemoteTaskFailed => "remote_task_failed",
            Self::OwnerNotLive => "owner_not_live",
            Self::GrantNotStanding => "grant_not_standing",
            Self::SendExecutorStoodDown => "send_executor_stood_down",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "non_idempotent_ambiguous" => Some(Self::NonIdempotentAmbiguous),
            "non_idempotent_pending" => Some(Self::NonIdempotentPending),
            "connector_revoked" => Some(Self::ConnectorRevoked),
            "binding_invalid" => Some(Self::BindingInvalid),
            "previously_abandoned" => Some(Self::PreviouslyAbandoned),
            "corrupt_ledger_row" => Some(Self::CorruptLedgerRow),
            "dedupe_reservation_replaced" => Some(Self::DedupeReservationReplaced),
            "dedupe_suppressed" => Some(Self::DedupeSuppressed),
            "owner_stopped" => Some(Self::OwnerStopped),
            "connector_key_slate_never_allow" => Some(Self::ConnectorSlateNeverAllow),
            "actor_erased" => Some(Self::ActorErased),
            "recipient_erased" => Some(Self::RecipientErased),
            "owner_erased" => Some(Self::OwnerErased),
            "remote_task_failed" => Some(Self::RemoteTaskFailed),
            "owner_not_live" => Some(Self::OwnerNotLive),
            "grant_not_standing" => Some(Self::GrantNotStanding),
            "send_executor_stood_down" => Some(Self::SendExecutorStoodDown),
            _ => None,
        }
    }
}
