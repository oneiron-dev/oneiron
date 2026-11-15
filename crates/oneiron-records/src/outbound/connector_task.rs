//! Moved from `crates/oneiron/src/outbound/connector_task.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::outbound::connector_task::UncertainSendAnswerOutcome;
use serde::Deserialize;
use serde::Serialize;

/// Terminal delivery projection carried by the synced connector-send TASK.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSendTaskOutcome {
    Delivered,
    Failed,
    Ambiguous,
    /// The send may have gone out, no lookup could tell, and the owner
    /// answered not to resend it (FIX 4747). Nothing sends it again.
    OwnerDeclinedResend,
}

/// A send that may have gone out and that no provider lookup could settle,
/// waiting for the owner's word (FIX 4747; canon ARCH-0023b "Still unknown:
/// ask the owner before any retry"): its TASK sends nothing until he answers
/// the inbox ask it raised.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UncertainSendHold {
    /// When the engine asked the owner, vault clock seconds; the ask's rows
    /// carry it.
    pub asked_at: u64,
    /// The owner answered resend: the TASK's executor sends it once.
    #[serde(default)]
    pub resend_released: bool,
}

/// The sticky send executor of one connector-send TASK (FIX 4747; canon
/// ARCH-0023b, pending outbound send): only the machine `node_id` names
/// sends it, and only while the TASK still holds this holder at this
/// `generation`. A handover moves it to another machine at the next
/// `generation`. The holder renews `held_until` while the TASK is its to
/// send; a lease no pass renewed, or one its holder released as it closed,
/// is expired from `held_until` on, and another machine's reaper may take it
/// (FIX 4747 slice 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendExecutorLease {
    /// The holder's stable sync node id (`m:client_id`).
    pub node_id: u64,
    /// Raised by one on every handover; a take from no lease starts at
    /// [`SEND_EXECUTOR_LEASE_FIRST_GENERATION`].
    pub generation: u64,
    /// Until when the holder holds it, vault clock seconds, as the TASK's
    /// other times: expired at and after this instant.
    pub held_until: u64,
}

impl SendExecutorLease {
    /// Whether `other` names this lease's holder at this generation,
    /// whatever either's `held_until`: a renewal or a release keeps the
    /// holding, so the holder's attempt in flight still passes its fence.
    #[must_use]
    pub fn same_holding(self, other: Self) -> bool {
        self.node_id == other.node_id && self.generation == other.generation
    }

    /// Whether the lease is expired at `now`: its holder neither renewed it
    /// past `now` nor holds it any more, so the reaper may take it.
    #[must_use]
    pub fn expired_at(self, now: u64) -> bool {
        now >= self.held_until
    }
}
