//! Moved from `crates/oneiron/src/verbs/custody_drain.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::check_in::effect::CheckInDecision;
use oneiron_verb_wire::store::key_custody::protocol::AckPosition;
pub use oneiron_verb_wire::verbs::custody_drain::CustodyDrainCommitRequest;
pub use oneiron_verb_wire::verbs::custody_drain::CustodyMemberReenrolRequest;
pub use oneiron_verb_wire::verbs::custody_drain::CustodyMemberRef;
use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroize;

/// A begun drain: what the member's ack must name, and the token it MACs
/// the ack with. A retry before the set changes returns the same ticket.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyDrainTicketView {
    /// The member being drained.
    pub target_id: String,
    /// The set revision it is drained out of.
    pub set_revision: u64,
    /// The local log position the drain began at.
    pub position: AckPosition,
    /// The drain's operation id, 64 hex.
    pub operation_id: String,
    /// The drain's generation token, 64 hex: for the member's own adapter.
    pub token: String,
    /// The check-in decision the begin ran on (2k3): the Owner on their own
    /// proof, and the approved check-in of another asker it applied, with
    /// its requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
}

impl Drop for CustodyDrainTicketView {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl std::fmt::Debug for CustodyDrainTicketView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodyDrainTicketView")
            .field("target_id", &self.target_id)
            .field("set_revision", &self.set_revision)
            .field("position", &self.position)
            .field("operation_id", &self.operation_id)
            .field("check_in", &self.check_in)
            .finish_non_exhaustive()
    }
}

/// The required set's revision after the owner's change, and the check-in
/// decision the change ran on (2k3): the Owner on their own proof, and the
/// approved check-in of another asker it applied, with its requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodySetRevision {
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
}
