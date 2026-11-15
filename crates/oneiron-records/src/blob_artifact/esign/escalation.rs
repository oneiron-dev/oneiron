//! Moved from `crates/oneiron/src/blob_artifact/esign/escalation.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::store::decision_ask_role::AskRole;
use serde::Deserialize;
use serde::Serialize;

/// The answer that lands the held signature.
pub const HOLD_ALLOW: &str = "allow";

/// The answer that keeps the signature from landing.
pub const HOLD_DECLINE: &str = "decline";

/// Where one hold stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HeldSigningState {
    /// Held; the host's next pass asks its first role.
    Held,
    /// Waits in the role ask queue under `question` (hex). `wait` is the
    /// role the ask's wait is timed at and since when, set at each climb;
    /// none while it waits at the role it was first asked at, timed from
    /// the ask.
    Asked {
        question: String,
        wait: Option<HeldAskWait>,
    },
    /// A role holder allowed it, and the signature landed.
    Allowed { at: u64 },
    /// A role holder declined it; the signature did not land.
    Declined { at: u64 },
    /// The document moved on before the answer could land: the recipient's
    /// turn passed or the document ended.
    Superseded { at: u64 },
}

/// The rung a held sign act's ask waits at, and since when: each rung of a
/// multi-hop chain waits its own [`ESIGN_ASK_CLIMB_HOURS`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldAskWait {
    pub role: AskRole,
    pub since: u64,
}
