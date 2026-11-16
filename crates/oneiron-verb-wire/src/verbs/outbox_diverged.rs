//! Moved from `crates/oneiron/src/verbs/outbox_diverged.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_vault_contract::vm_outbox::VmOutboxKind;
use serde::Deserialize;
use serde::Serialize;

/// The owner's answer to a diverged copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutboxDivergedAnswer {
    /// The copy moves aside under its own name, listed as kept aside until
    /// it is removed, so the member's next version lands.
    Keep,
    /// The copy is removed at the carrier's next turn; a kept-aside copy's
    /// side copy is deleted on the end that holds it.
    Remove,
}

/// The owner's answer to the copy the page lists with digest `held`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutboxDivergedAnswerRequest {
    /// The outbox kind, as the page lists it.
    #[schemars(with = "String")]
    pub kind: VmOutboxKind,
    pub member: String,
    /// The kept copy's digest, as the page lists it.
    pub held: String,
    pub answer: OutboxDivergedAnswer,
}

/// What the owner's answer did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutboxDivergedAnswerReceipt {
    #[schemars(with = "String")]
    pub kind: VmOutboxKind,
    pub member: String,
    pub held: String,
    pub answer: OutboxDivergedAnswer,
    /// The companion took it for its carrier's next turn.
    pub queued: bool,
}
