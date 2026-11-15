//! Moved from `crates/oneiron/src/verbs/outbox_diverged.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_vault_contract::vm_outbox::VmOutboxKind;
use oneiron_vault_contract::vm_outbox::VmOutboxSide;
pub use oneiron_verb_wire::verbs::outbox_diverged::OutboxDivergedAnswer;
pub use oneiron_verb_wire::verbs::outbox_diverged::OutboxDivergedAnswerReceipt;
pub use oneiron_verb_wire::verbs::outbox_diverged::OutboxDivergedAnswerRequest;
use serde::Deserialize;
use serde::Serialize;

/// The carrier's members as the owner sees them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxDivergedPage {
    /// Whether the vault's outbox companion answered; `false` on a vault
    /// that runs outside a VM or whose companion is down.
    pub carrier: bool,
    pub members: Vec<OutboxDivergedMember>,
}

/// One member's typed status, and the card a surface shows the owner for
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxDivergedMember {
    #[serde(flatten)]
    pub status: OutboxMemberStatus,
    pub card: OutboxOwnerCard,
}

/// One carrier member's status, as the guest carrier reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OutboxMemberStatus {
    /// A copy the carrier never agreed on, kept by `held_by` as the
    /// member's origin retired the agreed version, whose digest is `retired`
    /// when the retirement named one. `answer` is the owner's, once given: a
    /// removal stands here until it is carried.
    DivergedUnagreed {
        kind: VmOutboxKind,
        member: String,
        held_by: VmOutboxSide,
        /// The kept copy's digest, which an answer names.
        held: String,
        length: u64,
        retired: Option<String>,
        answer: Option<OutboxDivergedAnswer>,
    },
    /// The guest's own file, whose put the host refused as
    /// `digest_mismatch`, read again: it hashes to `read`, no longer to
    /// `recorded`, so none of it is sent until it changes (FIX 11075).
    SourceDigestMismatch {
        kind: VmOutboxKind,
        member: String,
        recorded: String,
        read: String,
    },
    /// A diverged copy the owner kept, which `held_by` moved aside to its
    /// side name `aside` (relative to the kind's root) at `kept_at_ms`
    /// (FIX 11985). `removing` once he had it removed, until the host
    /// answers; `failed` why the last removal did not go through. Its card
    /// offers the removal, which names `held`.
    KeptAside {
        kind: VmOutboxKind,
        member: String,
        held_by: VmOutboxSide,
        held: String,
        length: u64,
        aside: String,
        kept_at_ms: u64,
        removing: bool,
        failed: Option<String>,
    },
}

/// A generic owner card: a headline, a body in plain words, and the answers
/// it offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxOwnerCard {
    pub kind: OutboxCardKind,
    pub headline: String,
    pub body: String,
    pub actions: Vec<OutboxCardAction>,
}

/// What an outbox owner card is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxCardKind {
    /// A copy the carrier never agreed on.
    OutboxDiverged,
    /// A file held back as damaged at its source.
    OutboxSourceDamaged,
    /// A copy the owner kept, moved aside under its own name.
    OutboxKeptAside,
}

/// One answer a card offers: its label, the `answer` it gives and the owner
/// route that takes it (`vault.outbox.diverged.answer` takes it too).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxCardAction {
    pub label: String,
    pub answer: OutboxDivergedAnswer,
    pub route: String,
}
