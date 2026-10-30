//! A vault VM's outbox carrier members as the owner sees them, and his
//! answer to a diverged copy (FIX 11074, FIX 11242): the bodies of `GET` and
//! `POST /v1/owner/outbox/diverged`, which the facade verbs
//! `vault.outbox.diverged.list` and `vault.outbox.diverged.answer` answer as
//! well (FIX 11739). Each copy the carrier keeps of a member it never agreed
//! on carries a card with his two answers, remove or keep; each file the
//! guest holds back as damaged at its source is listed beside them. The
//! answer goes to the carrier's companion, which carries it out at its next
//! turn: nothing removes a copy without it.

use oneiron_vault_contract::vm_outbox::{VmOutboxKind, VmOutboxSide};
use serde::{Deserialize, Serialize};

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

/// The owner's answer to a diverged copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutboxDivergedAnswer {
    /// The copy moves aside under its own name, where the carrier leaves
    /// it, so the member's next version lands.
    Keep,
    /// The copy is removed at the carrier's next turn.
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
