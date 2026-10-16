//! The legal-hold vocabulary (OF-470, design B; ARCH-0038 #legal-hold,
//! BIZ-LEGAL-0004 §12, owner ruling 2026-10-17). Every field is an id, a
//! time or a typed code: the hold log holds no memory content and no free
//! text (C3).

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// The title of the owner's one confirm.
pub const LIFT_AND_ERASE_TITLE: &str = "Lift the hold and erase?";

/// The prompt the owner's one confirm shows (C7).
pub const LIFT_AND_ERASE_PROMPT: &str = "This lifts your hold and erases these records. It does not end any legal duty to keep them. This choice is recorded.";

/// What an owner erase shows where Oneiron hosts the bytes until the
/// deletion receipt completes, and while a secret order keeps them (C2, C4).
pub const ERASE_COMPLETION_PENDING: &str = "erase confirmed; completion pending";

/// The named refusal a delete of a held record fails with.
pub const LEGAL_HOLD_REFUSAL: &str = "legal hold: a hold names this record, so it is not deleted";

/// The refusal a delete fails with while only a secret order keeps the
/// record: it says nothing about the order.
pub const LEGAL_HOLD_DEFERRAL: &str = "delete deferred: completion pending";

/// How long a hold's log rows outlive the hold, in calendar months (C3: the
/// hold's life, then 24 months).
pub const LEGAL_HOLD_LOG_RETENTION_MONTHS: u32 = 24;

/// Who placed a hold, and so who may lift it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldKind {
    /// The vault owner's hold. The owner lifts it only through the one
    /// "Lift the hold and erase?" confirm.
    Customer,
    /// Oneiron's hold on an authority order, only where Oneiron hosts the
    /// bytes (Cloud and relay). Only Oneiron lifts it; an owner erase keeps
    /// the bytes (C1).
    HostOrder,
}

/// What a hold names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldTarget {
    /// One record. A CLAIM's id also holds its gate-decision key partition.
    Record(EntityId),
    /// One gate-decision key partition: a claim's, or (`None`) the
    /// claim-free one the retention-horizon sweep ages.
    GatePartition(Option<EntityId>),
}

impl LegalHoldTarget {
    /// The record or claim this target names; `None` for the claim-free
    /// partition.
    #[must_use]
    pub const fn id(&self) -> Option<EntityId> {
        match self {
            Self::Record(id) | Self::GatePartition(Some(id)) => Some(*id),
            Self::GatePartition(None) => None,
        }
    }
}

/// Who acted, in the hold log (C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldActorKind {
    Owner,
    Member,
    Agent,
    Timer,
    Host,
    /// A host-facing door that carries no actor (the raw `Vault` delete,
    /// batch, port and replay doors).
    Unattributed,
}

/// One hold row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHold {
    pub hold_id: EntityId,
    pub kind: LegalHoldKind,
    /// What the hold names now; a lifted hold keeps its last scope.
    pub targets: Vec<LegalHoldTarget>,
    /// Opaque id of who placed it (an owner's id, or the host's operator ref).
    pub placed_by: Option<String>,
    pub placed_by_kind: LegalHoldActorKind,
    pub placed_at: u64,
    /// A host order's stored end; Oneiron's maintenance pass lifts it then.
    pub ends_at: Option<u64>,
    /// Until when an order forbids telling the owner. While it runs the
    /// owner-visible log shows nothing of this hold (C2).
    pub secret_until: Option<u64>,
    /// Opaque matter or order reference. A host order's never leaves the
    /// host-only log and rows.
    pub matter_ref: Option<String>,
    pub lifted_at: Option<u64>,
    /// A host order's owner-visible notice was written (at placement, or
    /// when its silence ended).
    #[serde(default)]
    pub owner_told: bool,
}

impl LegalHold {
    /// Still standing.
    #[must_use]
    pub const fn stands(&self) -> bool {
        self.lifted_at.is_none()
    }

    /// An order forbids telling the owner about it at `now`.
    #[must_use]
    pub fn secret_at(&self, now: u64) -> bool {
        self.kind == LegalHoldKind::HostOrder && self.secret_until.is_some_and(|until| now < until)
    }
}

/// The six hold events (C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldEventKind {
    Placed,
    ScopeChanged,
    DeleteRefused,
    LiftAndEraseConfirmed,
    EraseCompleted,
    Lifted,
}

/// The reason code of one hold event. Never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldReason {
    /// The owner placed a customer hold.
    OwnerPlaced,
    /// A host-facing door placed a hold (the gate-partition door).
    HostPlaced,
    /// An authority order: the host's own log carries its reference.
    LegalOrder,
    ScopeWidened,
    /// The owner's lift-and-erase took these records out of the hold.
    ScopeNarrowedByErase,
    /// A host order's end date moved (a renewal).
    EndDateChanged,
    /// A delete met the hold.
    HeldRecord,
    /// A privacy erasure request met the hold: the held part is kept for
    /// that legal reason only (C5, C6).
    PrivacyEraseKept,
    /// The owner confirmed "Lift the hold and erase?".
    OwnerConfirmed,
    /// The owner's erase waits on a host order: completion pending.
    CompletionPending,
    /// The ARCH-0038 receipt has both completion times.
    ReceiptCompleted,
    /// The authority's release notice.
    AuthorityReleased,
    /// The order's stored end date passed.
    OrderEnded,
    /// A host-facing door released the hold.
    HostReleased,
    /// An order's silence ended; the owner is now told of it.
    SecrecyEnded,
}

/// One row of a hold log: ids, times and codes only (C3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldEvent {
    pub hold_id: EntityId,
    pub kind: LegalHoldKind,
    pub targets: Vec<LegalHoldTarget>,
    pub actor_ref: Option<String>,
    pub actor_kind: LegalHoldActorKind,
    pub at: u64,
    pub event: LegalHoldEventKind,
    pub reason: LegalHoldReason,
    /// The opaque matter or order reference. A host order's is in the
    /// host-only log only.
    pub matter_ref: Option<String>,
    /// The ARCH-0038 receipt's `request_id`, on "erase completed".
    pub request_id: Option<String>,
}

/// A host order to hold records (C1). Placed only where Oneiron hosts the
/// bytes, through the host-only door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOrderHold {
    pub targets: Vec<LegalHoldTarget>,
    /// Opaque order reference; it stays in the host-only log.
    pub order_ref: String,
    /// The order's period end, as the host computed it (for example
    /// §2703(f) 90 days, an EU preservation order 60 days, 刑訴 197(3) 30).
    pub ends_at: u64,
    /// The end of any silence the order imposes (§2705(b), 刑訴 218(3),
    /// e-evidence Art. 5(7)); `None` tells the owner as usual.
    pub secret_until: Option<u64>,
    /// Opaque ref of the host operator placing it.
    pub placed_by: String,
}

/// What the owner's one confirm did to one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftAndEraseStatus {
    /// Self-hosted: the hold is lifted and the record erased.
    Erased { receipt_ref: Option<String> },
    /// "Erase confirmed; completion pending" ([`ERASE_COMPLETION_PENDING`]):
    /// where Oneiron hosts the bytes, until the deletion receipt completes,
    /// or while a secret order keeps the bytes.
    CompletionPending,
    /// A legal order Oneiron must obey keeps the bytes; the erase runs when
    /// it lifts.
    KeptByLegalOrder,
    /// The hold was lifted, then the erase failed; a plain delete retries it.
    Failed { message: String },
}

/// The owner's one confirm's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftAndEraseOutcome {
    /// The customer holds lifted, or narrowed to what is left.
    pub holds: Vec<EntityId>,
    pub records: Vec<(EntityId, LiftAndEraseStatus)>,
}

/// A record kept after a refused privacy erasure: it serves only the legal
/// reason that kept it (C6, hosted only). Read enforcement is the scope
/// checks' (L02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldUseLimit {
    pub record: EntityId,
    pub since: u64,
    pub reason: LegalHoldReason,
}

/// One legal-hold maintenance pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegalHoldMaintenance {
    /// Host orders whose end date passed, now lifted.
    pub lapsed: u64,
    /// Confirmed erases run now that nothing holds their records.
    pub erased: u64,
    /// Refusals written to the hold logs.
    pub refusals: u64,
    /// Log rows and released holds past their retention.
    pub expired: u64,
}
