//! Moved from `crates/oneiron/src/deletion/legal_hold/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The title of the owner's one confirm.
pub const LIFT_AND_ERASE_TITLE: &str = "Lift the hold and erase?";

/// The prompt the owner's one confirm shows (C7).
pub const LIFT_AND_ERASE_PROMPT: &str = "This lifts your hold and erases these records. It does not end any legal duty to keep them. This choice is recorded.";

/// Who placed a hold, and so who may lift it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

/// One sealed capture of an owner's hold in the install's hold store:
/// the capture's id and the fingerprint of its sealed frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HoldCloneCapture {
    pub capture: EntityId,
    pub fingerprint: [u8; 32],
}

/// One hold row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// Opaque matter or order reference. The owner sees a host order's
    /// unless its silence runs ([`Self::owner_may_see`]).
    pub matter_ref: Option<String>,
    /// A host order's law, as an opaque ref ([`HostOrderHold`]).
    pub legal_basis_ref: Option<String>,
    /// Where a host order's law binds, as an opaque code.
    pub jurisdiction: Option<String>,
    /// Who issued a host order, as an opaque ref.
    pub issuing_authority_ref: Option<String>,
    pub lifted_at: Option<u64>,
    /// A host order's owner-visible notice was written (at placement, or
    /// when its silence ended).
    #[serde(default)]
    pub owner_told: bool,
    /// A host order's own terms also forbid using what it keeps (C6), kept
    /// as the order's data. Never set on a customer hold. A record a hosted
    /// privacy erasure kept is use-limited under any standing hold either way
    /// (FIX 8849).
    #[serde(default)]
    pub requires_non_use: bool,
    /// The sealed captures of this hold in the install's hold store, oldest
    /// first. Empty on rows written before the sealed copy.
    #[serde(default)]
    pub clone_captures: Vec<HoldCloneCapture>,
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

    /// THE owner's permitted view of this hold at `now` (WILL-PLAN L01 row
    /// 02): the whole row, its matter ref, operator and terms, and its
    /// events' actors and reasons, unless an order's silence runs
    /// (`secret_until`), when nothing of it. The list, the log and every
    /// refusal read it.
    #[must_use]
    pub fn owner_may_see(&self, now: u64) -> bool {
        !self.secret_at(now)
    }
}

/// The eight hold events (C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldEventKind {
    Placed,
    ScopeChanged,
    DeleteRefused,
    LiftAndEraseConfirmed,
    /// The owner's plain delete of a record only secret orders kept was
    /// accepted (FIX 1465). No longer written: host orders keep nothing in
    /// the vault; earlier logs keep it.
    EraseConfirmed,
    /// The owner withdrew an erase they confirmed that still waited: nothing
    /// of the record is erased by it, and no hold is placed again (FIX
    /// 10401).
    EraseWithdrawn,
    EraseCompleted,
    Lifted,
}

/// The reason code of one hold event. Never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The owner withdrew their waiting erase (FIX 10401).
    OwnerWithdrew,
    /// The owner's erase waited on a host order. No longer written: host
    /// orders keep nothing in the vault; earlier logs keep it.
    CompletionPending,
    /// The ARCH-0038 receipt's signed final row is appended: its hard purge,
    /// its historical sweep and every custody retirement it bound finished
    /// (FIX 5844).
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The fingerprint of the sealed capture this event placed or widened;
    /// `None` on rows written before the sealed copy and on events that
    /// wrote none.
    #[serde(default)]
    pub clone_fingerprint: Option<[u8; 32]>,
}

/// What an erase that ran still waits on (C4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErasePendingReason {
    /// Its historical sweep is queued: the receipt has no linked sweep row
    /// yet.
    HistoricalSweep,
    /// Its sweep finished or none was queued, and a custody retirement it
    /// bound has not finished on every required target yet (FIX 5844).
    CustodyRetirement,
    /// Nothing is erased yet: in a shared vault with two or more Owners the
    /// erase waits out the vault's `erase` veto window first, through the
    /// record's own `erase` act, and runs once that act completes (FIX 9781).
    VetoWindow,
}

/// What the owner's withdrawal did to one record's waiting erase (FIX
/// 10401).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EraseWithdrawal {
    /// The erase that waited is withdrawn: nothing of the record is erased
    /// by it. A hold its confirm lifted stays lifted.
    Withdrawn,
    /// No erase of the record waits.
    NotWaiting,
    /// Another Owner confirmed the erase: only they withdraw it. This
    /// Owner's objection to its `erase` act is their veto.
    ConfirmedByAnotherOwner,
    /// Its erase has begun, or a request has claimed its `erase` act: it
    /// runs to its end, and reads as its confirm's status does.
    UnderWay,
}
