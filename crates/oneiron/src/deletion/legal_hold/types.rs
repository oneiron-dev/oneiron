//! The legal-hold vocabulary (OF-470, design B; ARCH-0038 #legal-hold,
//! BIZ-LEGAL-0004 §12, owner ruling 2026-10-17). Every field is an id, a
//! time or a typed code: the hold log holds no memory content and no free
//! text (C3).

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::deletion::legal_hold::types::{
    ErasePendingReason, EraseWithdrawal, LIFT_AND_ERASE_PROMPT, LIFT_AND_ERASE_TITLE, LegalHold,
    LegalHoldActorKind, LegalHoldEvent, LegalHoldEventKind, LegalHoldKind, LegalHoldReason,
    LegalHoldTarget,
};

/// What an owner erase shows until its deletion receipt completes or its
/// shared vault's veto window clears (C4).
pub const ERASE_COMPLETION_PENDING: &str = "erase confirmed; completion pending";

/// The named refusal a delete of a held record fails with.
pub const LEGAL_HOLD_REFUSAL: &str = "legal hold: a hold names this record, so it is not deleted";

/// How long a hold's log rows outlive the hold, in calendar months (C3: the
/// hold's life, then 24 months).
pub const LEGAL_HOLD_LOG_RETENTION_MONTHS: u32 = 24;

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
    /// The law the order is made under, as an opaque ref (a statute or
    /// provision id). Its refusals name it.
    pub legal_basis_ref: Option<String>,
    /// Where that law binds, as an opaque code.
    pub jurisdiction: Option<String>,
    /// Who issued the order, as an opaque ref.
    pub issuing_authority_ref: Option<String>,
    /// The order's own terms also forbid using what it keeps (C6), recorded
    /// as its term. A refused hosted privacy erasure keeps the record under a
    /// use limit while any hold stands, whether this is set or not (FIX 8849).
    pub requires_non_use: bool,
}

/// What the owner's one confirm did to one record. One rule wherever the
/// bytes live (WILL-PLAN L01 row 04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftAndEraseStatus {
    /// The hold is lifted and the record erased: its deletion receipt is
    /// complete, its signed final row appended once the hard purge, the
    /// historical sweep and every custody retirement the erase bound had
    /// finished (C4, FIX 5844). No receipt when nothing was there to erase.
    Erased { receipt_ref: Option<String> },
    /// "Erase confirmed; completion pending" ([`ERASE_COMPLETION_PENDING`]):
    /// the erase still waits on its receipt's `reason` or on its shared
    /// vault's veto window.
    CompletionPending {
        receipt_ref: Option<String>,
        reason: Option<ErasePendingReason>,
    },
    /// The hold was lifted, then the erase failed; a plain delete retries it.
    Failed { message: String },
}

/// The owner's one confirm's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftAndEraseOutcome {
    /// The customer holds lifted, or narrowed to what is left.
    pub holds: Vec<EntityId>,
    pub records: Vec<(EntityId, LiftAndEraseStatus)>,
    /// What the owner confirmed is not what the vault holds now: nothing was
    /// lifted or erased, and this is what the confirm shows now, to confirm
    /// again in one step (FIX 1462).
    pub changed: Option<super::LiftAndEraseShownState>,
}

/// A record kept after a refused privacy erasure: it serves only the legal
/// reason that kept it (C6, hosted only), while a standing customer hold
/// still names it, for that hold's whole retention (FIX 8849). A host order's
/// [`HostOrderHold::requires_non_use`] binds its clone, not this limit. Read
/// enforcement is the scope checks' (L02).
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
