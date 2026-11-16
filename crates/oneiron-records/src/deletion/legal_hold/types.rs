//! Moved from `crates/oneiron/src/deletion/legal_hold/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::deletion::legal_hold::types::ErasePendingReason;
pub use oneiron_verb_wire::deletion::legal_hold::types::EraseWithdrawal;
pub use oneiron_verb_wire::deletion::legal_hold::types::LIFT_AND_ERASE_PROMPT;
pub use oneiron_verb_wire::deletion::legal_hold::types::LIFT_AND_ERASE_TITLE;
pub use oneiron_verb_wire::deletion::legal_hold::types::LegalHold;
pub use oneiron_verb_wire::deletion::legal_hold::types::LegalHoldActorKind;
pub use oneiron_verb_wire::deletion::legal_hold::types::LegalHoldEvent;
pub use oneiron_verb_wire::deletion::legal_hold::types::LegalHoldEventKind;
pub use oneiron_verb_wire::deletion::legal_hold::types::LegalHoldKind;
pub use oneiron_verb_wire::deletion::legal_hold::types::LegalHoldReason;
pub use oneiron_verb_wire::deletion::legal_hold::types::LegalHoldTarget;
use serde::Deserialize;
use serde::Serialize;

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
