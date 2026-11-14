//! Moved from `crates/oneiron/src/verbs/legal_hold.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::deletion::legal_hold::types::ErasePendingReason;
use crate::deletion::legal_hold::types::EraseWithdrawal;
use crate::deletion::legal_hold::types::LegalHoldTarget;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.legal_holds.place`'s input: what the owner's customer hold names,
/// and an optional opaque matter reference.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldPlaceRequest {
    /// Each `{"record": "<hex>"}`, `{"gate_partition": "<hex>"}` (a claim's
    /// gate-decision key partition), or `{"gate_partition": null}` (the
    /// claim-free partition).
    pub targets: Vec<LegalHoldTarget>,
    /// An opaque id, never free text: 1 to 128 of A-Z a-z 0-9 . _ : - /.
    #[serde(default)]
    pub matter_ref: Option<String>,
}

/// `vault.legal_holds.widen`'s input: more targets for one of the owner's
/// standing customer holds. A hold narrows only through the one confirm.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldWidenRequest {
    pub hold_id: EntityId,
    /// As [`LegalHoldPlaceRequest::targets`].
    pub targets: Vec<LegalHoldTarget>,
}

/// What the owner's one confirm did to one record, by one rule wherever the
/// bytes live (WILL-PLAN L01 row 04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LegalHoldEraseState {
    /// The hold is lifted and the record erased: its deletion receipt's
    /// signed final row is appended, its hard purge, historical sweep and
    /// every custody retirement it bound finished (C4, FIX 5844). No receipt
    /// when nothing was there.
    Erased { receipt_ref: Option<String> },
    /// "erase confirmed; completion pending"
    /// (`ERASE_COMPLETION_PENDING`): the erase still waits
    /// on `reason` of `receipt_ref`, or on its shared vault's veto window. Not
    /// erased yet.
    CompletionPending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<ErasePendingReason>,
    },
    /// The hold was lifted, then the erase failed; a plain delete retries it.
    Failed { message: String },
}

/// One record the confirm named, with what it did to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldErasedRecord {
    pub record: EntityId,
    pub status: LegalHoldEraseState,
}

/// `vault.legal_holds.withdraw_erase`'s input: the records whose waiting
/// erase the owner withdraws (FIX 10401).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldWithdrawEraseRequest {
    pub records: Vec<EntityId>,
}

/// One record the withdrawal named, with what it did to the erase that
/// waited on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldWithdrawnErase {
    pub record: EntityId,
    pub status: EraseWithdrawal,
}

/// `vault.legal_holds.withdraw_erase`'s answer: each named record's state,
/// in id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldErasesWithdrawn {
    pub records: Vec<LegalHoldWithdrawnErase>,
}
