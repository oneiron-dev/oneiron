//! Moved from `crates/oneiron/src/memory/claims/settle.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a committed settlement warns (FIX 7600).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettleWarningCode {
    /// The approved claim's VAD consolidation failed after the commit: the
    /// settlement stands, and the claim's VAD is pending.
    VadPending,
}

/// A warning a committed settlement carries: a stable code, the claim it is
/// about and one human line (FIX 7600). The settlement it rides on is
/// durable; the warning names work still owed after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleWarning {
    /// Why it warns.
    pub code: SettleWarningCode,
    /// The claim it is about (32 hex).
    pub claim_ref: String,
    /// One human line.
    pub detail: String,
}

/// `vault.claims.review`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimProposalReviewRequest {
    /// The proposed claim (short-id ref or 32-hex).
    pub claim_ref: String,
    /// An explicit native consent Grant for this holder and claim (64 hex).
    /// None uses the existing owner proof. A Grant grants no read access.
    pub grant_ref: Option<String>,
}

/// The settler's answer to one proposed claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSettleDecision {
    /// The reviewed body lands as approved.
    Approve,
    /// The reviewed body is rejected and closed.
    Reject,
}

/// `vault.claims.settle`'s input. It carries no approval, actor or body: the
/// answer is the caller's, and what it settles is what the review read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimSettleRequest {
    /// The proposed claim (short-id ref or 32-hex), as reviewed.
    pub claim_ref: String,
    /// The handle `vault.claims.review` returned for it.
    pub review_id: String,
    /// The answer.
    pub decision: ClaimSettleDecision,
    /// An explicit native consent Grant for this holder and claim (64 hex).
    /// None uses the existing owner proof, never an inferred Grant.
    pub grant_ref: Option<String>,
}

/// A settled change's verdict, and the proposal's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSettlementVerdict {
    /// The change landed: the claim reads as approved.
    Landed,
    /// The change was rejected.
    Rejected,
}

/// One change of a settled proposal and its verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimChangeVerdict {
    /// The claim the change is (32 hex).
    pub claim_ref: String,
    /// Its verdict.
    pub verdict: ClaimSettlementVerdict,
}

/// Who answered a settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimSettlementAnswer {
    /// A person's word: the owner whose revalidated proof settled it.
    Word {
        /// The person (32 hex).
        person_ref: String,
    },
    /// The actual holder answered under this owner-issued native Grant.
    Grant {
        /// The stored Grant's bound digest (64 hex).
        grant_ref: String,
    },
}

/// Why a settlement went the way it did; each is the reason code its ledger
/// row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ClaimSettlementReason {
    /// The owner approved the reviewed body.
    #[serde(rename = "gate.claim.settle.approved")]
    OwnerApproved,
    /// The owner rejected the reviewed body.
    #[serde(rename = "gate.claim.settle.declined")]
    OwnerDeclined,
    /// The explicitly granted holder approved the reviewed body.
    #[serde(rename = "gate.claim.settle.holder_approved")]
    HolderApproved,
    /// The explicitly granted holder rejected the reviewed body.
    #[serde(rename = "gate.claim.settle.holder_declined")]
    HolderDeclined,
}

impl ClaimSettlementReason {
    /// The reason code, as the ledger row records it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerApproved => "gate.claim.settle.approved",
            Self::OwnerDeclined => "gate.claim.settle.declined",
            Self::HolderApproved => "gate.claim.settle.holder_approved",
            Self::HolderDeclined => "gate.claim.settle.holder_declined",
        }
    }
}

/// The typed call that takes a settlement back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimSettlementRevert {
    /// The verb to call: `vault.claims.retract`.
    pub verb: String,
    /// The claim it names (32 hex).
    pub claim_ref: String,
}
