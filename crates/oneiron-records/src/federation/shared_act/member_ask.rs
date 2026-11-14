//! Moved from `crates/oneiron/src/federation/shared_act/member_ask.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use std::collections::BTreeSet;

/// Where an ask stands. Only a live Admin or Owner closes one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MemberAskStatus {
    Open,
    /// The Admin or Owner `by` applied it; `receipt` is the membership
    /// change's receipt, which names the Steward as its proposer.
    Applied {
        by: String,
        receipt: String,
    },
    Declined {
        by: String,
    },
}
