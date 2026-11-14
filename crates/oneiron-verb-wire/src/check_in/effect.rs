//! Moved from `crates/oneiron/src/check_in/effect.rs` (P2.5 2k3 main merge: the
//! step-up reset receipts, wire types since lib split W2, name it).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The check-in decision an act's family receipt records (P24-SHAPE Q9 =
/// A): the act class, the role it was judged under, the mode and why it
/// went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckInDecision {
    /// The act class's token.
    pub act_class: String,
    /// The role's token.
    pub role: String,
    /// The mode's wire token; none when the role acts on its own proof.
    pub mode: Option<String>,
    /// Why the act went: `never_ask`, `sure` (the person's own judgment),
    /// `own_proof`, or the basis the spent check-in gave (`approved`,
    /// `proceed_with_undo` or `window_passed`).
    pub basis: String,
    /// The check-in the act spent, 32 hex.
    pub check_in: Option<String>,
    /// Who asked for the act, PERSON or agent id hex, when an Owner applied
    /// another asker's approved check-in on their own proof (P24-SHAPE Q7 =
    /// A); none for an act its own actor asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
}
