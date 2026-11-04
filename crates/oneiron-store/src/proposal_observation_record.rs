//! The policy source behind a proposal submission's advisory threshold, as the
//! proposal observation records it.

use serde::{Deserialize, Serialize};

/// The manifest row (or shipped fallback) behind the advisory threshold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalPolicySource {
    pub threshold: u64,
    pub deciding_row: Option<String>,
    pub precedence_row: Option<String>,
    pub shipped_default_precedence: bool,
}
