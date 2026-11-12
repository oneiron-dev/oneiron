//! Moved from `crates/oneiron/src/context_board/frame.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::tokenizer::count_context_pack_tokens;
use serde::Deserialize;
use serde::Serialize;

/// A plugin-facing budget policy name resolved through the frame-owned closed
/// mapping [`section_policy_for_budget_ref`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct BudgetPolicyRef(pub String);
