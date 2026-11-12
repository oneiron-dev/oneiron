//! Moved from `crates/oneiron/src/llm/budget/rsi.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::research_budget::RsiBudgetConfig;
pub use crate::research_budget::RsiBudgetError;
pub use crate::research_budget::RsiBudgetRead;
pub use crate::research_budget::RsiBudgetShare;
pub use crate::research_budget::RsiExplorationRead;
pub use crate::research_budget::RsiOverdraftReceipt;
pub use crate::research_budget::RsiSettlement;
pub use crate::research_budget::RsiSpendPurpose;
pub use crate::research_budget::RsiTopUp;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

pub type RsiResult<T> = std::result::Result<T, RsiBudgetError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsiLine {
    Tokens,
    Exposure,
}
