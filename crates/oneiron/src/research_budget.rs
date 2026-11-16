//! Research-loop budget configuration, settlement, and refusal values.

#[doc(hidden)]
pub use oneiron_verb_wire::research_budget::{
    RsiBudgetConfig, RsiBudgetError, RsiBudgetRead, RsiBudgetShare, RsiExplorationRead,
    RsiOverdraftReceipt, RsiSettlement, RsiSpendPurpose, RsiTopUp,
};

/// `bytes` as lowercase hex.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    oneiron_hex::encode(bytes)
}
