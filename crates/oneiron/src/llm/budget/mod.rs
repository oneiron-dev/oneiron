//! Vault-local durable RSI budget ledger. The per-attempt budget guard and the leases it
//! issues are defined in `oneiron-model`.

mod rsi;
pub mod rsi_doors;

pub use rsi::{
    RsiBudgetConfig, RsiBudgetError, RsiBudgetRead, RsiBudgetShare, RsiExplorationRead,
    RsiOverdraftReceipt, RsiSettlement, RsiSpendPurpose, RsiTopUp,
};
