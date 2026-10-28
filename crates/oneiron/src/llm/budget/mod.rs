//! Vault-local durable RSI budget ledger and resident share ledger (FIX 7767). The
//! per-attempt budget guard and the leases it issues are defined in `oneiron-model`.

mod resident;
mod rsi;
pub mod rsi_doors;

pub(crate) use resident::erase_resident_share_actor_in_txn;
pub use resident::{ResidentShareRead, VaultResidentLedger};

pub use rsi::{
    RsiBudgetConfig, RsiBudgetError, RsiBudgetRead, RsiBudgetShare, RsiExplorationRead,
    RsiOverdraftReceipt, RsiSettlement, RsiSpendPurpose, RsiTopUp,
};
