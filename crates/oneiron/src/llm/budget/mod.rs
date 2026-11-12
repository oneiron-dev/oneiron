//! Vault-local durable RSI budget ledger and resident share ledger (FIX 7767). The
//! per-attempt budget guard and the leases it issues are defined in `oneiron-model`.

mod resident;
mod rsi;
pub mod rsi_doors;

pub use resident::{ResidentShareRead, VaultResidentLedger};
pub(crate) use resident::{resident_share_fits_in_txn, resident_share_frees};

pub use rsi::{
    RsiBudgetConfig, RsiBudgetError, RsiBudgetRead, RsiBudgetShare, RsiExplorationRead,
    RsiOverdraftReceipt, RsiSettlement, RsiSpendPurpose, RsiTopUp,
};
