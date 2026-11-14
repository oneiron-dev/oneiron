//! Moved from `crates/oneiron/src/store/checkout_lease.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
pub use oneiron_store::checkout_task::CheckoutTaskClass;

pub type CheckoutHolder = String;

#[derive(Debug)]
pub enum CheckoutError {
    StaleEpoch { held: u64, presented: u64 },
    LivenessOccupied { occupant: CheckoutHolder },
    ReceiptMismatch,
    SettlementAlreadyWon,
    RepoOps(String),
    Store(Error),
    Invalid(&'static str),
}

impl From<Error> for CheckoutError {
    fn from(e: Error) -> Self {
        Self::Store(e)
    }
}

pub type CheckoutResult<T> = Result<T, CheckoutError>;
