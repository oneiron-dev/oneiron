//! `vault.receipts`'s page as UniFFI crosses it (FIX 10186): the receipts
//! as [`FacadeReceipt`] records, and the `after` the next page takes.

use oneiron::task_verb::sdk;

use crate::codec::Lift;
use crate::dto::FacadeReceipt;
use crate::error::OneironError;

/// One page of governance receipts, newest first.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct FacadeReceiptPage {
    pub receipts: Vec<FacadeReceipt>,
    /// The next page's `after`; none once no older receipt is left.
    pub next_after: Option<String>,
    /// The receipts this page could hold: the limit, or the page size when
    /// the limit asked for more.
    pub effective_limit: u64,
    /// The limit was past the page size and this page was served at it;
    /// `next_after` continues to the rest.
    pub limit_clamped: bool,
}

impl Lift<sdk::VaultReceiptsPage> for FacadeReceiptPage {
    fn lift(value: sdk::VaultReceiptsPage) -> Result<Self, OneironError> {
        Ok(Self {
            receipts: Lift::lift(value.receipts)?,
            next_after: value.next_after,
            effective_limit: u64::try_from(value.effective_limit).unwrap_or(u64::MAX),
            limit_clamped: value.limit_clamped,
        })
    }
}
