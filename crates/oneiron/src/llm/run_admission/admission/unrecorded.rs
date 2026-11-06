//! Runs whose own receipt sink is fixed to discard at construction.

use super::{
    Arc, BudgetGuard, HostAccount, PayerPerson, RunAdmission, RunDeclaration, RunReceipt,
    RunReceiptSink,
};

struct UnrecordedReceipts;

impl RunReceiptSink for UnrecordedReceipts {
    fn record(&self, _: RunReceipt) {}
}

impl RunAdmission {
    /// Starts on the caller's actual meter, discarding this run's own receipts.
    /// This does not suppress offer state, backend logs or other captures;
    /// the host must also choose their unrecorded call paths.
    #[must_use]
    pub fn with_unrecorded_meter(
        run: impl Into<String>,
        declaration: RunDeclaration,
        meter: BudgetGuard,
        host: Option<Arc<HostAccount>>,
        payer: Option<PayerPerson>,
    ) -> Self {
        Self::start(
            run.into(),
            declaration,
            meter,
            host,
            Arc::new(UnrecordedReceipts),
            payer,
            None,
            None,
            true,
        )
    }

    /// Whether this run discards its own receipts, not a backend privacy proof.
    #[must_use]
    pub fn is_unrecorded(&self) -> bool {
        self.inner.unrecorded
    }
}
