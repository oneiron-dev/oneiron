//! Moved from `crates/oneiron/src/receipt/ledgers.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::ops::Bound;

// ONE-1690 closes the known interim double-authority window: ledger rows are
// the resend authority; send receipts are required-outcome audit narrative.

/// Delivery state carried by the additive connector-send receipt ledger.
/// Failed transport audit rows remain visible but are not idempotency tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendReceiptOutcome {
    Delivered,
    Failed,
    Ambiguous,
}
