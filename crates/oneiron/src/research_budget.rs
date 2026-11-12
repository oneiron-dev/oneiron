//! Research-loop budget configuration, settlement, and refusal values.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[doc(hidden)]
use oneiron_verb_wire::research_budget::{OVERDRAFT_RECEIPT_DOMAIN, hex_bytes};
#[doc(hidden)]
pub use oneiron_verb_wire::research_budget::{
    RsiBudgetConfig, RsiBudgetError, RsiBudgetRead, RsiBudgetShare, RsiExplorationRead,
    RsiOverdraftReceipt, RsiSettlement, RsiSpendPurpose, RsiTopUp,
};

/// `bytes` as lowercase hex.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    out
}
