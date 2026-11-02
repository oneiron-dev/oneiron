//! `vault.receipts`'s input and its page (FIX 10186): any positive limit,
//! served at most [`VAULT_RECEIPTS_PAGE_MAX`] receipts a page, and the
//! `after` the next page takes until the receipts end.
use serde::{Deserialize, Serialize};

/// The most receipts one `vault.receipts` page holds: a larger limit is
/// served a page at a time through `next_after`.
pub const VAULT_RECEIPTS_PAGE_MAX: usize = crate::memory::caps::MAX_SEARCH_LIMIT;

/// `vault.receipts`'s input: a page size, the receipt kinds to list as
/// `ReceiptKind` names them (`gate`, `hook`, `outbound`, ...), and the
/// `next_after` of the page before. With no kinds it lists the gate decision
/// ledger; an unknown kind is refused.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VaultReceiptsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
    /// The kinds to list; absent, null or empty, the gate ledger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    /// The `next_after` of the page before, under the same kinds; from the
    /// newest receipt when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// One page of `vault.receipts`, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultReceiptsPage {
    pub receipts: Vec<crate::memory::MemoryReceipt>,
    /// The next page's `after`; absent once no older receipt is left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
    /// The receipts this page could hold: the request's limit, or
    /// [`VAULT_RECEIPTS_PAGE_MAX`] when it asked for more.
    pub effective_limit: usize,
    /// The request's limit was past [`VAULT_RECEIPTS_PAGE_MAX`] and this
    /// page was served at it; `next_after` continues to the rest.
    #[serde(default)]
    pub limit_clamped: bool,
    /// Send receipt rows skipped as undecodable (FIX 12044): counted, never
    /// read as receipts. None on the gate ledger, which holds no sends.
    pub undecodable: u32,
}
