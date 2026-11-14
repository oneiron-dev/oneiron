//! Moved from `crates/oneiron/src/verbs/receipts_page.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
