//! The transfer verbs over a kept whole-vault export (FIX 11176). A
//! `vault.export` with `delivery: "transfer"` keeps its archive on the
//! server and names it by an [`ExportTransfer`](super::ExportTransfer);
//! `vault.export.transfer.read` reads one byte range of it as base64 and
//! `vault.export.transfer.release` lets it go, so a transport with no byte
//! route (MCP) reads the same kept archive the
//! `GET /v1/core/export-transfers/{transfer_ref}` route reads.

use serde::{Deserialize, Serialize};

/// The bytes one read answers when its caller names no length: a pacing
/// default, never a bound. Any length asked for is answered.
pub const EXPORT_TRANSFER_READ_BYTES: u64 = 4 * 1024 * 1024;

/// `vault.export.transfer.read`'s input: the kept export, where to start,
/// and how many bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportTransferReadRequest {
    /// The handle its `vault.export` answered.
    pub transfer_ref: String,
    /// The first byte to read; the start when absent.
    #[serde(default)]
    pub offset: u64,
    /// How many bytes to read, up to the archive's end;
    /// [`EXPORT_TRANSFER_READ_BYTES`] when absent.
    #[serde(default)]
    pub length: Option<u64>,
}

/// One byte range of a kept export, beside what the whole is: its length
/// and BLAKE3, which a reader checks once it holds every piece.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportTransferPiece {
    pub transfer_ref: String,
    /// Where this piece starts in the archive.
    pub offset: u64,
    /// This piece's bytes, as standard base64.
    pub bytes_base64: String,
    /// How many bytes this piece holds.
    pub length: u64,
    /// The whole archive's length.
    pub total_bytes: u64,
    /// The whole archive's BLAKE3, lowercase hex.
    pub digest: String,
    /// Whether this piece reaches the archive's end.
    pub end: bool,
}

/// `vault.export.transfer.release`'s input: the kept export to let go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportTransferReleaseRequest {
    pub transfer_ref: String,
}

/// What `vault.export.transfer.release` did: the kept export is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportTransferReleased {
    pub transfer_ref: String,
    /// Always `true`.
    pub released: bool,
}
