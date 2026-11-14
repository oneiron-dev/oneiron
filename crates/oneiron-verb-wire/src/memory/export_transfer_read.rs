//! Moved from `crates/oneiron/src/memory/export_transfer_read.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
