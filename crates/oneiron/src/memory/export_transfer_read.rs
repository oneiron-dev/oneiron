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

#[doc(hidden)]
pub use oneiron_verb_wire::memory::export_transfer_read::{
    ExportTransferPiece, ExportTransferReadRequest, ExportTransferReleaseRequest,
    ExportTransferReleased,
};
