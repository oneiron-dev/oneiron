//! Moved from `crates/oneiron/src/feedback/conversation_training/anonymous.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::feedback::conversation_training::anonymous::files::PieceFilesProblem;
use serde::Deserialize;
use serde::Serialize;

/// How a submission's offer leaves the vault (TL-6), set at its first
/// preparation from the offer pass and kept by every retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrainingTransport {
    /// Through the outbox's V2 files, which a managed vault's supervisor
    /// ships under its own binding.
    Hosted,
    /// Through the anonymous training window, piece by piece under its C,
    /// which a self-hosted vault's shipper reaches.
    Anonymous,
}
pub mod files;
