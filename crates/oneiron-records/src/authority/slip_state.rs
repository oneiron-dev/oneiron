//! Moved from `crates/oneiron/src/authority/slip_state.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldedSlip {
    pub action: SlipMintAction,
    pub signer: AuthorityKey,
    pub entry_hash: AuthorityEntryHash,
}
