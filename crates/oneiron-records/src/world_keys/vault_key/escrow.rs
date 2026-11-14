//! Moved from `crates/oneiron/src/world_keys/vault_key/escrow.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::world_keys::vault_key::*;
use getrandom::SysRng;
pub use oneiron_verb_wire::world_keys::vault_key::escrow::EscrowRetirement;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use std::sync::PoisonError;
use zeroize::Zeroizing;

/// What an escrow add warns of (FIX 2857). The wrap is sealed either way;
/// a warning names labels only, never a key or a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "warning")]
pub enum EscrowAddWarning {
    /// The recipient's key is one an escrow label was released to and then
    /// retired under: a released recipient is not meant to be sealed to
    /// again. Seal to a new key, and remove this wrap.
    RetiredRecipient { retired_label: String },
}

/// One escrow wrap added, and what the add warns of.
#[derive(Debug, Clone, Serialize)]
pub struct EscrowAdded {
    pub wrap: VaultKeyWrapInfo,
    /// Empty when nothing warns.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<EscrowAddWarning>,
}
