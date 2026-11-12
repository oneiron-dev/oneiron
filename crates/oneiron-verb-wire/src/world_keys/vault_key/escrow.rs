//! Moved from `crates/oneiron/src/world_keys/vault_key/escrow.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::world_keys::vault_key::*;
use serde::Deserialize;
use serde::Serialize;

/// One escrow recipient retired after its secret was released, and the
/// owner's receipt for it ([`Vault::retire_vault_key_escrow_as`]). Ids and
/// times only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EscrowRetirement {
    pub receipt_id: String,
    pub label: String,
    /// The vault still carried the wrap `escrow:<label>`, and the retirement
    /// removed it.
    pub removed_wrap: bool,
    /// The vault clock, in seconds, when it was retired.
    pub retired_at: u64,
}
