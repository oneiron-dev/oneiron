//! Doors for `tests/outbound_wait_setting_keys.rs` (restriction wave 6): a held connector call
//! the ledger never admitted and whether expiry settled it, and the dedupe check a re-send meets.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Keeps a held connector call first held at `held_at_ms`, which the ledger never admitted, and
/// returns its ref.
///
/// # Errors
///
/// Storage errors.
pub fn put_held_connector_call(vault: &Vault, held_at_ms: u64) -> Result<EntityId> {
    crate::outbound_consent::put_held_connector_call(vault, held_at_ms)
}

/// Whether the held call `call_ref` settled; `None` when no row holds it.
///
/// # Errors
///
/// Storage errors.
pub fn held_connector_call_settled(vault: &Vault, call_ref: &EntityId) -> Result<Option<bool>> {
    crate::outbound_consent::held_connector_call_settled(vault, call_ref)
}

/// Whether a new send is suppressed whose dedupe key an earlier, settled send reserved
/// `reserved_secs_ago` seconds before the vault's clock reads now.
///
/// # Errors
///
/// The ledger's refusal, as text.
pub fn resend_blocked_after(
    vault: &Vault,
    reserved_secs_ago: u64,
) -> std::result::Result<bool, String> {
    crate::outbound_chokepoint::dedupe::resend_blocked_after(vault, reserved_secs_ago)
        .map_err(|error| format!("{error:?}"))
}
