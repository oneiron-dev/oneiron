//! Door for the vault data-key generation test: an unlock whose password
//! wrap opened before a new generation and whose key is held after it, as a
//! delayed unlock's is.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::Vault;

/// Opens `vault`'s password wrap with `password`, runs `between`, then holds
/// the key the wrap opened to. Refused when `between` moved the vault to a
/// new data-key generation.
pub fn unlock_with_password_across(
    vault: &Vault,
    password: &[u8],
    between: impl FnOnce(),
) -> crate::error::Result<()> {
    vault.unlock_vault_key_with_password_across(password, between)
}
