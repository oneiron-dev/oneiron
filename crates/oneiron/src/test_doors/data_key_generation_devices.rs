//! Doors from the device delivery tests to the vault data key's stored state.
//!
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::path::Path;

use crate::Vault;
use crate::error::Result;

/// Opens a device vault at `path` under `home`'s storage id, as an enrolled
/// device opens under its home's: the two vaults' data-key commitments match.
pub fn open_device_vault_adopting_storage_id(path: &Path, home: &Vault) -> Result<Vault> {
    let id = crate::vault::VaultStorageId::for_test(home.vault_key_vault_id());
    Vault::open_owned_with(
        path,
        crate::VaultConfig::device(),
        crate::vault::OpenOptions::default().adopt_storage_id(id),
    )
}

/// This vault's stored data-key commitment and generation.
pub fn stored_data_key_state(vault: &Vault) -> Result<([u8; 32], u32)> {
    vault.stored_data_key_state()
}

/// Takes `from`'s held data key, state and links as `to`'s own, with a fresh
/// device wrap of `to`'s install, and holds the key on `to`.
pub fn clone_held_data_key(from: &Vault, to: &Vault) -> Result<()> {
    to.clone_data_key_state_from(from)
}
