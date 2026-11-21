//! What a sheet door's switch checks around its ask: the refusals the door
//! gives of its own, made before the ask with nothing held, and this
//! install's device wrap, read after it.

use super::*;

impl Vault {
    /// Whether a sheet door's switch to `preset` from `current` draws a
    /// printed sheet, after the refusals the door gives of its own: "any 2
    /// pieces" is turned on with its kit, and a draw needs an owner-held data
    /// key that this handle holds. Custody first, then the held key, as the
    /// draw checked them before it took the key as an argument. The door
    /// calls this before it asks, so the person is not asked about a switch
    /// it refuses, and takes the held key only after the ask.
    pub(super) fn sheet_switch_draws(
        &self,
        preset: RecoveryPreset,
        current: RecoveryPreset,
    ) -> Result<bool> {
        match preset {
            RecoveryPreset::NobodyButMeAnyTwo => Err(refused(ANY_TWO_NEEDS_KIT)),
            RecoveryPreset::NobodyButMe if current != preset => {
                if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
                    return Err(refused(PRESET_CUSTODY));
                }
                if self.held_vault_key().is_none() {
                    return Err(refused("unlock the vault key first"));
                }
                Ok(true)
            }
            RecoveryPreset::NobodyButMe | RecoveryPreset::Standard => Ok(false),
        }
    }

    /// The id of this install's device wrap when this install's keystore
    /// holds its slot, read without creating one; `None` with no keystore.
    /// It readies this install's signing keys, so a door reads it after it
    /// asks.
    pub(super) fn device_wrap_held_here(&self) -> Result<Option<String>> {
        let Ok(keystore) = self.device_keystore() else {
            return Ok(None);
        };
        let install = self.prepare_install_signing()?;
        let held = keystore
            .get(&self.vault_key_slot(install))
            .map_err(crate::world_keys::machine::keystore_error)?
            .is_some();
        Ok(held.then(|| {
            VaultKeyWrapKind::Device {
                install: install.to_hex(),
            }
            .id()
        }))
    }
}
