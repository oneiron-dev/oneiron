//! What a sheet door's switch checks around its ask: the refusals the door
//! gives of its own, made before the ask with nothing held, the ground it
//! asks for, and this install's device wrap, read after it.

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

    /// The ground a sheet door's switch from `current` to `preset` is asked
    /// on ([`Vault::recovery_preset_proof_ground`]). The preset in force is
    /// no switch: the write returns before its rotation and its fact, so the
    /// door asks nothing, and a write that finds another preset after all
    /// meets the write's own refusals. A kit door rotates when it enters
    /// kit-only from `Standard` with a kit that held the live generation on
    /// the door's read (`rotation`).
    pub(super) fn sheet_switch_ground(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        preset: RecoveryPreset,
        current: RecoveryPreset,
        rotation: Option<&PreparedRotation>,
    ) -> Result<Option<crate::authority::OwnerProofGround>> {
        let rotates = current == RecoveryPreset::Standard
            && preset.is_nobody_but_me()
            && rotation.is_some_and(|prepared| prepared.live_pre.is_some());
        self.recovery_preset_proof_ground(owner, preset.is_nobody_but_me(), rotates)
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
