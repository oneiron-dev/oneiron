//! The `[keystore]` section: where this install keeps its this-device-only key
//! slots (world privacy P6b, P6c). The engine keeps two secrets there per vault: the
//! seed of this machine's encryption key, which opens the world keys wrapped to it,
//! and the seed of its signing keys (receipts, settings edits, key records).
//!
//! - `backend = "platform"` (the default) is the Apple data-protection keychain,
//!   DPAPI-sealed files on Windows, or a 0700 key directory on other Unix systems.
//!   `"hardware"` seals every slot to a Secure Enclave key on Apple and is refused
//!   elsewhere, never served by a weaker tier (OF-168). `"off"` installs none, and
//!   every signing and world-key door then answers `KeystoreUnavailable`.
//! - `dir` is that key directory. It defaults to `$XDG_STATE_HOME/oneiron/keys`,
//!   then `$HOME/.local/state/oneiron/keys` (`%LOCALAPPDATA%\Oneiron\keys` on
//!   Windows), and it must lie outside the vault.
//! - `service` is the Apple keychain service name.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;

/// The keychain service the Apple adapter files slots under by default.
pub use oneiron_keystore::DEFAULT_KEYCHAIN_SERVICE;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeystoreBackend {
    #[default]
    Platform,
    Hardware,
    Off,
}

/// Resolved keystore settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeystoreConfig {
    pub backend: KeystoreBackend,
    pub dir: Option<PathBuf>,
    pub service: Option<String>,
}

impl KeystoreConfig {
    pub(super) fn apply_override(&mut self, over: KeystoreConfigOverride) {
        if let Some(value) = over.backend {
            self.backend = value;
        }
        if let Some(value) = over.dir {
            self.dir = Some(value);
        }
        if let Some(value) = over.service {
            self.service = Some(value);
        }
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        if self.dir.as_deref().is_some_and(Path::is_relative) {
            anyhow::bail!("keystore.dir must be an absolute path");
        }
        if self.service.as_deref() == Some("") {
            anyhow::bail!("keystore.service must not be empty");
        }
        Ok(())
    }

    /// Builds this platform's keystore for the vault at `vault_path`. `Ok(None)` when
    /// the backend is off. An error says why the platform has none; the caller logs it
    /// and serves on, since only the world-key doors need a keystore.
    pub fn open(
        &self,
        vault_path: &Path,
    ) -> anyhow::Result<Option<Arc<dyn oneiron_keystore::DeviceKeystore>>> {
        if self.backend == KeystoreBackend::Off {
            return Ok(None);
        }
        let dir = match &self.dir {
            Some(dir) => dir.clone(),
            None => default_key_dir()?,
        };
        let service = self.service.as_deref().unwrap_or(DEFAULT_KEYCHAIN_SERVICE);
        let keystore = match self.backend {
            KeystoreBackend::Hardware => {
                oneiron_keystore::hardware_keystore(service, &dir, &[vault_path])?
            }
            KeystoreBackend::Platform | KeystoreBackend::Off => {
                oneiron_keystore::platform_keystore(service, &dir, &[vault_path])?
            }
        };
        Ok(Some(keystore))
    }

    /// Installs this platform's keystore on `vault`, opened at `vault_path`, and
    /// loads this install's signing keys from it before any signing work is
    /// admitted. A platform with none does not stop serve: the signing and
    /// world-key doors answer `KeystoreUnavailable` without it, and reads and sync
    /// go on. True when one was installed.
    pub fn install_on(&self, vault: &oneiron::Vault, vault_path: &Path) -> bool {
        match self.open(vault_path) {
            Ok(Some(keystore)) => {
                tracing::info!(
                    assurance = keystore.assurance().label(),
                    "this-device keystore installed"
                );
                vault.install_device_keystore(keystore);
                vault.prepare_install_signing_logged();
                true
            }
            Ok(None) => {
                tracing::info!(
                    "keystore backend is off; signing and world-key doors are unavailable"
                );
                false
            }
            Err(error) => {
                // The keystore's closed error, or none for an unresolved key
                // directory; never the chain's text.
                tracing::warn!(
                    reason = ?error.downcast_ref::<oneiron_keystore::KeystoreError>(),
                    "no this-device-only keystore; signing and world-key doors are unavailable"
                );
                false
            }
        }
    }

    /// [`Self::install_on`] where init or serve may just have created the
    /// vault sealed (maximum tier, OF-570): one with no wrap yet takes this
    /// device's, and a failure fails the boot, since its pages open from the
    /// mirror beside it only through a wrap. True when a keystore was
    /// installed.
    pub fn install_on_boot(
        &self,
        vault: &oneiron::Vault,
        vault_path: &Path,
    ) -> anyhow::Result<bool> {
        let installed = self.install_on(vault, vault_path);
        if installed && vault.vault_pages_sealed() && vault.vault_key_wraps()?.is_empty() {
            vault.add_vault_key_device().map_err(|error| {
                anyhow::anyhow!(
                    "the new sealed vault's key was not wrapped to this device: {error}"
                )
            })?;
        }
        Ok(installed)
    }
}

/// The keystore crate's default key directory, or why there is none.
fn default_key_dir() -> anyhow::Result<PathBuf> {
    oneiron_keystore::default_key_dir().ok_or_else(|| {
        anyhow::anyhow!(
            "the key directory is unresolvable: neither XDG_STATE_HOME nor HOME names an \
             absolute directory; set keystore.dir (ONEIRON_KEYSTORE_DIR)"
        )
    })
}

/// One layer's `[keystore]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct KeystoreConfigOverride {
    pub(super) backend: Option<KeystoreBackend>,
    pub(super) dir: Option<PathBuf>,
    pub(super) service: Option<String>,
}

pub(super) fn lookup_keystore_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<KeystoreConfigOverride>> {
    let backend = lookup("ONEIRON_KEYSTORE_BACKEND")
        .map(|value| {
            serde_json::from_value(serde_json::Value::String(value.clone())).map_err(|_| {
                anyhow::anyhow!(
                    "ONEIRON_KEYSTORE_BACKEND must be platform, hardware or off, not {value:?}"
                )
            })
        })
        .transpose()?;
    let over = KeystoreConfigOverride {
        backend,
        dir: lookup("ONEIRON_KEYSTORE_DIR").map(PathBuf::from),
        service: lookup("ONEIRON_KEYSTORE_SERVICE"),
    };
    Ok((over != KeystoreConfigOverride::default()).then_some(over))
}
