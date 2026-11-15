//! The `one_vault` policy row (federation.md #one-vault-mode): one versioned
//! row in the vault's policy manifest that holds the company setting
//! `one_vault_mode`. Its only writer today is the Owner's manifest install,
//! as for the `inquiry` row.
//!
//! Wire shape, version 1:
//!
//! ```text
//! one_vault: { version: 1, mode: "off" | "on" }
//! ```
//!
//! No row means `off`, the default: the mode is for regulated firms, and the
//! onboarding text's plain line 2 is the default. A row with an unknown
//! version, an unknown or missing field or an unknown mode makes the whole
//! manifest unreadable, as every other manifest key does.

use super::*;
use crate::memory::{Memory, MemoryResult};
use serde::{Deserialize, Serialize};

/// The policy-manifest key of the one-vault row.
pub(crate) const ONE_VAULT_ROW_KEY: &str = "one_vault";

/// The only version of the row this build reads.
pub const ONE_VAULT_ROW_VERSION: u16 = 1;

/// Whether the company saves all work talk in the company vault.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OneVaultMode {
    /// The default. Work talk stays where the member holds it.
    #[default]
    Off,
    /// All work talk is saved in the company vault.
    On,
}

impl OneVaultMode {
    /// The wire token: `off` or `on`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }

    /// The mode a wire token names.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "off" => Some(Self::Off),
            "on" => Some(Self::On),
            _ => None,
        }
    }
}

/// The decoded `one_vault` row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneVaultPolicy {
    version: u16,
    mode: OneVaultMode,
}

impl OneVaultPolicy {
    /// The row's validated version: always [`ONE_VAULT_ROW_VERSION`].
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }

    /// Whether the company saves all work talk in its vault.
    #[must_use]
    pub const fn mode(self) -> OneVaultMode {
        self.mode
    }

    /// Decodes the manifest row. `None` for anything but a well-formed
    /// version 1 row (module doc).
    pub(crate) fn decode_row(value: &Value) -> Option<Self> {
        let fields = value.as_map()?;
        if fields.len() != 2 {
            return None;
        }
        let version = u16::try_from(map_field(fields, "version")?.as_u64()?).ok()?;
        if version != ONE_VAULT_ROW_VERSION {
            return None;
        }
        let mode = OneVaultMode::from_token(map_field(fields, "mode")?.as_str()?)?;
        Some(Self { version, mode })
    }
}

/// What the vault's resolved policy says about the one-vault row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OneVaultRead {
    /// No trusted manifest names the row.
    NoRow,
    Row(OneVaultPolicy),
    /// The resolved policy failed closed.
    Unreadable,
}

/// Where the vault's `one_vault_mode` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OneVaultSource {
    /// No row: the default, `off`.
    Default,
    /// The `one_vault` row of the vault's policy.
    Row,
    /// The policy failed closed: the mode is unknown, so no mode is
    /// answered. The caller refuses rather than guessing.
    Unreadable,
}

/// The vault's `one_vault_mode` and its source. `mode` is `None` exactly
/// when the source is `Unreadable`: an unreadable setting never answers a
/// guessed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OneVaultSetting {
    pub mode: Option<OneVaultMode>,
    pub source: OneVaultSource,
}

impl Vault {
    /// The company setting `one_vault_mode`, as this vault's policy resolves
    /// it now.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn one_vault_mode(&self) -> Result<OneVaultSetting> {
        let txn = self.store.env.read_txn()?;
        let read = crate::gate::resolve_policy_manifest(&self.store, &txn)?.one_vault_policy();
        Ok(match read {
            OneVaultRead::NoRow => OneVaultSetting {
                mode: Some(OneVaultMode::Off),
                source: OneVaultSource::Default,
            },
            OneVaultRead::Row(policy) => OneVaultSetting {
                mode: Some(policy.mode()),
                source: OneVaultSource::Row,
            },
            OneVaultRead::Unreadable => OneVaultSetting {
                mode: None,
                source: OneVaultSource::Unreadable,
            },
        })
    }
}

impl Memory<'_> {
    /// `workspace`'s `one_vault` setting, which every member it governs may
    /// read. The setting is the vault's; the workspace must exist here, as
    /// for the `work_companion` read.
    pub fn workspace_one_vault_get(&self, workspace: &str) -> MemoryResult<OneVaultSetting> {
        validate_name(
            workspace,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )?;
        read_preset_row(self.vault(), workspace)?.ok_or(Error::EntityNotFound)?;
        Ok(self.vault().one_vault_mode()?)
    }
}

/// The value of the one `name` field of a manifest map; `None` when it is
/// absent or repeated.
fn map_field<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut found = fields.iter().filter(|(key, _)| key.as_str() == Some(name));
    let (_, value) = found.next()?;
    found.next().is_none().then_some(value)
}
