//! The client's customization profile and the world-destination helpers. The owner's plain
//! choices are catalogue keys ([`setting_keys`]), read through the Setting primitive.

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::setting::SettingValue;

pub mod backup;
pub(crate) mod board_layout;
pub mod default_facet;
mod destination;
mod device_local;
mod device_only;
pub use oneiron_store::settings::model_pack;
pub use oneiron_store::settings::model_versioning;
mod models;
pub mod non_base_world_claim_fraction;
pub(crate) mod room_threads;
pub(crate) mod setting_keys;
pub mod snapshot_read;
pub mod undo_send;
pub use oneiron_store::settings::web_connector;

pub use destination::{
    CallerLocality, ReadDestination, RecipientChoice, RecipientLimit, RecipientWhy, ReleaseHold,
    read_destination_at, read_destination_locality,
};
pub(crate) use destination::{
    machine_recipient_hold_in, recipient_limits_in, withheld_row_hold_in, withheld_worlds_in,
    worlds_hold_in,
};
pub(crate) use device_local::{
    device_local_keeps_among, device_local_worlds_at, device_local_worlds_for,
    device_local_worlds_for_machine, off_device_readable_in, off_device_readable_in_txn,
};
pub(crate) use device_only::{
    CarriedWorlds, carried_worlds_in, device_only_recipient_worlds,
    device_only_recipient_worlds_raw, device_only_withholds, device_only_withholds_raw,
    device_only_withholds_run, minted_worlds_in,
};

pub use board_layout::{
    AgentBoardLayoutOverride, BOARD_LAYOUT_AGENT_OVERRIDES_MAX, BoardLayoutSettings,
};
pub use model_versioning::{
    DEFAULT_MODEL_STACK_CURRENT_ID, DEFAULT_MODEL_STACK_V1_ID, ModelStack, ModelStackDeprecation,
    ModelStackDeprecationStage, ModelStackDeprecationStatus, ModelStackDisclosure, ModelStackId,
    ModelStackIdError, ModelStackModel, ModelStackPreference, ModelStackRegistry,
    ModelStackRegistryError, ModelStackResolution, default_model_stack_registry,
    try_default_model_stack_registry,
};
pub use room_threads::RoomThreadAdminSettings;

/// Version of the persisted customization settings record.
pub const CUSTOMIZATION_SETTINGS_SCHEMA_VERSION: u16 = 1;

/// The four SET-03 customization layers persisted by this module.
pub const CUSTOMIZATION_SETTINGS_LAYER_COUNT: usize = 4;

const TOKEN_MAX_BYTES: usize = 64;
const WORLD_LABEL_MAX_BYTES: usize = 128;

/// Complete persisted customization profile: the value of the catalogue key
/// `client.customization`, which every member reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CustomizationSettings {
    pub schema_version: u16,
    pub accent: AccentLayer,
    #[serde(rename = "type")]
    pub type_layer: TypeLayer,
    pub mode: ModeLayer,
    pub world: WorldLayer,
}

impl Default for CustomizationSettings {
    fn default() -> Self {
        Self {
            schema_version: CUSTOMIZATION_SETTINGS_SCHEMA_VERSION,
            accent: AccentLayer::default(),
            type_layer: TypeLayer::default(),
            mode: ModeLayer::default(),
            world: WorldLayer::default(),
        }
    }
}

impl CustomizationSettings {
    fn validate(&self) -> Result<()> {
        if self.schema_version != CUSTOMIZATION_SETTINGS_SCHEMA_VERSION {
            return Err(Error::CorruptedIndex("customization settings"));
        }
        self.accent.validate()?;
        self.type_layer.validate()?;
        self.mode.validate()?;
        self.world.validate()?;
        Ok(())
    }
}

impl SettingValue for CustomizationSettings {
    /// Every layer's own rules, at the one schema version this build writes.
    fn check(self) -> Result<Self> {
        if self.schema_version != CUSTOMIZATION_SETTINGS_SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "customization settings schema_version is {CUSTOMIZATION_SETTINGS_SCHEMA_VERSION}"
            )));
        }
        self.validate()?;
        Ok(self)
    }
}

/// A persisted customization layer discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomizationLayer {
    Accent,
    Type,
    Mode,
    World,
}

impl CustomizationLayer {
    /// Returns the stable on-disk layer name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accent => "accent",
            Self::Type => "type",
            Self::Mode => "mode",
            Self::World => "world",
        }
    }

    /// Returns all persisted layers in canonical order.
    #[must_use]
    pub const fn all() -> [Self; CUSTOMIZATION_SETTINGS_LAYER_COUNT] {
        [Self::Accent, Self::Type, Self::Mode, Self::World]
    }
}

/// Accent color selection layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccentLayer {
    pub palette: String,
}

impl AccentLayer {
    /// Creates an accent layer from a stable palette token.
    pub fn new(palette: impl Into<String>) -> Result<Self> {
        let layer = Self {
            palette: palette.into(),
        };
        layer.validate()?;
        Ok(layer)
    }

    fn validate(&self) -> Result<()> {
        validate_token("accent.palette", &self.palette)
    }
}

impl Default for AccentLayer {
    fn default() -> Self {
        Self {
            palette: "system".to_owned(),
        }
    }
}

/// Typography/type selection layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TypeLayer {
    pub typeface: String,
}

impl TypeLayer {
    /// Creates a type layer from a stable typeface token.
    pub fn new(typeface: impl Into<String>) -> Result<Self> {
        let layer = Self {
            typeface: typeface.into(),
        };
        layer.validate()?;
        Ok(layer)
    }

    fn validate(&self) -> Result<()> {
        validate_token("type.typeface", &self.typeface)
    }
}

impl Default for TypeLayer {
    fn default() -> Self {
        Self {
            typeface: "system".to_owned(),
        }
    }
}

/// App mode/theme selection layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModeLayer {
    pub mode: String,
}

impl ModeLayer {
    /// Creates a mode layer from a stable mode token.
    pub fn new(mode: impl Into<String>) -> Result<Self> {
        let layer = Self { mode: mode.into() };
        layer.validate()?;
        Ok(layer)
    }

    fn validate(&self) -> Result<()> {
        validate_token("mode.mode", &self.mode)
    }
}

impl Default for ModeLayer {
    fn default() -> Self {
        Self {
            mode: "system".to_owned(),
        }
    }
}

/// World selection layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorldLayer {
    pub world_ref: Option<String>,
    pub label: Option<String>,
}

impl WorldLayer {
    /// Creates a world layer from an optional world entity id and display label.
    pub fn new(world_ref: Option<EntityId>, label: Option<String>) -> Result<Self> {
        let layer = Self {
            world_ref: world_ref.map(|id| id.to_hex()),
            label,
        };
        layer.validate()?;
        Ok(layer)
    }

    /// Creates a world layer from an already-serialized world entity id.
    pub fn from_hex(world_ref: Option<String>, label: Option<String>) -> Result<Self> {
        let layer = Self { world_ref, label };
        layer.validate()?;
        Ok(layer)
    }

    fn validate(&self) -> Result<()> {
        if let Some(world_ref) = &self.world_ref {
            EntityId::from_hex(world_ref).map_err(|_| {
                Error::InvalidConfig("settings world_ref must be an entity id".into())
            })?;
        }
        if let Some(label) = &self.label {
            validate_label("world.label", label)?;
        }
        Ok(())
    }
}

impl Vault {
    /// Reads the Dreamer plugin-suggestion knob, the key
    /// `dreamer.plugin_suggestions`. **Absent means enabled.**
    ///
    /// There is no environment override and no second cadence key: this one
    /// boolean is the entire dial. A row that does not decode reads off, never
    /// the default, because a disabled knob that reads back as enabled would
    /// resume proactive suggestions an owner switched off.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn plugin_suggestions_enabled(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(setting_keys::PLUGIN_SUGGESTIONS
            .read_in_txn(self, &rtxn, &[], None)?
            .value)
    }

    /// Held by a release verdict from its first flag read to its acceptance.
    /// A flag commit holds the other side, so a flag committed before a
    /// verdict accepts is always one it read. Hold it over reads only: never
    /// across a write or an async send.
    #[cfg(feature = "sync")]
    pub(crate) fn device_only_acceptance(&self) -> std::sync::RwLockReadGuard<'_, ()> {
        self.store
            .device_only_flag_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reads the client's customization profile, the key `client.customization`, or the
    /// default four-layer model while none is set.
    pub fn customization_settings(&self) -> Result<CustomizationSettings> {
        let rtxn = self.store.env.read_txn()?;
        let settings = setting_keys::CUSTOMIZATION
            .read_in_txn(self, &rtxn, &[], None)?
            .value;
        settings.validate()?;
        Ok(settings)
    }
}

fn validate_token(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > TOKEN_MAX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidConfig(format!(
            "{field} must be a non-empty ASCII token"
        )));
    }
    Ok(())
}

fn validate_label(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > WORLD_LABEL_MAX_BYTES || value.contains(char::is_control) {
        return Err(Error::InvalidConfig(format!(
            "{field} must be non-empty visible text"
        )));
    }
    Ok(())
}

pub(crate) mod tables;
#[cfg(test)]
mod tests;

/// Every world whose settings keep it off the machines `destination` names:
/// the world settings' one judge, asked for each machine a read's rows go to,
/// its proof revalidated in `txn` (mesh PR2b). Only a destination no live
/// machine proof names is unknown. Read through [`device_local_worlds_for`],
/// and through `device_local_worlds_for_machine` (FIX 5588 S4), which judges
/// the same settings via `WorldPrivacyView::withheld_for`: every door asks
/// one of those two functions which worlds a caller's rows are withheld from.
fn device_only_worlds_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    destination: &ReadDestination,
) -> Result<std::collections::BTreeSet<EntityId>> {
    withheld_worlds_in(vault, txn, destination)
}

// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::models::model_owner_fallback_accepts_masked;
