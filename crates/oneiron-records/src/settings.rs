//! Moved from `crates/oneiron/src/settings.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::settings::room_threads::RoomThreadAdminSettings;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::settings::model_pack;
pub use oneiron_store::settings::model_versioning;
pub use oneiron_store::settings::model_versioning::DEFAULT_MODEL_STACK_CURRENT_ID;
pub use oneiron_store::settings::model_versioning::DEFAULT_MODEL_STACK_V1_ID;
pub use oneiron_store::settings::model_versioning::ModelStack;
pub use oneiron_store::settings::model_versioning::ModelStackDeprecation;
pub use oneiron_store::settings::model_versioning::ModelStackDeprecationStage;
pub use oneiron_store::settings::model_versioning::ModelStackDeprecationStatus;
pub use oneiron_store::settings::model_versioning::ModelStackDisclosure;
pub use oneiron_store::settings::model_versioning::ModelStackId;
pub use oneiron_store::settings::model_versioning::ModelStackIdError;
pub use oneiron_store::settings::model_versioning::ModelStackModel;
pub use oneiron_store::settings::model_versioning::ModelStackPreference;
pub use oneiron_store::settings::model_versioning::ModelStackRegistry;
pub use oneiron_store::settings::model_versioning::ModelStackRegistryError;
pub use oneiron_store::settings::model_versioning::ModelStackResolution;
pub use oneiron_store::settings::model_versioning::default_model_stack_registry;
pub use oneiron_store::settings::model_versioning::try_default_model_stack_registry;
pub use oneiron_store::settings::web_connector;
pub use oneiron_verb_wire::settings::board_layout::AgentBoardLayoutOverride;
pub use oneiron_verb_wire::settings::board_layout::BOARD_LAYOUT_AGENT_OVERRIDES_MAX;
pub use oneiron_verb_wire::settings::destination::RecipientChoice;
pub use oneiron_verb_wire::settings::destination::RecipientWhy;
pub use oneiron_wake_contract::settings::destination::ReadDestination;
use serde::Deserialize;
use serde::Serialize;

/// Version of the persisted customization settings record.
pub const CUSTOMIZATION_SETTINGS_SCHEMA_VERSION: u16 = 1;

/// The four SET-03 customization layers persisted by this module.
pub const CUSTOMIZATION_SETTINGS_LAYER_COUNT: usize = 4;

/// Stable event kind for client-readable customization change notifications.
pub const CUSTOMIZATION_SETTINGS_CHANGED_EVENT_KIND: &str = "settings.customization.changed";

pub const TOKEN_MAX_BYTES: usize = 64;

pub const WORLD_LABEL_MAX_BYTES: usize = 128;

/// Complete persisted customization profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    fn layer_value(&self, layer: CustomizationLayer) -> CustomizationLayerValue {
        match layer {
            CustomizationLayer::Accent => CustomizationLayerValue::Accent(self.accent.clone()),
            CustomizationLayer::Type => CustomizationLayerValue::Type(self.type_layer.clone()),
            CustomizationLayer::Mode => CustomizationLayerValue::Mode(self.mode.clone()),
            CustomizationLayer::World => CustomizationLayerValue::World(self.world.clone()),
        }
    }

    fn apply_layer_value(&mut self, value: CustomizationLayerValue) {
        match value {
            CustomizationLayerValue::Accent(layer) => self.accent = layer,
            CustomizationLayerValue::Type(layer) => self.type_layer = layer,
            CustomizationLayerValue::Mode(layer) => self.mode = layer,
            CustomizationLayerValue::World(layer) => self.world = layer,
        }
    }

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

/// New value for one customization layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "layer", content = "value")]
pub enum CustomizationLayerValue {
    Accent(AccentLayer),
    Type(TypeLayer),
    Mode(ModeLayer),
    World(WorldLayer),
}

impl CustomizationLayerValue {
    /// Returns the layer this value updates.
    #[must_use]
    pub const fn layer(&self) -> CustomizationLayer {
        match self {
            Self::Accent(_) => CustomizationLayer::Accent,
            Self::Type(_) => CustomizationLayer::Type,
            Self::Mode(_) => CustomizationLayer::Mode,
            Self::World(_) => CustomizationLayer::World,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Accent(layer) => layer.validate(),
            Self::Type(layer) => layer.validate(),
            Self::Mode(layer) => layer.validate(),
            Self::World(layer) => layer.validate(),
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::Accent(layer) => layer.palette.clone(),
            Self::Type(layer) => layer.typeface.clone(),
            Self::Mode(layer) => layer.mode.clone(),
            Self::World(layer) => layer
                .label
                .clone()
                .or_else(|| layer.world_ref.clone())
                .unwrap_or_else(|| "default world".to_owned()),
        }
    }
}

/// Result of writing a customization layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomizationSettingsUpdate {
    pub settings: CustomizationSettings,
    pub event: Option<CustomizationSettingsChangeEvent>,
}

/// Client-readable event emitted when a customization layer changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomizationSettingsChangeEvent {
    pub sequence: u64,
    pub kind: String,
    pub changed_at: u64,
    pub layer: CustomizationLayer,
    pub previous: CustomizationLayerValue,
    pub current: CustomizationLayerValue,
    pub notice: String,
}

impl CustomizationSettingsChangeEvent {
    fn new(
        sequence: u64,
        changed_at: u64,
        previous: CustomizationLayerValue,
        current: CustomizationLayerValue,
    ) -> Self {
        let layer = current.layer();
        let notice = format!(
            "User changed the {} setting to {}.",
            layer.as_str(),
            current.summary()
        );
        Self {
            sequence,
            kind: CUSTOMIZATION_SETTINGS_CHANGED_EVENT_KIND.to_owned(),
            changed_at,
            layer,
            previous,
            current,
            notice,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.sequence == 0
            || self.kind != CUSTOMIZATION_SETTINGS_CHANGED_EVENT_KIND
            || self.previous.layer() != self.layer
            || self.current.layer() != self.layer
            || self.notice.is_empty()
        {
            return Err(Error::CorruptedIndex("customization settings event"));
        }
        self.previous.validate()?;
        self.current.validate()?;
        Ok(())
    }
}

pub fn validate_token(field: &'static str, value: &str) -> Result<()> {
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

pub fn validate_label(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > WORLD_LABEL_MAX_BYTES || value.contains(char::is_control) {
        return Err(Error::InvalidConfig(format!(
            "{field} must be non-empty visible text"
        )));
    }
    Ok(())
}
pub mod room_threads;
