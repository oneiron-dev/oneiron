//! Moved from `crates/oneiron/src/settings.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::settings::room_threads::RoomThreadAdminSettings;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
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
