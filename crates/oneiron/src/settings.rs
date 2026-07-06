//! Persisted customization settings and Eiri-visible change events.

use heed::types::Bytes;
use heed::{Database, RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::EntityId;
use crate::{Vault, unix_seconds_now};

/// Version of the persisted customization settings record.
pub const CUSTOMIZATION_SETTINGS_SCHEMA_VERSION: u16 = 1;

/// The four SET-03 customization layers persisted by this module.
pub const CUSTOMIZATION_SETTINGS_LAYER_COUNT: usize = 4;

/// Stable event kind for Eiri-readable customization change notifications.
pub const CUSTOMIZATION_SETTINGS_CHANGED_EVENT_KIND: &str = "settings.customization.changed";

const CUSTOMIZATION_SETTINGS_KEY: &[u8] = b"settings:customization:v1:profile";
const CUSTOMIZATION_EVENT_SEQUENCE_KEY: &[u8] = b"settings:customization:v1:event_sequence";
const CUSTOMIZATION_EVENT_KEY_PREFIX: &[u8] = b"settings:customization:v1:event:";
const TOKEN_MAX_BYTES: usize = 64;
const WORLD_LABEL_MAX_BYTES: usize = 128;

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

/// Eiri-readable event emitted when a customization layer changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomizationSettingsChangeEvent {
    pub sequence: u64,
    pub kind: String,
    pub changed_at: u64,
    pub layer: CustomizationLayer,
    pub previous: CustomizationLayerValue,
    pub current: CustomizationLayerValue,
    #[serde(rename = "aiCanChange")]
    pub ai_can_change: bool,
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
            ai_can_change: true,
            notice,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.sequence == 0
            || self.kind != CUSTOMIZATION_SETTINGS_CHANGED_EVENT_KIND
            || !self.ai_can_change
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

impl Vault {
    /// Reads the persisted customization settings, or the default four-layer model.
    pub fn customization_settings(&self) -> Result<CustomizationSettings> {
        let rtxn = self.store.env.read_txn()?;
        customization_settings_in_read_txn(&self.store.vault_meta, &rtxn)
    }

    /// Persists one customization layer and emits an Eiri-readable event when it changed.
    pub fn set_customization_layer(
        &self,
        value: CustomizationLayerValue,
    ) -> Result<CustomizationSettingsUpdate> {
        value.validate()?;
        self.with_write_txn(|wtxn| {
            let mut settings = customization_settings_in_write_txn(&self.store.vault_meta, wtxn)?;
            let previous = settings.layer_value(value.layer());
            if previous == value {
                return Ok(CustomizationSettingsUpdate {
                    settings,
                    event: None,
                });
            }

            settings.apply_layer_value(value.clone());
            let settings_raw = encode_customization_settings(&settings)?;
            let sequence = next_customization_event_sequence(&self.store.vault_meta, wtxn)?;
            let event = CustomizationSettingsChangeEvent::new(
                sequence,
                unix_seconds_now(),
                previous,
                value,
            );
            let event_raw = encode_customization_event(&event)?;
            self.store
                .vault_meta
                .put(wtxn, CUSTOMIZATION_SETTINGS_KEY, &settings_raw)?;
            self.store
                .vault_meta
                .put(wtxn, &customization_event_key(sequence), &event_raw)?;
            Ok(CustomizationSettingsUpdate {
                settings,
                event: Some(event),
            })
        })
    }

    /// Reads customization change events after `after_sequence`, capped by `limit`.
    pub fn customization_events_after(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<CustomizationSettingsChangeEvent>> {
        let rtxn = self.store.env.read_txn()?;
        customization_events_after_in_txn(&self.store.vault_meta, &rtxn, after_sequence, limit)
    }
}

fn customization_settings_in_read_txn(
    vault_meta: &Database<Bytes, Bytes>,
    rtxn: &RoTxn<'_>,
) -> Result<CustomizationSettings> {
    let Some(raw) = vault_meta.get(rtxn, CUSTOMIZATION_SETTINGS_KEY)? else {
        return Ok(CustomizationSettings::default());
    };
    decode_customization_settings(raw)
}

fn customization_settings_in_write_txn(
    vault_meta: &Database<Bytes, Bytes>,
    wtxn: &RwTxn<'_>,
) -> Result<CustomizationSettings> {
    let Some(raw) = vault_meta.get(wtxn, CUSTOMIZATION_SETTINGS_KEY)? else {
        return Ok(CustomizationSettings::default());
    };
    decode_customization_settings(raw)
}

fn next_customization_event_sequence(
    vault_meta: &Database<Bytes, Bytes>,
    wtxn: &mut RwTxn<'_>,
) -> Result<u64> {
    let next = match vault_meta.get(&*wtxn, CUSTOMIZATION_EVENT_SEQUENCE_KEY)? {
        Some(raw) => {
            let current = decode_sequence(raw)?;
            current
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("customization event sequence"))?
        }
        None => 1,
    };
    vault_meta.put(wtxn, CUSTOMIZATION_EVENT_SEQUENCE_KEY, &next.to_be_bytes())?;
    Ok(next)
}

fn customization_events_after_in_txn(
    vault_meta: &Database<Bytes, Bytes>,
    rtxn: &RoTxn<'_>,
    after_sequence: u64,
    limit: usize,
) -> Result<Vec<CustomizationSettingsChangeEvent>> {
    let mut events = Vec::new();
    for row in vault_meta.prefix_iter(rtxn, CUSTOMIZATION_EVENT_KEY_PREFIX)? {
        let (key, raw) = row?;
        let sequence = customization_event_sequence_from_key(key)?;
        if sequence <= after_sequence {
            continue;
        }
        if events.len() >= limit {
            break;
        }
        let event = decode_customization_event(raw)?;
        if event.sequence != sequence {
            return Err(Error::CorruptedIndex("customization settings event"));
        }
        events.push(event);
    }
    Ok(events)
}

fn customization_event_key(sequence: u64) -> [u8; CUSTOMIZATION_EVENT_KEY_PREFIX.len() + 8] {
    let mut key = [0; CUSTOMIZATION_EVENT_KEY_PREFIX.len() + 8];
    key[..CUSTOMIZATION_EVENT_KEY_PREFIX.len()].copy_from_slice(CUSTOMIZATION_EVENT_KEY_PREFIX);
    key[CUSTOMIZATION_EVENT_KEY_PREFIX.len()..].copy_from_slice(&sequence.to_be_bytes());
    key
}

fn customization_event_sequence_from_key(key: &[u8]) -> Result<u64> {
    let suffix = key
        .strip_prefix(CUSTOMIZATION_EVENT_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("customization settings event"))?;
    decode_sequence(suffix)
}

fn encode_customization_settings(settings: &CustomizationSettings) -> Result<Vec<u8>> {
    settings.validate()?;
    rmp_serde::to_vec_named(settings)
        .map_err(|_| Error::InvariantViolation("customization settings encode failed"))
}

fn decode_customization_settings(raw: &[u8]) -> Result<CustomizationSettings> {
    let settings: CustomizationSettings =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("customization settings"))?;
    settings.validate()?;
    Ok(settings)
}

fn encode_customization_event(event: &CustomizationSettingsChangeEvent) -> Result<Vec<u8>> {
    event.validate()?;
    rmp_serde::to_vec_named(event)
        .map_err(|_| Error::InvariantViolation("customization settings event encode failed"))
}

fn decode_customization_event(raw: &[u8]) -> Result<CustomizationSettingsChangeEvent> {
    let event: CustomizationSettingsChangeEvent = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("customization settings event"))?;
    event.validate()?;
    Ok(event)
}

fn decode_sequence(raw: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("customization settings event"))?;
    Ok(u64::from_be_bytes(bytes))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultConfig;

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        (dir, vault)
    }

    #[test]
    fn layer_write_persists_and_rereads_world_layer() -> Result<()> {
        let (dir, vault) = open_test_vault();
        let world = EntityId::from_bytes([0x42; 16])?;
        let world_layer = WorldLayer::new(Some(world), Some("studio".to_owned()))?;

        let update =
            vault.set_customization_layer(CustomizationLayerValue::World(world_layer.clone()))?;

        assert_eq!(update.settings.world, world_layer);
        drop(vault);
        let reopened = Vault::open(dir.path(), VaultConfig::default())?;
        assert_eq!(reopened.customization_settings()?.world, world_layer);
        Ok(())
    }

    #[test]
    fn settings_change_emits_eiri_readable_event() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let update = vault
            .set_customization_layer(CustomizationLayerValue::Accent(AccentLayer::new("blue")?))?;

        let event = update.event.expect("changed accent emits an event");
        assert_eq!(event.sequence, 1);
        assert_eq!(event.kind, CUSTOMIZATION_SETTINGS_CHANGED_EVENT_KIND);
        assert_eq!(event.layer, CustomizationLayer::Accent);
        assert!(event.ai_can_change);
        assert!(event.notice.contains("accent"));
        assert!(event.notice.contains("blue"));

        let events = vault.customization_events_after(0, 8)?;
        assert_eq!(events, vec![event]);
        Ok(())
    }

    #[test]
    fn no_alternate_message_style_rendering_path_is_part_of_settings_model() {
        assert_eq!(
            CustomizationLayer::all(),
            [
                CustomizationLayer::Accent,
                CustomizationLayer::Type,
                CustomizationLayer::Mode,
                CustomizationLayer::World
            ]
        );

        let serialized = serde_json::to_string(&CustomizationSettings::default()).unwrap();
        assert!(!serialized.contains("message_style"));
        assert!(!serialized.contains("bubble"));
        assert!(!serialized.contains("shape"));
    }
}
