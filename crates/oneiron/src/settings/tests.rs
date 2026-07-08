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
