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
    let world = EntityId::from_bytes([0x62; 16])?;
    let world_layer = WorldLayer::new(Some(world), Some("studio".to_owned()))?;

    let update =
        vault.set_customization_layer(CustomizationLayerValue::World(world_layer.clone()))?;

    assert_eq!(update.settings.world, world_layer);
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(reopened.customization_settings()?.world, world_layer);
    Ok(())
}
