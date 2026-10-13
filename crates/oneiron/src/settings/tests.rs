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

/// Sol R5 F6: discovery counts each type from one capped scan of its index.
/// Off this device a row a device-local world keeps never counts toward the
/// cap: such rows alone never overflow it, and the scan names only the rest.
/// On this device they still fill it.
#[test]
fn a_type_scan_off_this_device_never_overflows_on_device_local_rows() -> Result<()> {
    use crate::claim::CallerLocality;
    let (_dir, vault) = open_test_vault();
    let at = crate::temporal::TimeRange { start: 1, end: 1 };
    let (world, subject) = (EntityId::now(), EntityId::now());
    vault.put_entity(&world, crate::registry::ENTITY_TYPE_WORLD, at, 1, b"world")?;
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        1,
        b"person",
    )?;
    let claim = |world: Option<EntityId>| -> Result<EntityId> {
        let mut body = crate::claim::ClaimBody::new(
            "profile.orchid",
            crate::claim::ClaimSubject::Entity(subject),
            rmpv::Value::from("kept"),
            1.0,
            crate::claim::ClaimApprovalStatus::Approved,
            crate::claim::ClaimLifecycleStatus::Active,
        )?;
        body.world = world;
        let id = EntityId::now();
        vault.put_claim(&id, &body, at, 1)?;
        Ok(id)
    };
    let portable = claim(None)?;
    for _ in 0..2 {
        claim(Some(world))?;
    }
    vault.set_world_device_only(world, true)?;

    let claims = |locality| {
        vault.entities_by_type_at_with_cap(crate::registry::ENTITY_TYPE_CLAIM, locality, 2)
    };
    assert!(matches!(
        claims(CallerLocality::OnDevice),
        Err(Error::IndexOverflow(_))
    ));
    assert_eq!(claims(CallerLocality::OffDevice)?, [portable]);
    Ok(())
}
