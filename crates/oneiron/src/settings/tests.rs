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

/// Sol R5 F6: discovery counts each type from one scan of its index. Off
/// this device the scan names only rows no device-local world keeps; on this
/// device it names them all. Past the type's threshold row neither refuses
/// (rule 5): the owner-local check is raised once and the scan reads on.
#[test]
fn a_type_scan_off_this_device_names_no_device_local_row() -> Result<()> {
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
    // The threshold row fits the claims the vault opened with and one more.
    let mut portable = vault.entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?;
    portable.push(claim(None)?);
    for _ in 0..2 {
        claim(Some(world))?;
    }
    vault.keep_world_on_this_machine_for_test(world, true)?;

    let scan = crate::scan_check::EngineScan::TypeIndexRows;
    vault.set_scan_threshold(scan, u64::try_from(portable.len()).expect("fits"))?;
    let claims = |locality| vault.entities_by_type_at(crate::registry::ENTITY_TYPE_CLAIM, locality);
    assert_eq!(claims(CallerLocality::OnDevice)?.len(), portable.len() + 2);
    let mut off = claims(CallerLocality::OffDevice)?;
    off.sort();
    portable.sort();
    assert_eq!(off, portable);
    let checks = vault.scan_checks()?;
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].scan, scan.code());
    assert_eq!(
        checks[0].scope.as_deref(),
        Some(crate::entity_id::bytes_to_hex_lower(&[crate::registry::ENTITY_TYPE_CLAIM]).as_str())
    );
    Ok(())
}
