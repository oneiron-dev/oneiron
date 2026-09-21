//! PackByteMap contract tests: public results, persisted rows, and typed refusals.

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, RegistryError, Result};
use crate::registry::{ENTITY_TYPE_ASSET, TypeByteZone};
use crate::temporal::TimeRange;
use crate::{Vault, VaultConfig};

fn config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.map_size = 16 * 1024 * 1024;
    config
}

fn vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(config())
}

fn kind(slug: &str) -> PackKindIdentity {
    PackKindIdentity {
        name: format!("alice.tools.{slug}"),
        pack: "alice.tools".to_owned(),
        source_hash: [11; 32],
        schema_hash: [22; 32],
    }
}

fn range() -> TimeRange {
    TimeRange { start: 10, end: 10 }
}

#[test]
fn allocation_is_lowest_free_and_survives_reopen() -> Result<()> {
    let (dir, first) = vault();
    let registrations = first.install_pack_kinds(&[kind("alpha"), kind("beta")])?;
    assert_eq!(registrations[0].handle, Some(128));
    assert_eq!(registrations[1].handle, Some(129));
    let snapshot = first.pack_byte_map_snapshot()?.unwrap();
    let id = EntityId::now();
    first.put_pack_instance(
        &id,
        &kind("beta").name,
        range(),
        10,
        b"exact instance bytes",
    )?;
    let bytes = first.get(&id)?.unwrap();
    drop(first);
    let reopened = Vault::open(dir.path(), config())?;
    assert_eq!(reopened.pack_byte_map_snapshot()?.unwrap(), snapshot);
    assert_eq!(
        reopened.pack_kind_registration(&kind("alpha").name)?,
        Some(registrations[0].clone())
    );
    assert_eq!(reopened.get(&id)?, Some(bytes));
    assert_eq!(
        reopened.install_pack_kinds(&[kind("alpha")])?[0],
        registrations[0]
    );
    Ok(())
}

#[test]
fn collisions_and_duplicate_names_abort_the_entire_install() -> Result<()> {
    let (_dir, vault) = vault();
    let alpha = kind("alpha");
    vault.install_pack_kinds(std::slice::from_ref(&alpha))?;
    let before = vault.pack_byte_map_snapshot()?;
    let mut conflict = alpha.clone();
    conflict.source_hash = [99; 32];
    let err = vault
        .install_pack_kinds(&[kind("beta"), conflict])
        .unwrap_err();
    assert!(
        matches!(err, Error::Registry(RegistryError::PackKindNameCollision(name)) if name == alpha.name)
    );
    assert_eq!(vault.pack_byte_map_snapshot()?, before);
    assert!(vault.pack_kind_registration(&kind("beta").name)?.is_none());
    let mut schema_conflict = alpha.clone();
    schema_conflict.schema_hash = [98; 32];
    assert_eq!(
        vault
            .install_pack_kinds(&[schema_conflict])
            .unwrap_err()
            .kind(),
        ErrorKind::PackKindNameCollision
    );
    assert_eq!(
        vault
            .install_pack_kinds(&[alpha.clone(), alpha])
            .unwrap_err()
            .kind(),
        ErrorKind::PackKindNameCollision
    );
    for bad in [
        "alpha",
        "Alice.tools.alpha",
        "alice..tools.alpha",
        "alice.tools.x-y",
        "bob.tools.alpha",
    ] {
        let mut malformed = kind("alpha");
        malformed.name = bad.to_owned();
        assert_eq!(
            vault.install_pack_kinds(&[malformed]).unwrap_err().kind(),
            ErrorKind::InvalidPackByteMap
        );
    }
    Ok(())
}

#[test]
fn import_and_replay_resolve_name_not_the_senders_byte() -> Result<()> {
    let (_a, source) = vault();
    let (_b, destination) = vault();
    let alpha = kind("alpha");
    let beta = kind("beta");
    source.install_pack_kinds(&[alpha.clone(), beta.clone()])?;
    destination.install_pack_kinds(&[beta, alpha.clone()])?;
    let id = EntityId::now();
    source.put_pack_instance(&id, &alpha.name, range(), 10, b"original payload")?;
    let source_body = source.get(&id)?.unwrap();
    let original = PackInstanceEnvelope::from_bytes(&source_body)?;
    destination.import_pack_instance(&id, &original, range(), 10)?;
    let raw = destination.get_raw(&id)?.unwrap();
    assert_eq!(EntityMetadataHeader::parse(&raw).unwrap().entity_type, 129);
    let mapped = PackInstanceEnvelope::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    assert_eq!(mapped.kind, original.kind);
    assert_eq!(mapped.origin, original.origin);
    assert_eq!(mapped.payload, original.payload);
    assert_eq!(
        mapped.canonical_wire_form()?,
        original.canonical_wire_form()?
    );
    let replay_id = EntityId::now();
    destination
        .batch()
        .put_replicated(&replay_id, 128, range(), 10, &source_body)
        .commit()?;
    let replay_raw = destination.get_raw(&replay_id)?.unwrap();
    assert_eq!(
        EntityMetadataHeader::parse(&replay_raw)
            .unwrap()
            .entity_type,
        129
    );
    assert_eq!(
        PackInstanceEnvelope::from_bytes(&replay_raw[ENTITY_METADATA_HEADER_LEN..])?,
        mapped
    );
    // Exact source/schema is still identity: name alone cannot substitute code.
    let mut forged = original;
    forged.kind.source_hash = [55; 32];
    let denied_id = EntityId::now();
    assert_eq!(
        destination
            .import_pack_instance(&denied_id, &forged, range(), 10)
            .unwrap_err()
            .kind(),
        ErrorKind::PackKindNameCollision
    );
    assert!(destination.get(&denied_id)?.is_none());
    Ok(())
}

#[test]
fn imported_carrier_is_data_and_cannot_install_or_restore_authority() -> Result<()> {
    let (_a, source) = vault();
    let (_b, destination) = vault();
    source.install_pack_kinds(&[kind("alpha")])?;
    let snapshot = source.pack_byte_map_snapshot()?.unwrap();
    let body = serde_json::to_vec(&snapshot).unwrap();
    let carrier = super::persistence::carrier_id(blake3::hash(&body).as_bytes())?;
    // Source carrier is an ordinary stored entity, not an unexported cache.
    assert_eq!(source.get(&carrier)?, Some(body.clone()));
    destination.put_entity(&carrier, ENTITY_TYPE_ASSET, range(), 10, &body)?;
    assert_eq!(destination.get(&carrier)?, Some(body));
    assert!(destination.pack_byte_map_snapshot()?.is_none());
    let (_, envelope) = snapshot.envelope(&kind("alpha").name, b"data")?;
    let id = EntityId::now();
    assert_eq!(
        destination
            .import_pack_instance(&id, &envelope, range(), 10)
            .unwrap_err()
            .kind(),
        ErrorKind::PackKindNotInstalled
    );
    assert!(destination.get(&id)?.is_none());
    Ok(())
}

#[test]
fn uninstalled_handles_stay_pinned_by_live_rows_and_deleted_shells() -> Result<()> {
    let (_dir, vault) = vault();
    let alpha = kind("alpha");
    vault.install_pack_kinds(std::slice::from_ref(&alpha))?;
    let id = EntityId::now();
    vault.put_pack_instance(&id, &alpha.name, range(), 10, b"data")?;
    vault.uninstall_pack_kind(&alpha.name)?;
    assert!(!vault.gc_pack_kind(&alpha.name)?);
    assert_eq!(
        vault.install_pack_kinds(&[kind("beta")])?[0].handle,
        Some(129)
    );
    let denied_id = EntityId::now();
    assert_eq!(
        vault
            .put_pack_instance(&denied_id, &alpha.name, range(), 10, b"later")
            .unwrap_err()
            .kind(),
        ErrorKind::PackKindNotInstalled
    );
    assert!(
        vault
            .delete_entity_with_reason(&id, crate::deletion::DeleteReason::UserDelete)?
            .existed
    );
    // Soft deletion retains a metadata shell. This is still
    // a reference to the old kind; returning its byte now would reinterpret it.
    assert!(!vault.gc_pack_kind(&alpha.name)?);
    assert_eq!(
        vault.pack_kind_registration(&alpha.name)?.unwrap().handle,
        Some(128)
    );
    Ok(())
}

#[test]
fn collected_slots_reuse_lowest_byte_without_reinterpreting_stale_bodies() -> Result<()> {
    let (_dir, vault) = vault();
    let alpha = kind("alpha");
    vault.install_pack_kinds(std::slice::from_ref(&alpha))?;
    let original_map = vault.pack_byte_map_snapshot()?.unwrap();
    let (_, stale) = original_map.envelope(&alpha.name, b"old data")?;
    vault.uninstall_pack_kind(&alpha.name)?;
    assert!(vault.gc_pack_kind(&alpha.name)?);
    // Same identity can return, but never with an old local generation.
    let installed = vault
        .install_pack_kinds(std::slice::from_ref(&alpha))?
        .remove(0);
    assert_eq!(installed.handle, Some(128));
    assert_eq!(installed.generation, 2);
    let id = EntityId::now();
    assert_eq!(
        vault
            .put_entity(&id, 128, range(), 10, &stale.to_bytes()?)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidPackByteMap
    );
    assert!(vault.get(&id)?.is_none());
    vault.uninstall_pack_kind(&alpha.name)?;
    assert!(vault.gc_pack_kind(&alpha.name)?);
    let beta = vault.install_pack_kinds(&[kind("beta")])?.remove(0);
    assert_eq!(beta.handle, Some(128));
    assert_eq!(beta.generation, 3);
    assert!(
        vault
            .put_entity(&id, 128, range(), 10, &stale.to_bytes()?)
            .is_err()
    );
    // Retirement retains source/name ownership even after the byte is reused.
    let mut collision = alpha;
    collision.source_hash = [77; 32];
    assert_eq!(
        vault.install_pack_kinds(&[collision]).unwrap_err().kind(),
        ErrorKind::PackKindNameCollision
    );
    Ok(())
}

#[test]
fn forged_legacy_registration_never_opens_the_pack_half() -> Result<()> {
    let (dir, vault) = vault();
    assert_eq!(
        vault
            .register_structural_kind(128, "qx", TypeByteZone::PackHandle, "alice.tools")
            .unwrap_err()
            .kind(),
        ErrorKind::StructuralKindZoneViolation
    );
    // Forge the old cache's persisted row, including a valid zone ordinal.
    let pack = b"alice.tools";
    let mut encoded = vec![
        crate::store::STRUCTURAL_KIND_REGISTRY_RECORD_VERSION,
        128,
        5,
        2,
    ];
    encoded.extend_from_slice(&(pack.len() as u16).to_le_bytes());
    encoded.extend_from_slice(b"qx");
    encoded.extend_from_slice(pack);
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(
            txn,
            &crate::store::structural_kind_registry_key(128),
            &encoded,
        )
    })?;
    drop(vault);
    let reopened = Vault::open(dir.path(), config())?;
    let id = EntityId::now();
    assert_eq!(
        reopened
            .put_entity(&id, 128, range(), 10, b"forged")
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidEntityType
    );
    assert!(reopened.get(&id)?.is_none());
    assert!(reopened.pack_byte_map_snapshot()?.is_none());
    Ok(())
}

#[test]
fn malformed_or_replaced_carrier_fails_reads_and_reopen_closed() -> Result<()> {
    let (dir, vault) = vault();
    vault.install_pack_kinds(&[kind("alpha")])?;
    let snapshot = vault.pack_byte_map_snapshot()?.unwrap();
    let body = serde_json::to_vec(&snapshot).unwrap();
    let carrier = super::persistence::carrier_id(blake3::hash(&body).as_bytes())?;
    assert_eq!(
        vault
            .put_entity(&carrier, ENTITY_TYPE_ASSET, range(), 10, b"forged carrier")
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidPackByteMap
    );
    assert_eq!(
        vault.delete_entity(&carrier).unwrap_err().kind(),
        ErrorKind::InvalidPackByteMap
    );
    assert_eq!(vault.pack_byte_map_snapshot()?, Some(snapshot));
    // Inject disk corruption below the public gate to prove reopen checks the
    // carrier, rather than merely trusting that lawful writers once vetted it.
    vault.with_write_txn(|txn| {
        let raw = vault.store.entities.get(txn, carrier.as_bytes())?.unwrap();
        let mut corrupted = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
        corrupted.extend_from_slice(b"corrupt carrier");
        vault
            .store
            .entities
            .put(txn, carrier.as_bytes(), &corrupted)?;
        Ok(())
    })?;
    assert_eq!(
        vault.pack_byte_map_snapshot().unwrap_err().kind(),
        ErrorKind::InvalidPackByteMap
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), config());
    assert!(matches!(
        reopened,
        Err(Error::Registry(RegistryError::InvalidPackByteMap(_)))
    ));
    Ok(())
}

#[test]
fn overflow_shares_final_byte_with_name_bound_subtypes_and_safe_reuse() -> Result<()> {
    let (_dir, vault) = vault();
    let kinds: Vec<_> = (0..122).map(|i| kind(&format!("shape_{i}"))).collect();
    let installed = vault.install_pack_kinds(&kinds)?;
    assert_eq!(installed.first().unwrap().handle, Some(128));
    for row in &installed[119..] {
        assert_eq!(row.handle, Some(247));
    }
    assert_ne!(installed[119].generation, installed[120].generation);
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_pack_instance(&a, &kinds[119].name, range(), 10, b"first")?;
    vault.put_pack_instance(&b, &kinds[120].name, range(), 10, b"overflow")?;
    let a_bytes = vault.get(&a)?.unwrap();
    let a_body = &a_bytes;
    assert_eq!(PackInstanceEnvelope::from_bytes(a_body)?.kind, kinds[119]);
    let b_bytes = vault.get(&b)?.unwrap();
    assert_eq!(PackInstanceEnvelope::from_bytes(&b_bytes)?.kind, kinds[120]);
    assert_eq!(
        vault
            .put_pack_instance(&a, &kinds[120].name, range(), 10, b"wrong subtype")
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidPackByteMap
    );
    assert_eq!(
        vault
            .put_entity(&a, ENTITY_TYPE_ASSET, range(), 10, b"wrong kind")
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidPackByteMap
    );
    assert_eq!(vault.get(&a)?, Some(a_bytes));
    vault.uninstall_pack_kind(&kinds[119].name)?;
    assert!(!vault.gc_pack_kind(&kinds[119].name)?);
    vault.uninstall_pack_kind(&kinds[121].name)?;
    assert!(vault.gc_pack_kind(&kinds[121].name)?);
    assert_eq!(
        vault.install_pack_kinds(std::slice::from_ref(&kinds[121]))?[0].generation,
        4
    );
    vault.uninstall_pack_kind(&kinds[4].name)?;
    assert!(vault.gc_pack_kind(&kinds[4].name)?);
    assert_eq!(
        vault.install_pack_kinds(&[kind("extra")])?[0].handle,
        Some(132)
    );
    Ok(())
}

#[test]
fn binary_payload_encoding_cannot_hide_credentials_from_the_write_wall() -> Result<()> {
    let (_dir, vault) = vault();
    vault.install_pack_kinds(&[kind("alpha")])?;
    let id = EntityId::now();
    let error = vault
        .put_pack_instance(
            &id,
            &kind("alpha").name,
            range(),
            10,
            b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::GateWriteRejected);
    assert!(vault.get(&id)?.is_none());
    Ok(())
}

#[test]
fn archive_resolves_named_instances_without_importing_install_authority() -> Result<()> {
    use crate::context_pack::PackFormat;
    let (_a, source) = vault();
    let (_b, destination) = vault();
    let alpha = kind("alpha");
    let beta = kind("beta");
    source.install_pack_kinds(&[alpha.clone(), beta.clone()])?;
    let id = EntityId::now();
    source.put_pack_instance(&id, &alpha.name, range(), 10, b"exact portable data")?;
    let artifact = source.export_whole_vault(PackFormat::Json)?;
    destination.read_whole_vault_json(artifact.bytes())?;
    assert_eq!(
        destination
            .import_whole_vault_json(artifact.bytes())
            .unwrap_err()
            .kind(),
        ErrorKind::PackKindNotInstalled
    );
    assert!(destination.pack_byte_map_snapshot()?.is_none());
    assert!(destination.get(&id)?.is_none());
    destination.install_pack_kinds(&[beta, alpha.clone()])?;
    destination.import_whole_vault_json(artifact.bytes())?;
    assert_eq!(
        destination
            .import_whole_vault_json(artifact.bytes())?
            .inserted_entities,
        0
    );
    let raw = destination.get_raw(&id)?.unwrap();
    assert_eq!(EntityMetadataHeader::parse(&raw).unwrap().entity_type, 129);
    let original = PackInstanceEnvelope::from_bytes(&source.get(&id)?.unwrap())?;
    let restored = PackInstanceEnvelope::from_bytes(&destination.get(&id)?.unwrap())?;
    assert_eq!(
        original.canonical_wire_form()?,
        restored.canonical_wire_form()?
    );
    source.uninstall_pack_kind(&alpha.name)?;
    assert!(source.export_whole_vault(PackFormat::Json)?.bytes().len() > 100);
    Ok(())
}

#[test]
fn archive_nulls_pack_payload_credentials_without_losing_named_identity() -> Result<()> {
    use crate::context_pack::PackFormat;
    use crate::serialize::ExportBody;
    let (_dir, vault) = vault();
    let alpha = kind("alpha");
    vault.install_pack_kinds(std::slice::from_ref(&alpha))?;
    let id = EntityId::now();
    vault.put_pack_instance(&id, &alpha.name, range(), 10, b"safe")?;
    // Model legacy/corrupt storage below admission: export nulling is independently mandatory.
    vault.with_write_txn(|txn| {
        let raw = vault.store.entities.get(txn, id.as_bytes())?.unwrap();
        let mut body = PackInstanceEnvelope::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        body.payload = br#"{"password":"hidden-in-pack","value":4}"#.to_vec();
        let mut replaced = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
        replaced.extend(body.to_bytes()?);
        vault.store.entities.put(txn, id.as_bytes(), &replaced)?;
        Ok(())
    })?;
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        let archive = vault.export_whole_vault(format)?;
        assert!(!String::from_utf8_lossy(archive.bytes()).contains("hidden-in-pack"));
        if format == PackFormat::Json {
            let document = vault.read_whole_vault_json(archive.bytes())?;
            let row = document
                .evidence_ledger
                .entities
                .iter()
                .find(|r| r.id == id.to_hex())
                .unwrap();
            let ExportBody::Pack(body) = &row.body else {
                panic!("named identity lost");
            };
            assert_eq!(body.kind, alpha);
            assert_eq!(body.payload, ExportBody::Nulled);
            assert!(vault.import_whole_vault_json(archive.bytes()).is_err());
        }
    }
    Ok(())
}
