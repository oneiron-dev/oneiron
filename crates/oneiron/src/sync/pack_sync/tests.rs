use super::*;
use crate::Vault;
use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::ErrorKind;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::registry::pack_byte_map::{PackInstanceEnvelope, PackKindIdentity};
use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::temporal::TimeRange;
use loro::ExportMode;

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

fn install(vault: &Vault, kinds: &[PackKindIdentity]) {
    vault
        .with_write_txn(|txn| vault.install_pack_kinds_in_txn(txn, kinds))
        .unwrap();
}

fn range_for(learned_at: u64) -> TimeRange {
    TimeRange {
        start: learned_at,
        end: learned_at,
    }
}

#[test]
fn canonical_outbound_restores_origin_handle_and_generation() -> Result<()> {
    let (_dir, vault) = vault();
    let alpha = kind("alpha");
    install(&vault, std::slice::from_ref(&alpha));
    let learned_at = 1_772_400_000u64;
    let id = EntityId::now();
    vault.put_pack_instance(
        &id,
        &alpha.name,
        range_for(learned_at),
        learned_at,
        b"payload",
    )?;
    let raw = vault.get_raw(&id)?.unwrap();
    let canonical = canonical_outbound_blob(&raw)?.unwrap();
    let local_envelope = PackInstanceEnvelope::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    let wire_envelope = PackInstanceEnvelope::from_bytes(&canonical[ENTITY_METADATA_HEADER_LEN..])?;
    assert_eq!(wire_envelope.kind, local_envelope.kind);
    assert_eq!(wire_envelope.payload, local_envelope.payload);
    assert_eq!(wire_envelope.origin, local_envelope.origin);
    assert_eq!(wire_envelope.generation, local_envelope.origin.generation);
    let wire_header = EntityMetadataHeader::parse(&canonical).unwrap();
    assert_eq!(wire_header.entity_type, local_envelope.origin.handle);
    assert_eq!(wire_header.learned_at, learned_at);
    // Non-pack rows pass through untouched.
    let ordinary = {
        let mut blob = Vec::new();
        blob.push(1u8);
        blob.extend_from_slice(&learned_at.to_be_bytes());
        blob.extend_from_slice(&learned_at.to_be_bytes());
        blob.extend_from_slice(&learned_at.to_be_bytes());
        blob.extend_from_slice(b"ordinary");
        blob
    };
    assert!(canonical_outbound_blob(&ordinary)?.is_none());
    Ok(())
}

#[test]
fn two_vault_loro_round_trip_is_stable_across_different_local_handles() -> Result<()> {
    let (_a_dir, source) = vault();
    let (_b_dir, destination) = vault();
    let alpha = kind("alpha");
    let beta = kind("beta");
    // Different local registration orders: same global names, different bytes.
    install(&source, &[alpha.clone(), beta.clone()]);
    install(&destination, &[beta, alpha.clone()]);
    assert_eq!(
        source.pack_kind_registration(&alpha.name)?.unwrap().handle,
        Some(128)
    );
    assert_eq!(
        destination
            .pack_kind_registration(&alpha.name)?
            .unwrap()
            .handle,
        Some(129)
    );
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let pack_id = EntityId::now();
    source.put_pack_instance(
        &pack_id,
        &alpha.name,
        range_for(learned_at),
        learned_at,
        b"shared payload",
    )?;
    let ordinary_id = EntityId::now();
    source.put_entity(
        &ordinary_id,
        1,
        range_for(learned_at),
        learned_at,
        b"ordinary body",
    )?;
    // Source reverse-mirrors canonical pack bytes plus the ordinary row.
    let source_doc = create_window_doc("source", &window_key);
    let mirrored = crate::sync::window::reverse_rematerialize(&source, &source_doc, &window_key)?;
    assert_eq!(mirrored, 2);
    let source_entities = source_doc.get_map("entities");
    let canonical = crate::sync::loro_support::map_get_bytes(&source_entities, &pack_id.to_hex())
        .expect("pack carrier mirrors");
    let source_raw = source.get_raw(&pack_id)?.unwrap();
    let expected_canonical = canonical_outbound_blob(&source_raw)?.unwrap();
    assert_eq!(canonical, expected_canonical);
    // Export/import the window update into the destination doc, then forward-remap.
    let update = source_doc.export(ExportMode::all_updates()).unwrap();
    let destination_doc = create_window_doc("destination", &window_key);
    destination_doc.import(&update).unwrap();
    let materializer = crate::sync::bridge::Materializer::new();
    let healed = crate::sync::window::forward_rematerialize(
        &destination,
        &destination_doc,
        &materializer,
        &window_key,
    )?;
    assert_eq!(healed, 2);
    let destination_raw = destination.get_raw(&pack_id)?.unwrap();
    let destination_header = EntityMetadataHeader::parse(&destination_raw).unwrap();
    assert_eq!(destination_header.entity_type, 129);
    let mapped = PackInstanceEnvelope::from_bytes(&destination_raw[ENTITY_METADATA_HEADER_LEN..])?;
    let original = PackInstanceEnvelope::from_bytes(&source_raw[ENTITY_METADATA_HEADER_LEN..])?;
    assert_eq!(mapped.kind, original.kind);
    assert_eq!(mapped.payload, original.payload);
    assert_eq!(mapped.origin, original.origin);
    assert_eq!(
        mapped.canonical_wire_form()?,
        original.canonical_wire_form()?
    );
    // Destination reverse-mirrors the SAME canonical bytes: no echo rewrite.
    let before = crate::sync::loro_support::map_get_bytes(
        &destination_doc.get_map("entities"),
        &pack_id.to_hex(),
    )
    .unwrap();
    assert_eq!(before, canonical);
    let second =
        crate::sync::window::reverse_rematerialize(&destination, &destination_doc, &window_key)?;
    assert_eq!(second, 0);
    let after = crate::sync::loro_support::map_get_bytes(
        &destination_doc.get_map("entities"),
        &pack_id.to_hex(),
    )
    .unwrap();
    assert_eq!(after, canonical);
    // Forward is idempotent on the echo: no repeated mutation.
    let healed_again = crate::sync::window::forward_rematerialize(
        &destination,
        &destination_doc,
        &materializer,
        &window_key,
    )?;
    assert_eq!(healed_again, 0);
    assert_eq!(destination.get_raw(&pack_id)?, Some(destination_raw));
    // Non-pack row replicates byte-identically and stays stable.
    assert_eq!(
        destination.get_raw(&ordinary_id)?,
        source.get_raw(&ordinary_id)?
    );
    Ok(())
}

#[test]
fn forged_identity_quarantines_and_missing_registration_pends_without_install() -> Result<()> {
    let (_a_dir, source) = vault();
    let (_b_dir, destination) = vault();
    let alpha = kind("alpha");
    install(&source, std::slice::from_ref(&alpha));
    install(&destination, std::slice::from_ref(&alpha));
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let forged_id = EntityId::now();
    source.put_pack_instance(
        &forged_id,
        &alpha.name,
        range_for(learned_at),
        learned_at,
        b"original",
    )?;
    let source_raw = source.get_raw(&forged_id)?.unwrap();
    let mut forged = PackInstanceEnvelope::from_bytes(&source_raw[ENTITY_METADATA_HEADER_LEN..])?;
    forged.kind.source_hash = [55; 32];
    let forged_body = forged.to_bytes()?;
    let mut forged_blob = Vec::new();
    forged_blob.push(128u8);
    forged_blob.extend_from_slice(&learned_at.to_be_bytes());
    forged_blob.extend_from_slice(&learned_at.to_be_bytes());
    forged_blob.extend_from_slice(&learned_at.to_be_bytes());
    forged_blob.extend_from_slice(&forged_body);
    let doc = create_window_doc("forged", &window_key);
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        &forged_id.to_hex(),
        &forged_blob,
    )?;
    doc.commit();
    let materializer = crate::sync::bridge::Materializer::new();
    let healed =
        crate::sync::window::forward_rematerialize(&destination, &doc, &materializer, &window_key)?;
    assert_eq!(healed, 0);
    assert!(destination.get_raw(&forged_id)?.is_none());
    let quarantined = quarantined_records(&destination)?;
    assert!(
        quarantined.iter().any(
            |(_, record)| record.container == QuarantineContainer::Entities
                && record.reason_code == "PackKindNameCollision"
        ),
        "forged source hash must quarantine as PackKindNameCollision, got {quarantined:?}"
    );
    // Missing local registration quarantines as NotInstalled and keeps no local row.
    let (_c_dir, uninstalled) = vault();
    let missing_id = EntityId::now();
    let missing_doc = create_window_doc("missing", &window_key);
    let canonical = canonical_outbound_blob(&source_raw)?.unwrap();
    crate::sync::loro_support::map_insert_bytes(
        &missing_doc.get_map("entities"),
        &missing_id.to_hex(),
        &canonical,
    )?;
    missing_doc.commit();
    let healed_missing = crate::sync::window::forward_rematerialize(
        &uninstalled,
        &missing_doc,
        &materializer,
        &window_key,
    )?;
    assert_eq!(healed_missing, 0);
    assert!(uninstalled.get_raw(&missing_id)?.is_none());
    assert!(uninstalled.pack_byte_map_snapshot()?.is_none());
    let missing_quarantined = quarantined_records(&uninstalled)?;
    assert!(
        missing_quarantined
            .iter()
            .any(|(_, record)| record.reason_code == "PackKindNotInstalled"),
        "missing registration must quarantine as PackKindNotInstalled, got {missing_quarantined:?}"
    );
    install(&uninstalled, std::slice::from_ref(&alpha));
    crate::sync::window::forward_rematerialize(
        &uninstalled,
        &missing_doc,
        &materializer,
        &window_key,
    )?;
    assert!(uninstalled.get_raw(&missing_id)?.is_some());
    Ok(())
}

#[test]
fn foreign_asset_map_snapshot_replicates_as_data_without_authorizing_install() -> Result<()> {
    let (_a_dir, source) = vault();
    let (_b_dir, destination) = vault();
    let alpha = kind("alpha");
    install(&source, std::slice::from_ref(&alpha));
    let snapshot = source.pack_byte_map_snapshot()?.unwrap();
    let body = serde_json::to_vec(&snapshot).unwrap();
    let carrier = {
        let hash = blake3::hash(&body);
        crate::codebase::entity_id_from_hash_material(
            b"oneiron:pack-byte-map-carrier:v1",
            &[hash.as_bytes()],
        )?
    };
    assert_eq!(source.get(&carrier)?.unwrap(), body);
    let instance_id = EntityId::now();
    let learned_at = crate::unix_seconds_now();
    source.put_pack_instance(
        &instance_id,
        &alpha.name,
        range_for(learned_at),
        learned_at,
        b"carrier-test payload",
    )?;
    let source_envelope = PackInstanceEnvelope::from_bytes(
        &source.get_raw(&instance_id)?.unwrap()[ENTITY_METADATA_HEADER_LEN..],
    )?;
    let window_key = WindowKey::from_timestamp(learned_at);
    let source_doc = create_window_doc("carrier-source", &window_key);
    let mirrored = crate::sync::window::reverse_rematerialize(&source, &source_doc, &window_key)?;
    assert!(mirrored >= 1);
    let update = source_doc.export(ExportMode::all_updates()).unwrap();
    let destination_doc = create_window_doc("carrier-destination", &window_key);
    destination_doc.import(&update).unwrap();
    let materializer = crate::sync::bridge::Materializer::new();
    crate::sync::window::forward_rematerialize(
        &destination,
        &destination_doc,
        &materializer,
        &window_key,
    )?;
    // The carrier replicates as an ordinary ASSET row ...
    let replicated = destination
        .get_raw(&carrier)?
        .expect("carrier replicates as data");
    let header = EntityMetadataHeader::parse(&replicated).unwrap();
    assert_eq!(header.entity_type, ENTITY_TYPE_ASSET);
    // ... but it never authorizes a local install.
    assert!(destination.pack_byte_map_snapshot()?.is_none());
    assert!(destination.pack_kind_registration(&alpha.name)?.is_none());
    let denied_id = EntityId::now();
    assert_eq!(
        destination
            .import_pack_instance(
                &denied_id,
                &source_envelope,
                range_for(learned_at),
                learned_at
            )
            .unwrap_err()
            .kind(),
        ErrorKind::PackKindNotInstalled
    );
    Ok(())
}
