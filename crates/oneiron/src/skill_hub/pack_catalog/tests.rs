//! Source custody tests: exact bytes, inert imports, generic/replay parity and rollback.
use super::*;
use crate::batch::export::{ExportPack, WholeVaultDocument};
use crate::context_pack::PackFormat;
use crate::skill_hub::HubFile;
use crate::{EntityId, TimeRange, Vault, VaultConfig, error::Result};

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}
fn files() -> Vec<HubFile> {
    vec![
    HubFile::new("PACK.md", b"---\nname: example.contacts\ndescription: Contact predicate pack\nversion: 1.0.0\nkind: capability\npredicates: [\"example.contacts.phone\"]\n---\nExact  source body.\n".to_vec()),
    HubFile::new("skills/contact/SKILL.md", b"---\nname: contact\ndescription: Contact format\nversion: 1.0.0\n---\nKeep spelling.\n".to_vec()),
]
}
#[test]
fn source_survives_reopen_and_all_formats_roundtrip_without_installing() -> Result<()> {
    let source = PackSource::from_files(files())?;
    let (dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let id = vault.stage_pack_source(&source, at(1), 2)?;
    assert_eq!(vault.stage_pack_source(&source, at(3), 4)?, id);
    assert_eq!(vault.list_pack_sources()?, vec![(id, source.clone())]);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(vault.get_pack_source(&id)?, Some(source.clone()));
    for format in [
        PackFormat::Json,
        PackFormat::Markdown,
        PackFormat::Toon,
        PackFormat::Yaml,
        PackFormat::Plaintext,
    ] {
        let artifact = vault.export_whole_vault(format)?;
        artifact.manifest().validate(format)?;
        assert!(String::from_utf8_lossy(artifact.bytes()).contains("Exact  source body."));
        if format == PackFormat::Json {
            let document = vault.read_whole_vault_json(artifact.bytes())?;
            let bundle = document
                .packs
                .iter()
                .find_map(|p| match p {
                    ExportPack::Source(p) if p.entity_id == id.to_hex() => Some(p),
                    _ => None,
                })
                .expect("source bundle");
            assert_eq!(
                bundle.source_tree.content_hash,
                Some(source.content_hash().to_hex())
            );
            assert_eq!(bundle.source_tree.import_files()?, source.files());
            let (_target_dir, target) =
                crate::test_util::open_test_vault_with(VaultConfig::default());
            target.import_whole_vault_json(artifact.bytes())?;
            assert_eq!(target.get_pack_source(&id)?, Some(source.clone()));
            assert_eq!(
                target
                    .import_whole_vault_json(artifact.bytes())?
                    .inserted_entities,
                0
            );
            // The source declares a predicate, but remains inert source data.
            assert!(target.get_skill_record(&id).is_err());
        }
    }
    Ok(())
}
#[test]
fn source_write_doors_refuse_identity_drift_and_roll_back() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let source = PackSource::from_files(files())?;
    let id = vault.stage_pack_source(&source, at(1), 1)?;
    let bytes = codec::encode(&source)?;
    let wrong = EntityId::now();
    assert!(
        vault
            .put_entity(&wrong, crate::registry::ENTITY_TYPE_ASSET, at(2), 2, &bytes)
            .is_err()
    );
    assert!(vault.get_raw(&wrong)?.is_none());
    assert!(
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_ASSET,
                at(2),
                2,
                b"replacement"
            )
            .is_err()
    );
    assert!(
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_ASSET,
                at(2),
                2,
                b"replacement"
            )
            .commit()
            .is_err()
    );
    let first = EntityId::now();
    assert!(
        vault
            .batch()
            .put(
                &first,
                crate::registry::ENTITY_TYPE_PERSON,
                at(2),
                2,
                b"rollback"
            )
            .put(&wrong, crate::registry::ENTITY_TYPE_ASSET, at(2), 2, &bytes)
            .commit()
            .is_err()
    );
    assert!(vault.get_raw(&first)?.is_none());
    assert_eq!(vault.get_pack_source(&id)?, Some(source));
    Ok(())
}
#[test]
fn missing_script_namespace_collision_and_tree_aliases_are_refused() -> Result<()> {
    let mut source = files();
    source[0].content=b"---\nname: example.connector\ndescription: Wire adapter\nversion: 1\nkind: connector\nadapter: script:scripts/adapter.py\n---\nWire.\n".to_vec();
    assert!(PackSource::from_files(source.clone()).is_err());
    source.push(HubFile::new("scripts/adapter.py", b"print(1)\n".to_vec()));
    assert!(PackSource::from_files(source.clone()).is_ok());
    source.push(HubFile::new(
        "scripts/adapter.py/child",
        b"aliased".to_vec(),
    ));
    assert!(PackSource::from_files(source).is_err());
    let mut source = files();
    source[0].content = String::from_utf8(source[0].content.clone())
        .unwrap()
        .replace("example.contacts.phone", "another.author.phone")
        .into_bytes();
    assert!(PackSource::from_files(source).is_err());
    Ok(())
}
#[test]
fn archive_rejects_replaced_or_missing_source_facets() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let source = PackSource::from_files(files())?;
    vault.stage_pack_source(&source, at(1), 1)?;
    let artifact = vault.export_whole_vault(PackFormat::Json)?;
    let mut document: WholeVaultDocument = serde_json::from_slice(artifact.bytes()).unwrap();
    let index = document
        .packs
        .iter()
        .position(|p| matches!(p, ExportPack::Source(_)))
        .unwrap();
    let ExportPack::Source(bundle) = &mut document.packs[index] else {
        unreachable!()
    };
    bundle.source_tree.files[0].content = Some("forged".into());
    assert!(
        vault
            .read_whole_vault_json(&serde_json::to_vec(&document).unwrap())
            .is_err()
    );
    let mut document: WholeVaultDocument = serde_json::from_slice(artifact.bytes()).unwrap();
    document.packs.remove(index);
    assert!(
        vault
            .read_whole_vault_json(&serde_json::to_vec(&document).unwrap())
            .is_err()
    );
    Ok(())
}
