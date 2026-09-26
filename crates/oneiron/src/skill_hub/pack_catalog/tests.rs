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
    let mut builtin = source.clone();
    builtin[0].content = String::from_utf8(builtin[0].content.clone())
        .unwrap()
        .replace("script:scripts/adapter.py", "built-in:email")
        .into_bytes();
    assert!(matches!(
        PackSource::from_files(builtin)?.manifest().adapter,
        Some(PackAdapter::Builtin(_))
    ));
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

pub(super) fn agent_files() -> Result<Vec<HubFile>> {
    use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    let definition = AgentDefinition::new(
        "example.worker",
        "Portable agent",
        "1.0.0",
        Some("Use the supplied facts.\n".into()),
        vec![],
        vec![],
        vec![],
        None,
        AgentScope::Base,
        AgentCeiling::Auto,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from("agent-pack"),
        )]),
        None,
        true,
        None,
    );
    crate::agent_def::agent_pack_files(&EntityId::now(), &definition, &[], &[])
}

#[test]
fn connector_and_agent_fixtures_share_a_manifest_and_preserve_source_hash() -> Result<()> {
    let mut script = vec![
        HubFile::new("PACK.md", b"---\nname: example.wire\ndescription: Script adapter\nversion: 1\nkind: connector\nadapter: script:scripts/adapter.py\n---\n".to_vec()),
        HubFile::new("scripts/adapter.py", b"print(1)\n".to_vec()),
    ];
    let mut builtin = script.clone();
    builtin[0].content = String::from_utf8(builtin[0].content.clone())
        .unwrap()
        .replace("script:scripts/adapter.py", "built-in:email")
        .into_bytes();
    builtin.pop();
    for (files, kind, adapter) in [
        (
            builtin,
            PackKind::Connector,
            PackAdapter::Builtin("email".into()),
        ),
        (
            std::mem::take(&mut script),
            PackKind::Connector,
            PackAdapter::Script("scripts/adapter.py".into()),
        ),
        (
            agent_files()?,
            PackKind::Agent,
            PackAdapter::Builtin("unused".into()),
        ),
    ] {
        let source = PackSource::from_files(files.clone())?;
        assert_eq!(source.manifest().kind, kind);
        if kind == PackKind::Agent {
            assert!(source.manifest().adapter.is_none());
            assert_eq!(
                source.manifest().agent_facets.as_ref().unwrap().identity,
                "identity.md"
            );
        } else {
            assert_eq!(source.manifest().adapter, Some(adapter));
            assert!(source.manifest().agent_facets.is_none());
        }
        let encoded = codec::encode(&source)?;
        let restored = codec::decode(&encoded)?.expect("pack source envelope");
        assert_eq!(restored, source);
        assert_eq!(restored.content_hash(), source.content_hash());
        assert_eq!(restored.manifest(), source.manifest());
        let mut reversed = files;
        reversed.reverse();
        assert_eq!(
            PackSource::from_files(reversed)?.content_hash(),
            source.content_hash()
        );
    }
    Ok(())
}

#[test]
fn agent_facets_are_required_typed_and_bound_to_the_manifest() -> Result<()> {
    let files = agent_files()?;
    let mutate = |path: &str, content: Vec<u8>| {
        let mut files = files.clone();
        files.iter_mut().find(|f| f.path == path).unwrap().content = content;
        files
    };
    for missing in [
        "identity.md",
        "policy.md",
        "skills.json",
        "knowledge/selected.json",
    ] {
        let files = files
            .iter()
            .filter(|f| f.path != missing)
            .cloned()
            .collect();
        assert!(PackSource::from_files(files).is_err(), "missing {missing}");
    }
    for bad in [
        mutate(
            "identity.md",
            b"An identity different from the policy.\n".to_vec(),
        ),
        mutate("policy.md", b"not typed JSON".to_vec()),
        mutate(
            "skills.json",
            br#"[{"skill_id":"demo","content_hash":"unbound"}]"#.to_vec(),
        ),
        mutate(
            "PACK.md",
            String::from_utf8(files[0].content.clone())
                .unwrap()
                .replace("example.worker", "example.other")
                .into_bytes(),
        ),
        mutate(
            "PACK.md",
            String::from_utf8(files[0].content.clone())
                .unwrap()
                .replace("identity.md", "scripts/identity.md")
                .into_bytes(),
        ),
    ] {
        assert!(PackSource::from_files(bad).is_err());
    }
    let mut with_code = files;
    with_code.push(HubFile::new(
        "scripts/launch.sh",
        b"echo not an agent facet\n".to_vec(),
    ));
    assert!(PackSource::from_files(with_code).is_err());
    Ok(())
}

#[test]
fn credential_in_any_agent_facet_is_refused_with_named_reason() -> Result<()> {
    for path in [
        "PACK.md",
        "identity.md",
        "policy.md",
        "skills.json",
        "knowledge/selected.json",
    ] {
        let mut files = agent_files()?;
        files
            .iter_mut()
            .find(|f| f.path == path)
            .unwrap()
            .content
            .extend_from_slice(b"\ntoken=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n");
        let err = PackSource::from_files(files).expect_err("credential must refuse");
        assert!(
            format!("{err:?}").contains("gate.secret_scan.github_token"),
            "{path}: {err:?}"
        );
    }
    Ok(())
}

#[test]
fn agent_skill_refs_require_pinned_hashes_and_match_policy_dependencies() -> Result<()> {
    use crate::skill::SkillDependency;
    let mut files = agent_files()?;
    let policy = files.iter_mut().find(|f| f.path == "policy.md").unwrap();
    let mut data: serde_json::Value = serde_json::from_slice(&policy.content).unwrap();
    let bytes = crate::serialize::ExportBody::to_bytes(
        &serde_json::from_value::<crate::serialize::ExportBody>(data["definition"].clone())
            .unwrap(),
    )?;
    let mut definition = crate::agent_def::decode_agent_definition(&bytes)?;
    definition
        .skills
        .push(SkillDependency::new("example.count"));
    let encoded = crate::agent_def::encode_agent_definition(&definition)?;
    data["definition"] = serde_json::to_value(crate::serialize::ExportBody::from_bytes(
        &encoded,
        crate::registry::ENTITY_TYPE_AGENT_DEF,
    ))
    .unwrap();
    policy.content = serde_json::to_vec(&data).unwrap();
    let refs = serde_json::json!([{
        "entity_id": EntityId::now().to_hex(),
        "skill_id": "example.count",
        "version": "1",
        "content_hash": "ab".repeat(32),
        "min_version": null,
    }]);
    files
        .iter_mut()
        .find(|f| f.path == "skills.json")
        .unwrap()
        .content = serde_json::to_vec(&refs).unwrap();
    assert_eq!(
        PackSource::from_files(files.clone())?.manifest().kind,
        PackKind::Agent
    );
    let mut bad = files.clone();
    bad.iter_mut()
        .find(|f| f.path == "skills.json")
        .unwrap()
        .content = serde_json::to_vec(&serde_json::json!([{
        "entity_id": refs[0]["entity_id"],
        "skill_id": "example.count",
        "version": "1",
        "content_hash": "not-a-content-hash",
        "min_version": null,
    }]))
    .unwrap();
    assert!(PackSource::from_files(bad).is_err());
    let mut bad = files;
    bad.iter_mut()
        .find(|f| f.path == "skills.json")
        .unwrap()
        .content = serde_json::to_vec(&serde_json::json!([{
        "entity_id": refs[0]["entity_id"],
        "skill_id": "example.unrelated",
        "version": "1",
        "content_hash": "ab".repeat(32),
        "min_version": null,
    }]))
    .unwrap();
    assert!(PackSource::from_files(bad).is_err());
    Ok(())
}
