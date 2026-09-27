//! Source-folder exports and ordinary admission, with no replay/activation bypass.
use super::*;
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::context_pack::PackFormat;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill::{SkillDependency, SkillLifecycle, SkillRecord};
use crate::skill_hub::{HubFile, HubPackage, HubPin, HubRef, SkillCapabilitySurface};
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;
use crate::{Vault, VaultConfig};
use rmpv::Value;

fn time() -> TimeRange {
    TimeRange {
        start: 100,
        end: 120,
    }
}

fn package() -> HubPackage {
    let record = SkillRecord::new(
        "fixture.bundle",
        "Portable skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        vec![],
        Value::Map(vec![(Value::from("fixture"), Value::from("source-bundle"))]),
    );
    let mut package = HubPackage::new(record, vec![
        HubFile::new("SKILL.md", b"---\nname: fixture.bundle\ndescription: Portable skill\nversion: 1.0.0\n---\nCount input lines.\n".to_vec()),
        HubFile::new("scripts/count.py", b"print(3)\n".to_vec()),
        HubFile::new("references/readme.md", b"Exact reference bytes.\n".to_vec()),
    ], SkillCapabilitySurface::default());
    package.record.content_hash = Some(package.content_hash().expect("bundle fixture"));
    package
}

fn agent(name: &str, parent: Option<EntityId>) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "Portable agent",
        "1.0.0",
        Some("Count carefully.\n".into()),
        vec![SkillDependency::new("fixture.bundle")],
        vec![],
        vec![],
        None,
        AgentScope::Base,
        AgentCeiling::Auto,
        parent,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("fixture"), Value::from("source-bundle"))]),
        None,
        true,
        None,
    )
}

fn install(vault: &Vault) -> Result<EntityId> {
    vault.import_skill_from_hub(
        &HubRef::new(EntityId::now(), "fixture/bundle", HubPin::None)?,
        &package(),
        time(),
        130,
    )
}

#[test]
fn source_bundles_all_five_formats_and_native_json_reimport() -> Result<()> {
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let skill = install(&source)?;
    let agent_id = EntityId::now();
    let mut generated_agent = agent("fixture.agent", None);
    generated_agent.source = ClaimSource::Generated;
    generated_agent.generated = true;
    generated_agent.human_authored = false;
    source.put_agent_definition(&agent_id, &generated_agent, time(), 130)?;
    let selected = EntityId::now();
    source.put_claim(
        &selected,
        &ClaimBody::new(
            "preference.format",
            ClaimSubject::Entity(agent_id),
            Value::from("brief"),
            0.7,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        ),
        time(),
        130,
    )?;
    let expected = package();
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        let export = source.export_whole_vault(format)?;
        export.manifest().validate(format)?;
        let text = std::str::from_utf8(export.bytes()).expect("bundle fixture");
        for value in [
            "SKILL.md",
            "scripts/count.py",
            "print(3)",
            "PACK.md",
            "identity.md",
            "policy.md",
            "skills.json",
            "knowledge/selected.json",
        ] {
            assert!(
                text.contains(value),
                "missing source facet {value} in {format:?}"
            );
        }
        assert!(text.contains(&expected.content_hash()?.to_hex()));
        if format != PackFormat::Json {
            continue;
        }
        assert_native_reimport(&export, skill, agent_id, selected, &expected)?;
    }
    Ok(())
}

fn assert_native_reimport(
    export: &WholeVaultExport,
    skill: EntityId,
    agent_id: EntityId,
    selected: EntityId,
    expected: &HubPackage,
) -> Result<()> {
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    let document = target.read_whole_vault_json(export.bytes())?;
    let bundle = document
        .skills
        .iter()
        .find(|b| b.entity.id == skill.to_hex())
        .expect("bundle fixture");
    assert_eq!(
        bundle
            .source_tree
            .as_ref()
            .expect("bundle fixture")
            .import_files()?,
        expected.export_files()?
    );
    let agent_bundle = document
        .agent_packs
        .iter()
        .find(|b| b.entity_id == agent_id.to_hex())
        .expect("bundle fixture");
    assert!(agent_bundle.fork_hash.is_some());
    assert_eq!(agent_bundle.omission, None);
    // A native export must enter the same hub pack consumer without a second schema.
    let native_files = agent_bundle
        .source_tree
        .as_ref()
        .expect("native agent source")
        .import_files()?;
    let source = crate::skill_hub::pack_catalog::PackSource::from_files(native_files.clone())?;
    assert_eq!(
        source.manifest().kind,
        crate::skill_hub::pack_catalog::PackKind::Agent
    );
    assert_eq!(
        source.content_hash(),
        crate::skill::canonical_skill_tree_hash(
            native_files
                .iter()
                .map(|file| (file.path.as_str(), file.content.as_slice()))
        )?
    );
    let refs: Vec<serde_json::Value> = serde_json::from_slice(
        &native_files
            .iter()
            .find(|file| file.path == "skills.json")
            .expect("native skills facet")
            .content,
    )
    .expect("native references");
    assert_eq!(refs[0]["entity_id"], skill.to_hex());
    assert_eq!(refs[0]["content_hash"], expected.content_hash()?.to_hex());
    install_native_agent_pack(&target, source)?;
    assert!(
        agent_bundle
            .source_tree
            .as_ref()
            .expect("bundle fixture")
            .files
            .iter()
            .any(|f| f.path == "knowledge/selected.json"
                && f.content
                    .as_ref()
                    .expect("bundle fixture")
                    .contains(&selected.to_hex()))
    );
    assert!(!document.manifest.import_omissions.is_empty());
    let receipt = target.import_whole_vault_json(export.bytes())?;
    assert_eq!(
        receipt.omitted_entities,
        document.manifest.import_omissions.len()
    );
    let imported_skill = target.get_skill_record(&skill)?.expect("bundle fixture");
    assert_eq!(imported_skill.source, ClaimSource::Imported);
    assert_eq!(
        imported_skill.approval_status,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(imported_skill.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(imported_skill.content_hash, expected.record.content_hash);
    let imported_agent = target
        .get_agent_definition(&agent_id)?
        .expect("bundle fixture");
    assert!(!imported_agent.enabled);
    assert_eq!(imported_agent.ceiling, AgentCeiling::Proposed);
    assert_eq!(imported_agent.source, ClaimSource::Imported);
    assert!(!imported_agent.generated);
    assert!(imported_agent.human_authored);
    assert_eq!(
        imported_agent.approval_status,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        target
            .get_claim(&selected)?
            .expect("bundle fixture")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(
        !target
            .skill_scan_verdicts_for_content_hash(expected.content_hash()?)?
            .is_empty()
    );
    let exported = target.export_whole_vault(PackFormat::Json)?;
    let readback = target.read_whole_vault_json(exported.bytes())?;
    assert_eq!(
        readback
            .skills
            .iter()
            .find(|b| b.entity.id == skill.to_hex())
            .expect("bundle fixture")
            .source_tree,
        bundle.source_tree
    );
    assert_eq!(
        target
            .import_whole_vault_json(export.bytes())?
            .inserted_entities,
        0
    );
    let mut activation = imported_skill;
    activation.lifecycle_status = SkillLifecycle::Active;
    assert!(
        target
            .update_skill_record(&skill, &activation, time(), 131)
            .is_err()
    );
    Ok(())
}

#[test]
fn fork_hash_binds_actual_parent_at_fork_not_current_parent_at_export() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    install(&vault)?;
    let parent = EntityId::now();
    let mut definition = agent("fixture.parent", None);
    vault.put_agent_definition(&parent, &definition, time(), 130)?;
    let before = vault.export_whole_vault(PackFormat::Json)?;
    let before = vault.read_whole_vault_json(before.bytes())?;
    let actual_parent_hash = before
        .agent_packs
        .iter()
        .find(|b| b.entity_id == parent.to_hex())
        .expect("bundle fixture")
        .source_tree
        .as_ref()
        .expect("bundle fixture")
        .content_hash
        .clone()
        .expect("bundle fixture");
    let fork = EntityId::now();
    vault.put_agent_definition(&fork, &agent("fixture.child", Some(parent)), time(), 131)?;
    definition.version = "2.0.0".into();
    definition.instructions = Some("Different source after fork.\n".into());
    vault.update_agent_definition(&parent, &definition, time(), 132)?;
    let after = vault.export_whole_vault(PackFormat::Json)?;
    let after = vault.read_whole_vault_json(after.bytes())?;
    let child_bundle = after
        .agent_packs
        .iter()
        .find(|b| b.entity_id == fork.to_hex())
        .expect("bundle fixture");
    let parent_bundle = after
        .agent_packs
        .iter()
        .find(|b| b.entity_id == parent.to_hex())
        .expect("bundle fixture");
    assert_eq!(child_bundle.fork_hash.as_ref(), Some(&actual_parent_hash));
    assert_ne!(
        parent_bundle
            .source_tree
            .as_ref()
            .expect("bundle fixture")
            .content_hash
            .as_ref(),
        Some(&actual_parent_hash)
    );
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    target.import_whole_vault_json(&serde_json::to_vec(&after).expect("bundle fixture"))?;
    let imported = target.export_whole_vault(PackFormat::Json)?;
    let imported = target.read_whole_vault_json(imported.bytes())?;
    assert_eq!(
        imported
            .agent_packs
            .iter()
            .find(|b| b.entity_id == fork.to_hex())
            .expect("bundle fixture")
            .fork_hash,
        child_bundle.fork_hash
    );
    Ok(())
}

#[test]
fn source_file_credentials_are_nulled_and_redaction_manifest_is_checked() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    // The real historical hub door can hold a scanner-flagged Candidate; export
    // still cannot release that file, even when its secret has an unfamiliar shape.
    let mut tainted = package();
    tainted.files.push(HubFile::new(
        "scripts/private.py",
        b"api_key = 'residual-file-credential'\n".to_vec(),
    ));
    tainted.files.push(HubFile::new(
        "signature.json",
        b"{\"signature\":\"residual-signature\"}".to_vec(),
    ));
    tainted.record.content_hash = Some(tainted.content_hash()?);
    let id = vault.import_skill_from_hub(
        &HubRef::new(EntityId::now(), "fixture/redacted", HubPin::None)?,
        &tainted,
        time(),
        130,
    )?;
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        let export = vault.export_whole_vault(format)?;
        export.manifest().validate(format)?;
        let text = std::str::from_utf8(export.bytes()).expect("bundle fixture");
        assert!(!text.contains("residual-file-credential"));
        assert!(!text.contains("residual-signature"));
        if format != PackFormat::Json {
            continue;
        }
        let mut document = vault.read_whole_vault_json(export.bytes())?;
        assert!(
            document
                .manifest
                .bundle_omissions
                .iter()
                .any(|o| o.entity_id == id.to_hex()
                    && o.reason == BundleOmissionReason::SkillSourceRedacted)
        );
        assert_eq!(
            document
                .skills
                .iter()
                .find(|b| b.entity.id == id.to_hex())
                .expect("bundle fixture")
                .source_tree
                .as_ref()
                .expect("bundle fixture")
                .content_hash,
            None
        );
        document.manifest.import_refusals.clear();
        assert!(
            vault
                .read_whole_vault_json(&serde_json::to_vec(&document).expect("bundle fixture"))
                .is_err()
        );
        let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
        assert!(target.import_whole_vault_json(export.bytes()).is_err());
        assert!(target.get_skill_record(&id)?.is_none());
    }
    Ok(())
}

#[test]
fn tampered_files_facets_paths_and_omissions_are_not_admitted() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    install(&vault)?;
    let id = EntityId::now();
    vault.put_agent_definition(&id, &agent("fixture.reject", None), time(), 130)?;
    let export = vault.export_whole_vault(PackFormat::Json)?;
    let document = vault.read_whole_vault_json(export.bytes())?;
    for mutate in 0..5 {
        let mut changed = document.clone();
        match mutate {
            0 => {
                changed.skills[0]
                    .source_tree
                    .as_mut()
                    .expect("bundle fixture")
                    .files[0]
                    .content = Some("changed instructions".into());
            }
            1 => {
                changed.skills[0]
                    .source_tree
                    .as_mut()
                    .expect("bundle fixture")
                    .files[0]
                    .path = "../SKILL.md".into();
            }
            2 => {
                changed
                    .agent_packs
                    .iter_mut()
                    .find(|b| b.entity_id == id.to_hex())
                    .expect("bundle fixture")
                    .source_tree
                    .as_mut()
                    .expect("bundle fixture")
                    .files[0]
                    .content = Some("forged policy".into());
            }
            3 => changed.manifest.import_omissions.clear(),
            _ => changed.manifest.source_boundaries.clear(),
        }
        assert!(
            vault
                .read_whole_vault_json(&serde_json::to_vec(&changed).expect("bundle fixture"))
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn missing_source_and_historic_fork_binding_are_explicit_not_invented() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let skill = EntityId::now();
    // Valid metadata has no folder unless an owning source door persisted one.
    vault.put_skill_record(&skill, &package().record, time(), 130)?;
    let parent = EntityId::now();
    vault.put_agent_definition(&parent, &agent("fixture.legacy-parent", None), time(), 130)?;
    let fork = EntityId::now();
    vault.put_agent_definition(
        &fork,
        &agent("fixture.legacy-fork", Some(parent)),
        time(),
        131,
    )?;
    // Model an on-disk fork born before source binding existed. No assertion of
    // private state follows; the public archive must report the missing fact.
    // Both the binding row and the birth source carrier go: the fork-hash door
    // falls back to the carrier when the binding is absent.
    vault.with_write_txn(|txn| {
        let mut key = b"agent_def/portable-birth/v1\0".to_vec();
        key.extend_from_slice(fork.as_bytes());
        vault.store.vault_meta.delete(txn, &key)?;
        let carrier = crate::agent_def::birth_source_id(&fork)?;
        if let Some(raw) = vault.store.entities.get(txn, carrier.as_bytes())? {
            let header =
                crate::batch::EntityMetadataHeader::parse(&raw).expect("birth carrier header");
            assert_eq!(
                header.entity_type,
                crate::registry::ENTITY_TYPE_ASSET,
                "derived carrier address holds the birth source"
            );
            vault.store.entities.delete(txn, carrier.as_bytes())?;
        }
        Ok(())
    })?;
    let export = vault.export_whole_vault(PackFormat::Json)?;
    let document = vault.read_whole_vault_json(export.bytes())?;
    assert!(
        document
            .manifest
            .bundle_omissions
            .iter()
            .any(|o| o.entity_id == skill.to_hex()
                && o.reason == BundleOmissionReason::SkillSourceUnavailable)
    );
    let bundle = document
        .agent_packs
        .iter()
        .find(|b| b.entity_id == fork.to_hex())
        .expect("bundle fixture");
    assert_eq!(bundle.fork_hash, None);
    assert_eq!(
        bundle.omission,
        Some(AgentBundleOmission::ForkBindingUnavailable)
    );
    assert!(
        bundle
            .source_tree
            .as_ref()
            .expect("bundle fixture")
            .content_hash
            .is_some()
    );
    Ok(())
}

fn install_native_agent_pack(
    vault: &Vault,
    source: crate::skill_hub::pack_catalog::PackSource,
) -> Result<()> {
    use crate::skill_hub::pack_catalog::{
        PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackPermissions, PackSourceAdapter,
    };
    use crate::skill_hub::{
        HubSyncPolicy, SkillHubAdapter, SkillHubKind, SkillHubRecord, SkillHubTrustTier,
    };
    struct NativeAdapter {
        hub: EntityId,
        endpoint: String,
        source: crate::skill_hub::pack_catalog::PackSource,
    }
    impl SkillHubAdapter for NativeAdapter {
        fn hub_id(&self) -> EntityId {
            self.hub
        }
        fn kind(&self) -> SkillHubKind {
            SkillHubKind::Git
        }
        fn endpoint(&self) -> Option<&str> {
            Some(&self.endpoint)
        }
        fn fetch_package(&self, _: &HubRef) -> Result<HubPackage> {
            Err(crate::Error::EntityNotFound)
        }
    }
    impl PackSourceAdapter for NativeAdapter {
        fn fetch_pack_source(
            &self,
            _: &HubRef,
        ) -> Result<crate::skill_hub::pack_catalog::PackSource> {
            Ok(self.source.clone())
        }
    }
    struct Fit;
    impl PackFitPolicy for Fit {
        fn evaluate(
            &self,
            _: &crate::skill_hub::pack_catalog::PackSource,
            permissions: &PackPermissions,
        ) -> Result<PackFitVerdict> {
            assert!(permissions.bundled_skills.is_empty());
            Ok(PackFitVerdict {
                fits: true,
                rules_hit: false,
                code_auto_install: true,
            })
        }
    }
    let owner_id = EntityId::now();
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        time(),
        131,
        b"native owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:native-pack",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let hub = EntityId::now();
    let endpoint = "https://example.invalid/native-hub";
    vault.configure_skill_hub(
        &owner,
        &hub,
        &SkillHubRecord::new(
            SkillHubKind::Git,
            endpoint,
            SkillHubTrustTier::Verified,
            HubSyncPolicy::PinnedCommit,
        )?,
        time(),
        132,
    )?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:native-pack", hub)?;
    let adapter = NativeAdapter {
        hub,
        endpoint: endpoint.to_owned(),
        source: source.clone(),
    };
    let reference = HubRef::new(
        hub,
        "agents/fixture.agent",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    let PackInstallDisposition::Installed(receipt) =
        vault.install_pack_from_adapter(&adapter, &reference, &publisher, &Fit, time(), 133)?
    else {
        panic!("native pack install");
    };
    assert_eq!(receipt.content_hash, source.content_hash().to_hex());
    assert_eq!(receipt.pin_value, source.content_hash().to_hex());
    Ok(())
}
