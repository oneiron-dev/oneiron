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

/// A generated agent `agent_id` that uses the fixture skill, and one claim
/// about it for its selected knowledge: the skill's id and the claim's.
fn seed_portable_agent(source: &Vault, agent_id: EntityId) -> Result<(EntityId, EntityId)> {
    let skill = install(source)?;
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
        )?,
        time(),
        130,
    )?;
    Ok((skill, selected))
}

#[test]
fn source_bundles_all_five_formats_and_native_json_reimport() -> Result<()> {
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let agent_id = EntityId::now();
    let (skill, selected) = seed_portable_agent(&source, agent_id)?;
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

/// A real bug (this file's reimport check failed about 1 run in 600): the
/// source-file credential check read a typed id in an agent's selected
/// knowledge as an encoded payload whenever its bytes also parse as one whole
/// MessagePack value, and the export dropped the pack as a credential. This
/// agent's id is `c4 0e` and 14 bytes, a complete MessagePack bin8, and every
/// claim about it carries that id. The pack is read straight from the archive
/// bytes and installed through the hub consumer: the archive's own claim rows
/// meet the whole-vault document's credential pass, a separate path.
#[test]
fn an_agent_whose_id_reads_as_messagepack_keeps_its_pack_through_export_and_install() -> Result<()>
{
    let mut id = [0xc4, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    id[2..].copy_from_slice(b"fixture-agents");
    let mut cursor = std::io::Cursor::new(&id[..]);
    assert!(matches!(
        rmpv::decode::read_value(&mut cursor),
        Ok(Value::Binary(_))
    ));
    assert_eq!(cursor.position(), 16);
    let agent_id = EntityId::from_bytes(id)?;
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    seed_portable_agent(&source, agent_id)?;
    let export = source.export_whole_vault(PackFormat::Json)?;
    let archive: serde_json::Value = serde_json::from_slice(export.bytes()).expect("archive JSON");
    let bundle: ExportAgentBundle = serde_json::from_value(
        archive["agent_packs"]
            .as_array()
            .expect("agent bundles")
            .iter()
            .find(|bundle| bundle["entity_id"] == agent_id.to_hex())
            .expect("agent bundle")
            .clone(),
    )
    .expect("agent bundle");
    assert_eq!(bundle.omission, None);
    let files = bundle.source_tree.expect("agent source").import_files()?;
    let pack = crate::skill_hub::pack_catalog::PackSource::from_files(files)?;
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    install_native_agent_pack(&target, pack)
}

/// No id is ever read as a payload: over hundreds of agent packs with random
/// agent, world and relationship ids, every pack's source tree stays whole and
/// its selected knowledge reads back as written. Every fifth pack draws its
/// ids until their bytes parse as one whole MessagePack container, the shape
/// the first knowledge form dropped.
#[test]
fn no_random_id_drops_an_agent_pack() -> Result<()> {
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(0x0e1d);
    let mut random_id = |container: bool| loop {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes);
        let mut cursor = std::io::Cursor::new(&bytes[..]);
        let parses = matches!(
            rmpv::decode::read_value(&mut cursor),
            Ok(Value::Map(_) | Value::Array(_) | Value::Binary(_) | Value::Ext(..))
        ) && cursor.position() == 16;
        if (parses || !container)
            && let Ok(id) = EntityId::from_bytes(bytes)
        {
            return id;
        }
    };
    let definition = agent("fixture.agent", None);
    for pack in 0..250 {
        let container = pack % 5 == 0;
        let agent_id = random_id(container);
        let mut claim = ClaimBody::new(
            "preference.format",
            ClaimSubject::Entity(agent_id),
            Value::from("brief"),
            0.7,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        claim.world = Some(random_id(container));
        claim.rel = Some(random_id(container));
        let knowledge = vec![ExportEntity {
            id: random_id(false).to_hex(),
            short_ref: None,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred_start: 100,
            occurred_end: 120,
            learned_at: 130,
            body: crate::serialize::ExportBody::from_bytes(
                &crate::claim::encode_claim_body(&claim)?,
                crate::registry::ENTITY_TYPE_CLAIM,
            ),
        }];
        assert_eq!(
            crate::agent_def::select_agent_knowledge(&agent_id, &knowledge),
            knowledge
        );
        let files = crate::agent_def::agent_pack_files(&agent_id, &definition, &[], &knowledge)?;
        let tree = crate::serialize::export_source_tree(&files)?;
        let dropped: Vec<_> = tree
            .files
            .iter()
            .filter(|file| file.content.is_none())
            .map(|file| &file.path)
            .collect();
        assert!(
            tree.content_hash.is_some(),
            "agent {} lost its pack: {dropped:?}",
            agent_id.to_hex()
        );
        let selected = tree
            .files
            .iter()
            .find(|file| file.path == "knowledge/selected.json")
            .and_then(|file| file.content.as_deref())
            .expect("knowledge facet");
        assert_eq!(
            crate::agent_def::decode_agent_knowledge(selected.as_bytes())?,
            (crate::agent_def::KnowledgeFormat::CURRENT, knowledge)
        );
    }
    Ok(())
}

/// An archive an older engine wrote, its agent packs carrying the first
/// knowledge form, still imports: stored archives read back as written.
#[test]
fn an_archive_with_first_form_agent_knowledge_still_imports() -> Result<()> {
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let agent_id = EntityId::now();
    seed_portable_agent(&source, agent_id)?;
    let export = source.export_whole_vault(PackFormat::Json)?;
    let mut document: WholeVaultDocument =
        serde_json::from_slice(export.bytes()).expect("archive JSON");
    let bindings = document
        .agent_packs
        .iter()
        .filter_map(|bundle| {
            Some((
                EntityId::from_hex(&bundle.entity_id).ok()?,
                bundle.fork_hash.clone()?,
            ))
        })
        .collect();
    crate::serialize::populate_agent_bundles(
        &mut document,
        &bindings,
        crate::agent_def::KnowledgeFormat::V1,
    )?;
    let knowledge = document
        .agent_packs
        .iter()
        .find(|bundle| bundle.entity_id == agent_id.to_hex())
        .and_then(|bundle| bundle.source_tree.as_ref())
        .expect("agent source")
        .import_files()?
        .into_iter()
        .find(|file| file.path == "knowledge/selected.json")
        .expect("knowledge facet");
    assert_eq!(knowledge.content.first(), Some(&b'['));
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    target.import_whole_vault_json(&serde_json::to_vec(&document).expect("archive JSON"))?;
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
    // The source root project and its home room map onto this vault's root
    // (ARCH-0067: the vault itself is the root project).
    assert_eq!(
        receipt.omitted_entities,
        document.manifest.import_omissions.len() + 2
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
fn fork_hash_matches_unchanged_parent_with_selected_knowledge() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    install(&vault)?;
    let parent = EntityId::now();
    vault.put_agent_definition(
        &parent,
        &agent("fixture.knowledge-parent", None),
        time(),
        130,
    )?;
    let claim = EntityId::now();
    vault.put_claim(
        &claim,
        &ClaimBody::new(
            "test.source_note",
            ClaimSubject::Entity(parent),
            Value::from("Selected parent knowledge"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .unwrap(),
        time(),
        130,
    )?;
    let before = vault.export_whole_vault(PackFormat::Json)?;
    let before = vault.read_whole_vault_json(before.bytes())?;
    let claim_row = before
        .claims
        .iter()
        .find(|row| row.id == claim.to_hex())
        .unwrap();
    assert!(
        claim_row.short_ref.is_some(),
        "archive entity retains its hydratable short ref"
    );
    let parent_bundle = before
        .agent_packs
        .iter()
        .find(|bundle| bundle.entity_id == parent.to_hex())
        .unwrap();
    let tree = parent_bundle.source_tree.as_ref().unwrap();
    let parent_hash = tree.content_hash.as_ref().unwrap();
    let selected = tree
        .files
        .iter()
        .find(|file| file.path == "knowledge/selected.json")
        .unwrap();
    let (_, selected) =
        crate::agent_def::decode_agent_knowledge(selected.content.as_deref().unwrap().as_bytes())?;
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].id, claim.to_hex());
    assert_eq!(
        selected[0].short_ref, None,
        "portable facet has no source-vault refs"
    );
    let child = EntityId::now();
    vault.put_agent_definition(
        &child,
        &agent("fixture.knowledge-child", Some(parent)),
        time(),
        131,
    )?;
    let after = vault.export_whole_vault(PackFormat::Json)?;
    let after = vault.read_whole_vault_json(after.bytes())?;
    let unchanged_parent = after
        .agent_packs
        .iter()
        .find(|bundle| bundle.entity_id == parent.to_hex())
        .unwrap();
    assert_eq!(
        unchanged_parent
            .source_tree
            .as_ref()
            .unwrap()
            .content_hash
            .as_ref(),
        Some(parent_hash)
    );
    let fork = after
        .agent_packs
        .iter()
        .find(|bundle| bundle.entity_id == child.to_hex())
        .unwrap();
    assert_eq!(
        fork.fork_hash.as_ref(),
        Some(parent_hash),
        "fork captures the exported parent's exact portable tree"
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
    // Install screening reads the seeded pack-install policy and fails closed
    // without it (ONE-2019). Restore the shipped manifest this legacy fixture
    // cleared for the install only; the reimport keeps its manifest-free Gate.
    let policy_id = crate::gate::default_policy_manifest_id()?;
    crate::test_util::put_policy_manifest_bytes(
        vault,
        policy_id,
        &crate::gate::default_policy_manifest().unwrap(),
    )?;
    let installed =
        vault.install_pack_from_adapter(&adapter, &reference, &publisher, &Fit, time(), 133);
    vault.with_write_txn(|txn| {
        crate::batch::deindex_entity_for_test(&vault.store, txn, &policy_id)
    })?;
    let PackInstallDisposition::Installed(receipt) = installed? else {
        panic!("native pack install");
    };
    assert_eq!(receipt.content_hash, source.content_hash().to_hex());
    assert_eq!(receipt.pin_value, source.content_hash().to_hex());
    Ok(())
}
