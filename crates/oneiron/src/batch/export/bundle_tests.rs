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

/// The second form keeps rows at the first form's depth: a claim value
/// nested as deep as the first form still carried whole keeps its pack whole
/// (a review finding against an enveloped second form, which sat one level
/// deeper and redacted it).
#[test]
fn knowledge_as_deep_as_the_first_form_carried_keeps_its_pack() -> Result<()> {
    use crate::agent_def::{KnowledgeFormat, agent_pack_files_in};
    let agent_id = EntityId::from_bytes([1, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])?;
    let definition = agent("fixture.agent", None);
    let whole = |format: KnowledgeFormat, depth: usize| -> Result<bool> {
        let mut value = Value::from("note");
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        let claim = ClaimBody::new(
            "preference.format",
            ClaimSubject::Entity(agent_id),
            value,
            0.7,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        let knowledge = [ExportEntity {
            id: EntityId::now().to_hex(),
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
        let files = agent_pack_files_in(format, &agent_id, &definition, &[], &knowledge)?;
        Ok(crate::serialize::export_source_tree(&files)?
            .content_hash
            .is_some())
    };
    let mut deepest = 0;
    while whole(KnowledgeFormat::V1, deepest + 1)? {
        deepest += 1;
        assert!(deepest < 64, "the first form refuses some depth");
    }
    assert!(whole(KnowledgeFormat::CURRENT, deepest)?);
    Ok(())
}

/// An archive an older engine wrote, its agent packs carrying the first
/// knowledge form, still imports: stored archives read back as written.
#[test]
fn an_archive_with_first_form_agent_knowledge_still_imports() -> Result<()> {
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    // A fixed id whose first-form facet the old writer kept whole.
    let agent_id = EntityId::from_bytes([1, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])?;
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

/// CONS-06 (owner ruling 2026-10-17, ARCH-0038 #export-credentials): the
/// Owner's whole-vault export keeps source-file credentials byte-equal to
/// stored ("all your data is all your data"), while scoped and contact
/// exports still null them. The redaction manifest is checked on the scoped
/// side, where redaction still happens.
#[test]
fn owner_whole_vault_keeps_source_credentials_that_scoped_and_contact_exports_null() -> Result<()> {
    use std::io::{Read as _, Seek as _};
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    // The real historical hub door can hold a scanner-flagged Candidate; the
    // Owner's own archive keeps that file's bytes, even when its secret has
    // an unfamiliar shape.
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
    // The Owner's whole-vault export keeps every source file byte-equal to
    // stored, and names no redaction for the skill.
    let export = vault.export_whole_vault(true)?;
    export.manifest().validate()?;
    assert!(export.manifest().secrets_included);
    let document = vault.read_whole_vault_archive(export.bytes())?;
    let tree = document
        .skills
        .iter()
        .find(|bundle| bundle.entity.id == id.to_hex())
        .expect("skill bundle")
        .source_tree
        .as_ref()
        .expect("skill source tree");
    assert_eq!(
        tree.content_hash,
        Some(tainted.content_hash()?.to_hex()),
        "the owner's archive keeps the skill's exact source identity"
    );
    for want in &tainted.files {
        let got = tree
            .files
            .iter()
            .find(|file| file.path == want.path)
            .expect("carried source file");
        assert_eq!(
            got.content,
            ExportSourceContent::Text(
                String::from_utf8(want.content.clone()).expect("UTF-8 fixture")
            ),
            "the owner's archive keeps {} byte-equal",
            want.path
        );
        assert!(got.sha256.is_some(), "a kept file keeps its proof");
    }
    assert_eq!(tree.files.len(), tainted.files.len());
    assert!(
        !document
            .manifest
            .bundle_omissions
            .iter()
            .any(|omission| omission.entity_id == id.to_hex()),
        "the owner's archive names no redaction for its skill"
    );
    assert!(
        !document
            .manifest
            .import_refusals
            .iter()
            .any(|refusal| matches!(
                refusal,
                ExportImportRefusal::Entity { entity_id, .. } if entity_id == &id.to_hex()
            )),
        "the owner's archive refuses nothing of its skill"
    );
    // The owner's archive restores the skill's exact source on import.
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    target.import_whole_vault_archive(export.bytes())?;
    let rtxn = target.store.env.read_txn()?;
    let restored = target
        .export_hub_package_in_txn(&rtxn, &id)?
        .expect("restored source package");
    let mut got = restored.export_files()?;
    let mut want = tainted.export_files()?;
    got.sort_by(|a, b| a.path.cmp(&b.path));
    want.sort_by(|a, b| a.path.cmp(&b.path));
    assert_eq!(got, want, "import restores the exact source files");
    drop(rtxn);
    // A scoped records archive for an off-device reader still nulls the
    // credential-bearing files, keeps the safe ones exact, and names the
    // redaction in its manifest.
    let contact = EntityId::now();
    let reader =
        crate::write_envelope::WriteActor::new(contact, crate::edge::EdgeActorClass::Human);
    let mut ids = BTreeSet::new();
    ids.insert(id);
    let (mut spool, receipt, _positions) = vault.export_records_archive(
        &ids,
        reader,
        |_txn| Ok::<_, Error>(()),
        vault.archive_spool_file()?,
    )?;
    assert!(
        receipt
            .manifest()
            .bundle_omissions
            .iter()
            .any(|omission| omission.entity_id == id.to_hex()
                && omission.reason == BundleOmissionReason::SkillSourceRedacted),
        "the scoped manifest names the redaction"
    );
    assert!(
        receipt
            .manifest()
            .import_refusals
            .iter()
            .any(|refusal| matches!(
                refusal,
                ExportImportRefusal::Entity { entity_id, reason }
                    if entity_id == &id.to_hex()
                        && *reason == ImportRefusalReason::RedactedSource
            )),
        "the scoped manifest refuses the redacted source"
    );
    spool.seek(std::io::SeekFrom::Start(0))?;
    let mut scoped_bytes = Vec::new();
    spool.read_to_end(&mut scoped_bytes)?;
    let scoped = vault.read_whole_vault_archive(&scoped_bytes)?;
    let scoped_tree = scoped
        .skills
        .iter()
        .find(|bundle| bundle.entity.id == id.to_hex())
        .expect("scoped skill bundle")
        .source_tree
        .as_ref()
        .expect("scoped source tree");
    assert_eq!(
        scoped_tree.content_hash, None,
        "a redacted tree claims no identity"
    );
    for path in ["scripts/private.py", "signature.json"] {
        let member = scoped_tree
            .files
            .iter()
            .find(|file| file.path == path)
            .expect("redacted member");
        assert_eq!(member.content, ExportSourceContent::Redacted);
        assert_eq!(member.sha256, None);
    }
    for path in ["SKILL.md", "scripts/count.py", "references/readme.md"] {
        let want = tainted
            .files
            .iter()
            .find(|file| file.path == path)
            .expect("fixture file");
        let got = scoped_tree
            .files
            .iter()
            .find(|file| file.path == path)
            .expect("carried safe file");
        assert_eq!(
            got.content,
            ExportSourceContent::Text(
                String::from_utf8(want.content.clone()).expect("UTF-8 fixture")
            ),
            "the scoped archive keeps {path} byte-equal"
        );
    }
    // No scoped record row carries a credential byte, end to end.
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(scoped_bytes.as_slice()))
        .map_err(|_| Error::InvariantViolation("scoped archive zip"))?;
    for index in 0..zip.len() {
        let mut member = zip
            .by_index(index)
            .map_err(|_| Error::InvariantViolation("scoped archive member"))?;
        if !member.name().starts_with("records/") {
            continue;
        }
        let name = member.name().to_owned();
        let mut text = String::new();
        member
            .read_to_string(&mut text)
            .map_err(|_| Error::InvariantViolation("scoped archive member"))?;
        assert!(
            !text.contains("residual-file-credential"),
            "scoped record carries no credential: {name}"
        );
        assert!(
            !text.contains("residual-signature"),
            "scoped record carries no credential: {name}"
        );
    }
    // A redacted source still cannot import: the refusal from the old test,
    // moved under the scope where redaction still happens.
    let (_scoped_dir, scoped_vault) = open_test_vault_with(VaultConfig::default());
    assert!(
        scoped_vault
            .import_whole_vault_archive(&scoped_bytes)
            .is_err()
    );
    assert!(scoped_vault.get_skill_record(&id)?.is_none());
    // The redaction manifest is checked: an archive whose manifest hides the
    // redaction is rejected.
    let tampered = archive_without_bundle_omissions(&scoped_bytes)?;
    assert!(vault.read_whole_vault_archive(&tampered).is_err());
    let tampered = archive_without_import_refusals(&scoped_bytes)?;
    assert!(vault.read_whole_vault_archive(&tampered).is_err());
    // The contact door emits selected ASSET bodies, not an expanded source
    // tree. Seed scan-off residue explicitly: normal package persistence skips
    // a credential-bearing carrier, so selecting the skill alone tests nothing.
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:contact-source-residue",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.set_secret_scan_mode(&owner, crate::batch::secret_scan::SecretScanMode::Off, 131)?;
    let carrier =
        crate::store::skill_source_carrier::source_carrier_id(&id, &tainted.content_hash()?)?;
    let carrier_bytes = crate::skill_hub::encode_source_carrier(&id, &tainted)?;
    vault.put_entity(
        &carrier,
        crate::registry::ENTITY_TYPE_ASSET,
        time(),
        130,
        &carrier_bytes,
    )?;
    assert_eq!(
        vault.get(&carrier)?.as_deref(),
        Some(carrier_bytes.as_slice())
    );
    let mut selected = vec![id, carrier];
    let mut source_files = Vec::new();
    for file in &tainted.files {
        let file_id = EntityId::now();
        vault.put_entity(
            &file_id,
            crate::registry::ENTITY_TYPE_ASSET,
            time(),
            130,
            &file.content,
        )?;
        assert_eq!(
            vault.get(&file_id)?.as_deref(),
            Some(file.content.as_slice())
        );
        selected.push(file_id);
        source_files.push((file_id, file.path.as_str()));
    }
    let bundle: serde_json::Value =
        serde_json::from_slice(&vault.export_entity_bundle_json(&selected)?)
            .map_err(|_| Error::InvariantViolation("bundle JSON"))?;
    let entities = bundle["entities"].as_array().expect("contact entities");
    let carried = entities
        .iter()
        .find(|row| row["id"] == carrier.to_hex())
        .expect("contact output contains the selected source carrier");
    assert_eq!(carried["entity_type"], crate::registry::ENTITY_TYPE_ASSET);
    assert!(
        carried["body"].is_null(),
        "the opaque source carrier withholds all credential members and its tree hash"
    );
    for (file_id, path) in source_files {
        let carried = entities
            .iter()
            .find(|row| row["id"] == file_id.to_hex())
            .expect("contact output contains the selected source file");
        match path {
            "scripts/private.py" => assert!(carried["body"].is_null()),
            "signature.json" => assert!(carried["body"]["signature"].is_null()),
            _ => {}
        }
    }
    let emitted = bundle.to_string();
    for secret in ["residual-file-credential", "residual-signature"] {
        let encoded = secret
            .bytes()
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            !emitted.contains(&encoded),
            "contact bundle contains no credential encoded as byte values: {emitted}"
        );
    }
    assert!(
        !emitted.contains("residual-file-credential"),
        "contact bundle: {emitted}"
    );
    assert!(
        !emitted.contains("residual-signature"),
        "contact bundle: {emitted}"
    );
    Ok(())
}

/// Copies a whole-vault archive member by member, with `bundle_omissions`
/// cleared from its manifest: the rows still declare the redaction.
fn archive_without_bundle_omissions(bytes: &[u8]) -> Result<Vec<u8>> {
    archive_with_changed_manifest(bytes, |manifest| manifest.bundle_omissions.clear())
}

/// Leaves the source redaction intact but hides its declared import refusal.
fn archive_without_import_refusals(bytes: &[u8]) -> Result<Vec<u8>> {
    archive_with_changed_manifest(bytes, |manifest| manifest.import_refusals.clear())
}

fn archive_with_changed_manifest(
    bytes: &[u8],
    mut change: impl FnMut(&mut WholeVaultDocumentManifest),
) -> Result<Vec<u8>> {
    use std::io::{Read as _, Write as _};
    let invalid = |what: &str| Error::InvalidConfig(format!("tampered fixture archive: {what}"));
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|_| invalid("unreadable"))?;
    let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::FileOptions::default();
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).map_err(|_| invalid("unreadable"))?;
        let name = member.name().to_owned();
        if name.ends_with('/') {
            continue;
        }
        let mut content = Vec::new();
        member
            .read_to_end(&mut content)
            .map_err(|_| invalid("unreadable"))?;
        if name == VAULT_ARCHIVE_MANIFEST_PATH {
            let mut manifest: WholeVaultDocumentManifest =
                serde_json::from_slice(&content).map_err(|_| invalid("manifest"))?;
            change(&mut manifest);
            content = serde_json::to_vec(&manifest).map_err(|_| invalid("manifest"))?;
        }
        out.start_file(name.as_str(), options)
            .map_err(|_| invalid("unwritable"))?;
        out.write_all(&content).map_err(|_| invalid("unwritable"))?;
    }
    Ok(out
        .finish()
        .map_err(|_| invalid("unwritable"))?
        .into_inner())
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
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
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
