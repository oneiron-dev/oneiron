//! New births retain exact source and cannot acquire archive authority from a format tag.
use super::{HubFile, HubPackage, SkillPackageFormat, decode_hub_package, encode_hub_package};
use crate::batch::export::{ExportSkillBundle, ImportOmissionReason, WholeVaultDocument};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::context_pack::PackFormat;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use crate::skill_convert::{
    ConvertOutcome, ConvertRequest, RefineVerdict, RefinedSkill, SkillRefineBrief, SkillRefiner,
    convert_messages_to_skill,
};
use crate::temporal::TimeRange;
use crate::{Vault, VaultConfig};
use std::collections::BTreeSet;

fn at(value: u64) -> TimeRange {
    TimeRange {
        start: value,
        end: value,
    }
}

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("source fixture directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("source fixture vault");
    (dir, vault)
}

fn files() -> Vec<HubFile> {
    vec![
        HubFile::new("SKILL.md", b"---\nname: source-report\nrequires-bins: [\"python3\"]\nrequires-env: [\"REPORT_MODE\"]\nrequires-mcp: [\"reports\"]\nallowed-tools: [\"read_file\"]\n---\n\nCount  lines.\n".to_vec()),
        HubFile::new("scripts/count.py", b"print(3)\n".to_vec()),
    ]
}

struct Refiner;
impl SkillRefiner for Refiner {
    fn refine(&self, _: &SkillRefineBrief) -> Result<RefinedSkill> {
        Ok(RefinedSkill {
            // Native metadata deliberately differs from the source name. A merge
            // proposal has this shape too: the target owns the native skill id.
            skill_id: "native-report".into(),
            desc: "Count input lines when preparing a report".into(),
            files: files(),
            verdict: RefineVerdict::Mint {
                justification: "No existing report skill".into(),
            },
        })
    }
}

fn message(vault: &Vault) -> Result<EntityId> {
    let id = EntityId::now();
    let bytes = crate::gate::canonical_witness_message_body_for_test(
        "user",
        "dialogue",
        "Count the input lines for a report",
        true,
        0,
    )?;
    vault
        .batch()
        .put_canonical_message_for_test(&id, at(1), 1, &bytes)
        .commit()?;
    Ok(id)
}

fn convert(vault: &Vault, message: EntityId) -> Result<EntityId> {
    let ConvertOutcome::Created(id) = convert_messages_to_skill(
        vault,
        &ConvertRequest::new(vec![message]),
        &Refiner,
        at(2),
        2,
    )?
    else {
        panic!("first conversion creates a skill");
    };
    Ok(id)
}

fn snapshot(vault: &Vault) -> Result<WholeVaultDocument> {
    let export = vault.export_whole_vault(PackFormat::Json)?;
    vault.read_whole_vault_json(export.bytes())
}

fn bundle(document: &WholeVaultDocument, id: EntityId) -> &ExportSkillBundle {
    document
        .skills
        .iter()
        .find(|bundle| bundle.entity.id == id.to_hex())
        .expect("source bundle")
}

fn stored(vault: &Vault, id: EntityId) -> Result<HubPackage> {
    let txn = vault.store.env.read_txn()?;
    vault
        .export_hub_package_in_txn(&txn, &id)?
        .ok_or(Error::EntityNotFound)
}

#[test]
fn converted_partial_frontmatter_survives_reopen_with_exact_hash_and_dedup() -> Result<()> {
    let (dir, vault) = open();
    let selected = message(&vault)?;
    let id = convert(&vault, selected)?;
    let hash = canonical_skill_tree_hash(
        files()
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let record = vault.get_skill_record(&id)?.expect("converted record");
    assert_eq!(record.content_hash, Some(hash));
    assert_eq!(record.version, format!("convert-{}", &hash.to_hex()[..16]));
    assert_eq!(record.lifecycle_status, SkillLifecycle::Candidate);
    drop(vault);

    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let document = snapshot(&vault)?;
    let source = bundle(&document, id);
    assert_eq!(source.source_format, Some(SkillPackageFormat::Native));
    assert_eq!(
        source
            .source_tree
            .as_ref()
            .expect("source")
            .import_files()?,
        files()
    );
    assert!(
        !document
            .manifest
            .bundle_omissions
            .iter()
            .any(|omission| omission.entity_id == id.to_hex())
    );
    let package = stored(&vault, id)?;
    assert_eq!(decode_hub_package(&encode_hub_package(&package)?)?, package);
    let mut forged_capabilities = package.clone();
    forged_capabilities
        .capabilities
        .bins
        .insert("unbound-tool".into());
    assert_eq!(
        encode_hub_package(&forged_capabilities)
            .expect_err("Native envelopes cannot add a source-free capability grant")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        package.capabilities.bins,
        BTreeSet::from(["python3".to_owned()])
    );
    assert_eq!(
        package.capabilities.env,
        BTreeSet::from(["REPORT_MODE".to_owned()])
    );
    assert_eq!(
        package.capabilities.mcp,
        BTreeSet::from(["reports".to_owned()])
    );
    assert_eq!(
        package.capabilities.allowed_tools,
        BTreeSet::from(["read_file".to_owned()])
    );
    assert_eq!(
        convert_messages_to_skill(
            &vault,
            &ConvertRequest::new(vec![selected]),
            &Refiner,
            at(3),
            3,
        )?,
        ConvertOutcome::DupPointer(id)
    );
    // The converted skill plus the four bootstrap seed skills.
    assert_eq!(snapshot(&vault)?.skills.len(), 5);
    Ok(())
}

#[test]
fn package_and_record_rollback_together_after_both_writes() -> Result<()> {
    let (_dir, vault) = open();
    let id = EntityId::now();
    let hash = canonical_skill_tree_hash(
        files()
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        "rollback-source",
        "Rollback source",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("rollback-fixture"),
        )]),
    )
    .with_content_hash(hash);
    let package = super::package_from_source(&record, files(), SkillPackageFormat::Native)?;
    let result: Result<()> = vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, &id, &record, at(1), 1)?;
        vault.persist_hub_package_in_txn(txn, &id, &package)?;
        Err(Error::InvariantViolation(
            "source fixture abort after persistence",
        ))
    });
    assert_eq!(
        result.expect_err("abort").kind(),
        ErrorKind::InvariantViolation
    );
    assert!(vault.get_skill_record(&id)?.is_none());
    let txn = vault.store.env.read_txn()?;
    assert!(vault.export_hub_package_in_txn(&txn, &id)?.is_none());
    assert!(
        vault
            .skill_entity_for_content_hash_in_txn(&txn, hash)?
            .is_none()
    );
    Ok(())
}

#[test]
fn fork_reidentifies_exact_source_and_supported_json_reimports_only_candidates() -> Result<()> {
    let (_dir, vault) = open();
    // A source-only native package is the supported round-trip fixture. The
    // separate conversion test proves the real MESSAGE -> package producer.
    // Deleting a witness would create a local-only redaction audit, not remove
    // that owning import boundary.
    let parent = EntityId::now();
    let hash = canonical_skill_tree_hash(
        files()
            .iter()
            .map(|f| (f.path.as_str(), f.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        "native-report",
        "Count input lines",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        1.0,
        true,
        false,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("native-file-fixture"),
        )]),
    )
    .with_content_hash(hash);
    let source = super::package_from_source(&record, files(), SkillPackageFormat::Native)?;
    vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, &parent, &record, at(1), 1)?;
        vault.persist_hub_package_in_txn(txn, &parent, &source)
    })?;
    let mut metadata_only = record.clone();
    metadata_only.version = "2".into();
    metadata_only.desc = "Different instructions without different files".into();
    let body = crate::skill::encode_skill_record(&metadata_only)?;
    for door in 0..3 {
        let result = match door {
            0 => vault.update_skill_record(&parent, &metadata_only, at(2), 2),
            1 => vault
                .batch()
                .put(&parent, crate::registry::ENTITY_TYPE_SKILL, at(2), 2, &body)
                .commit(),
            _ => vault
                .batch()
                .put_replicated(&parent, crate::registry::ENTITY_TYPE_SKILL, at(2), 2, &body)
                .commit(),
        };
        assert_eq!(
            result
                .expect_err("source and native metadata stay bound")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
        assert_eq!(vault.get_skill_record(&parent)?, Some(record.clone()));
    }
    let before = stored(&vault, parent)?;
    let fork_id = EntityId::now();
    let fork = vault.fork_skill_record(&parent, &fork_id, "personal-report", at(3), 3)?;
    let after = stored(&vault, fork_id)?;
    assert_eq!(fork.content_hash, Some(after.content_hash()?));
    assert_ne!(fork.content_hash, before.record.content_hash);
    assert_eq!(after.capabilities, before.capabilities);
    assert_eq!(after.files[1..], before.files[1..]);
    assert_eq!(stored(&vault, parent)?, before);
    assert_eq!(fork.forked_from, Some(parent));
    assert_eq!(fork.lifecycle_status, SkillLifecycle::Candidate);
    let duplicate_fork = EntityId::now();
    assert_eq!(
        vault
            .fork_skill_record(&parent, &duplicate_fork, "personal-report", at(4), 4)
            .expect_err("a second fork cannot mint a second content-hash holder")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert!(vault.get_skill_record(&duplicate_fork)?.is_none());
    let text = std::str::from_utf8(&after.files[0].content).expect("source text");
    assert!(text.ends_with("\nCount  lines.\n"));
    assert_eq!(
        text.lines().find(|line| line.starts_with("name: ")),
        Some("name: \"personal-report\"")
    );
    assert_eq!(
        text.lines().find(|line| line.starts_with("version: ")),
        Some("version: \"1\"")
    );

    let export = vault.export_whole_vault(PackFormat::Json)?;
    let document = vault.read_whole_vault_json(export.bytes())?;
    // The seeded root project row (structural kind, no owning import adapter)
    // is the only expected refusal; the fork pair itself must not refuse.
    let root = vault
        .store
        .vault_meta
        .get(
            &vault.store.env.read_txn()?,
            b"project.root.v1",
        )?
        .map(|raw| EntityId::from_bytes(raw.as_ref().try_into().expect("root id")))
        .transpose()?
        .expect("seeded root project");
    assert_eq!(
        document.manifest.import_refusals,
        vec![crate::batch::export::ExportImportRefusal::Entity {
            entity_id: root.to_hex(),
            reason: crate::batch::export::ImportRefusalReason::OwningEntityAdapterRequired,
        }]
    );
    assert!(
        !document.manifest.bundle_omissions.iter().any(|omission| [
            parent.to_hex(),
            fork_id.to_hex()
        ]
        .contains(&omission.entity_id))
    );
    let policies: Vec<_> = document
        .manifest
        .import_omissions
        .iter()
        .filter(|omission| omission.reason == ImportOmissionReason::PolicyAuthorityNotRestored)
        .map(|omission| EntityId::from_hex(&omission.entity_id))
        .collect::<Result<_>>()?;
    assert_eq!(policies.len(), 1);
    let (_target_dir, target) = open();
    let local_policy = target
        .get(&policies[0])?
        .expect("target has its own default policy");
    // The parent + fork pair plus their two source carrier rows insert; the
    // source vault's root project row is skipped (owning-adapter refusal)
    // while the target keeps its own root, and identical seed rows count as
    // unchanged rather than inserted.
    let receipt = target.import_whole_vault_json(export.bytes())?;
    assert_eq!(receipt.inserted_entities, 4);
    assert_eq!(target.get(&policies[0])?, Some(local_policy));
    for id in [parent, fork_id] {
        let imported = target.get_skill_record(&id)?.expect("imported skill");
        assert_eq!(imported.source, ClaimSource::Imported);
        assert!(!imported.generated);
        assert!(imported.human_authored);
        assert_eq!(imported.approval_status, ClaimApprovalStatus::Proposed);
        assert_eq!(imported.lifecycle_status, SkillLifecycle::Candidate);
        assert!(
            !target
                .skill_scan_verdicts_for_content_hash(imported.content_hash.expect("hash"))?
                .is_empty()
        );
        assert_eq!(
            bundle(&snapshot(&target)?, id).source_tree,
            bundle(&document, id).source_tree
        );
        assert_eq!(
            stored(&target, id)?.capabilities,
            stored(&vault, id)?.capabilities
        );
        let mut activation = imported;
        activation.lifecycle_status = SkillLifecycle::Active;
        assert_eq!(
            target
                .update_skill_record(&id, &activation, at(4), 4)
                .expect_err("format does not authorize activation")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }
    assert_eq!(
        target
            .import_whole_vault_json(export.bytes())?
            .inserted_entities,
        0
    );

    // A native tree with incomplete frontmatter is not a portable Folder.
    // Relabelling it must fail validation before any entity lands.
    let mut forged = document;
    forged.skills[0].source_format = Some(SkillPackageFormat::Folder);
    let (_reject_dir, rejected) = open();
    assert!(
        rejected
            .import_whole_vault_json(&serde_json::to_vec(&forged).expect("JSON"))
            .is_err()
    );
    assert!(rejected.get_skill_record(&parent)?.is_none());
    assert!(rejected.get_skill_record(&fork_id)?.is_none());
    Ok(())
}
