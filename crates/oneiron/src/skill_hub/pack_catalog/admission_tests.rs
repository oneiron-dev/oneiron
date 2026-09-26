//! Caller-visible pack admission, re-consent, runtime and transaction laws.
use super::*;
use crate::{
    Vault, VaultConfig,
    consent::AuthenticatedOwner,
    entity_id::EntityId,
    error::Result,
    skill_hub::{
        ForeignSkillPublisher, HubAskSurface, HubFile, HubPin, HubRef, HubSyncPolicy, SkillHubKind,
        SkillHubRecord, SkillHubTrustTier,
    },
    temporal::TimeRange,
};
fn source(connector: bool) -> Result<PackSource> {
    let kind = if connector {
        "kind: connector\nadapter: built-in:email"
    } else {
        "kind: capability"
    };
    PackSource::from_files(vec![
        HubFile::new("PACK.md", format!("---\nname: alice.tools\ndescription: fixture\nversion: 1\n{kind}\npredicates: [\"alice.tools.topic\"]\nkinds: [\"alice.tools.item\"]\ngrants: [\"mail.read\"]\nwakes: [\"mail.arrived\"]\n---\nExact pack source\n").into_bytes()),
        HubFile::new("knowledge/kinds/alice.tools.item.json", br#"{"type":"object","description":"inert shape descriptor"}"#.to_vec()),
        HubFile::new("skills/format/SKILL.md", b"---\nname: alice.format\ndescription: format\nversion: 1\n---\nKeep facts exact.\n".to_vec()),
    ])
}
struct Policy {
    rules_hit: bool,
    code_auto_install: bool,
    fits: bool,
}
impl PackFitPolicy for Policy {
    fn evaluate(
        &self,
        _source: &PackSource,
        _permissions: &PackPermissions,
    ) -> Result<PackFitVerdict> {
        Ok(PackFitVerdict {
            fits: self.fits,
            rules_hit: self.rules_hit,
            code_auto_install: self.code_auto_install,
        })
    }
}
fn policy() -> Policy {
    Policy {
        rules_hit: false,
        code_auto_install: true,
        fits: true,
    }
}
fn fixture(
    tier: SkillHubTrustTier,
    source: &PackSource,
) -> Result<(
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    HubRef,
    ForeignSkillPublisher,
)> {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.map_size = 16 * 1024 * 1024;
    let (dir, vault) = crate::test_util::open_test_vault_with(config);
    let owner = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(&owner, crate::registry::ENTITY_TYPE_PERSON, at, 1, b"owner")?;
    let owner = vault.authenticate_owner(
        owner,
        "principal:pack-owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let hub = EntityId::now();
    let record = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        "https://example.invalid/packs.json",
        tier,
        HubSyncPolicy::ContentHashFrozen,
    )?;
    vault.configure_skill_hub(&owner, &hub, &record, at, 1)?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:pack-author", hub)?;
    let reference = HubRef::new(
        hub,
        "pack",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    Ok((dir, vault, owner, reference, publisher))
}
// Model a configured adapter's successful fetch in these unit fixtures. The
// real Git and HTTP adapters exercise the public fetch door separately.
fn fetched_fixture(
    vault: &Vault,
    source: &PackSource,
    reference: &HubRef,
    publisher: &ForeignSkillPublisher,
    at: u64,
) -> Result<EntityId> {
    let id = vault.stage_pack_source(source, TimeRange { start: at, end: at }, at)?;
    vault.with_write_txn(|txn| vault.record_pack_fetch_in_txn(txn, &id, reference, publisher))?;
    Ok(id)
}
#[test]
fn locally_staged_bytes_cannot_claim_a_hub_origin() -> Result<()> {
    let source = source(false)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Community, &source)?;
    let id = vault.stage_pack_source(&source, TimeRange { start: 3, end: 3 }, 3)?;
    assert!(
        vault
            .prepare_pack_install(id, &reference, &publisher, &policy())
            .is_err()
    );
    assert!(vault.installed_pack("alice.tools")?.is_none());
    Ok(())
}
#[test]
fn rejected_standalone_content_cannot_reactivate_through_a_pack() -> Result<()> {
    let source = source(false)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Community, &source)?;
    let skill_file = source
        .files()
        .iter()
        .find(|file| file.path == "skills/format/SKILL.md")
        .expect("skill folder");
    let package = crate::skill_hub::folder::package_from_files(vec![HubFile::new(
        "SKILL.md",
        skill_file.content.clone(),
    )])?;
    let skill_ref = HubRef::new(
        reference.hub_id,
        "standalone/format",
        HubPin::ContentHash(package.content_hash()?.to_hex()),
    )?;
    let skill =
        vault.import_skill_from_hub(&skill_ref, &package, TimeRange { start: 2, end: 2 }, 2)?;
    let mut rejected = vault.get_skill_record(&skill)?.expect("imported skill");
    rejected.approval_status = crate::claim::ClaimApprovalStatus::Rejected;
    vault.update_skill_record(&skill, &rejected, TimeRange { start: 3, end: 3 }, 3)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 4)?;
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    assert!(vault.install_pack(&ask).is_err());
    assert_eq!(
        vault.get_skill_record(&skill)?.unwrap().approval_status,
        crate::claim::ClaimApprovalStatus::Rejected
    );
    assert!(vault.installed_pack("alice.tools")?.is_none());
    assert!(vault.pack_kind_registration("alice.tools.item")?.is_none());
    Ok(())
}
#[test]
fn changed_hub_configuration_invalidates_prepared_install_without_losing_source() -> Result<()> {
    let source = source(false)?;
    let (_dir, vault, owner, reference, publisher) =
        fixture(SkillHubTrustTier::Community, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    let revised = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        "https://example.invalid/revised.json",
        SkillHubTrustTier::Untrusted,
        HubSyncPolicy::ContentHashFrozen,
    )?;
    vault.configure_skill_hub(
        &owner,
        &reference.hub_id,
        &revised,
        TimeRange { start: 4, end: 4 },
        4,
    )?;
    assert!(vault.install_pack(&ask).is_err());
    assert_eq!(vault.get_pack_source(&id)?, Some(source));
    assert!(vault.installed_pack("alice.tools")?.is_none());
    assert!(vault.pack_for_predicate("alice.tools.topic")?.is_none());
    assert!(vault.pack_kind_registration("alice.tools.item")?.is_none());
    Ok(())
}
#[test]
fn code_free_pack_installs_active_without_qualification_or_consent() -> Result<()> {
    for (tier, surface) in [
        (SkillHubTrustTier::Verified, HubAskSurface::OneTap),
        (
            SkillHubTrustTier::Community,
            HubAskSurface::SummarizedReview,
        ),
        (SkillHubTrustTier::Untrusted, HubAskSurface::FullReview),
    ] {
        let source = source(false)?;
        let (dir, vault, _owner, reference, publisher) = fixture(tier, &source)?;
        let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
        let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
        assert_eq!(ask.permissions().grants, ["mail.read"]);
        assert_eq!(ask.permissions().widening_grants, ["mail.read"]);
        assert_eq!(ask.surface(), surface);
        let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
            panic!("post-fit install");
        };
        assert_eq!(receipt.status, PackInstallStatus::Active);
        assert_eq!(receipt.hub_ref, "pack");
        assert_eq!(receipt.pin_value, source.content_hash().to_hex());
        assert_eq!(
            vault.pack_for_predicate("alice.tools.topic")?,
            Some((*receipt).clone())
        );
        assert_eq!(
            vault
                .pack_kind_registration("alice.tools.item")?
                .unwrap()
                .handle,
            Some(128)
        );
        let skill = EntityId::from_hex(&receipt.skills[0])?;
        assert_eq!(
            vault.get_skill_record(&skill)?.unwrap().lifecycle_status,
            crate::skill::SkillLifecycle::Active
        );
        // The resident can load and attribute the pack's exact authored skill
        // through the ordinary attempt door, not only inspect Active metadata.
        let queue = crate::attempt_queue::AttemptQueue::new(&vault);
        let crate::attempt_queue::EnqueueOutcome::Enqueued(attempt) =
            queue.enqueue(crate::attempt_queue::EnqueueAttempt {
                kind: "pack.runtime".to_owned(),
                payload: vec![],
                dedupe_key: None,
                run_id: None,
                now: 8,
            })?
        else {
            panic!("attempt")
        };
        let loaded = vault.load_attempt_skill_pack(attempt.id, &skill, 8)?;
        assert!(
            loaded
                .source_files
                .unwrap()
                .iter()
                .any(|file| file.path == "SKILL.md"
                    && file.content.ends_with(b"Keep facts exact.\n"))
        );
        assert_eq!(queue.get(attempt.id)?.unwrap().manifest.len(), 1);
        drop(vault);
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.map_size = 16 * 1024 * 1024;
        assert_eq!(
            Vault::open(dir.path(), config)?.installed_pack("alice.tools")?,
            Some(*receipt)
        );
    }
    Ok(())
}
#[test]
fn resident_authored_skill_rides_installed_pack_in_one_attempt() -> Result<()> {
    let source = source(false)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Verified, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("installed");
    };
    let bundled = EntityId::from_hex(&receipt.skills[0])?;
    let authored_id = EntityId::now();
    let mut authored = crate::skill::SkillRecord::new(
        "alice.workflow",
        "Conversation-authored workflow",
        "1",
        crate::claim::ClaimApprovalStatus::Approved,
        crate::skill::SkillLifecycle::Candidate,
        crate::claim::ClaimSource::UserStated,
        1.0,
        false,
        true,
        vec![crate::skill::SkillDependency::new("alice.format")],
        rmpv::Value::Map(vec![("source".into(), "resident-chat".into())]),
    );
    vault.put_skill_record(&authored_id, &authored, TimeRange { start: 5, end: 5 }, 5)?;
    authored.lifecycle_status = crate::skill::SkillLifecycle::Active;
    vault.update_skill_record(&authored_id, &authored, TimeRange { start: 6, end: 6 }, 6)?;
    let queue = crate::attempt_queue::AttemptQueue::new(&vault);
    let crate::attempt_queue::EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(crate::attempt_queue::EnqueueAttempt {
            kind: "pack.runtime".to_owned(),
            payload: vec![],
            dedupe_key: None,
            run_id: None,
            now: 7,
        })?
    else {
        panic!("attempt")
    };
    assert!(
        vault
            .load_attempt_skill_pack(attempt.id, &bundled, 7)?
            .source_files
            .is_some()
    );
    assert_eq!(
        vault
            .load_attempt_skill_pack(attempt.id, &authored_id, 8)?
            .record
            .skill_id,
        "alice.workflow"
    );
    let manifest = queue.get(attempt.id)?.unwrap().manifest;
    assert_eq!(manifest.len(), 2);
    assert!(
        manifest
            .iter()
            .any(|entry| entry.reference == "alice.workflow")
    );
    Ok(())
}
#[test]
fn code_flag_and_rule_hits_keep_candidate_inert() -> Result<()> {
    for rules_hit in [false, true] {
        let source = source(true)?;
        let (_dir, vault, _owner, reference, publisher) =
            fixture(SkillHubTrustTier::Verified, &source)?;
        let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
        let ask = vault.prepare_pack_install(
            id,
            &reference,
            &publisher,
            &Policy {
                rules_hit,
                code_auto_install: false,
                fits: true,
            },
        )?;
        let PackInstallDisposition::Candidate(receipt) = vault.install_pack(&ask)? else {
            panic!("candidate");
        };
        assert_eq!(vault.candidate_pack(&source)?, Some(*receipt.clone()));
        assert_eq!(
            receipt.candidate_reason,
            Some(if rules_hit {
                PackCandidateReason::RulesHit
            } else {
                PackCandidateReason::CodeAutoInstallOff
            })
        );
        assert!(vault.installed_pack("alice.tools")?.is_none());
        assert!(vault.pack_for_predicate("alice.tools.topic")?.is_none());
        assert!(vault.pack_kind_registration("alice.tools.item")?.is_none());
        let skill = EntityId::from_hex(&receipt.skills[0])?;
        assert_eq!(
            vault.get_skill_record(&skill)?.unwrap().lifecycle_status,
            crate::skill::SkillLifecycle::Candidate
        );
        let resumed = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
        assert!(matches!(
            vault.install_pack(&resumed)?,
            PackInstallDisposition::Installed(_)
        ));
        assert!(vault.candidate_pack(&source)?.is_none());
        assert_eq!(
            vault.get_skill_record(&skill)?.unwrap().lifecycle_status,
            crate::skill::SkillLifecycle::Active
        );
    }
    Ok(())
}
#[test]
fn code_free_pack_is_candidate_only_on_rules_hit() -> Result<()> {
    let source = source(false)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Untrusted, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    assert!(
        vault
            .prepare_pack_install(
                id,
                &reference,
                &publisher,
                &Policy {
                    fits: false,
                    rules_hit: false,
                    code_auto_install: true
                }
            )
            .is_err()
    );
    let ask = vault.prepare_pack_install(
        id,
        &reference,
        &publisher,
        &Policy {
            fits: true,
            rules_hit: true,
            code_auto_install: true,
        },
    )?;
    let PackInstallDisposition::Candidate(receipt) = vault.install_pack(&ask)? else {
        panic!("rules hit");
    };
    assert_eq!(
        receipt.candidate_reason,
        Some(PackCandidateReason::RulesHit)
    );
    assert!(vault.pack_kind_registration("alice.tools.item")?.is_none());
    Ok(())
}
#[test]
fn pinned_bundled_skill_verdict_keeps_pack_candidate() -> Result<()> {
    use crate::skill_hub::{
        ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillGovernance, SkillScanReceipt,
    };
    let source = source(false)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Verified, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    let blocked = vault.prepare_pack_install(
        id,
        &reference,
        &publisher,
        &Policy {
            fits: true,
            rules_hit: true,
            code_auto_install: true,
        },
    )?;
    let PackInstallDisposition::Candidate(candidate) = vault.install_pack(&blocked)? else {
        panic!("candidate");
    };
    let skill = EntityId::from_hex(&candidate.skills[0])?;
    let hash = vault
        .get_skill_record(&skill)?
        .expect("skill")
        .content_hash
        .expect("hash");
    let verdict = SkillScanReceipt::new(
        "fixture-risk",
        5,
        ScanVerdict::Malicious,
        ScanRiskLevel::Critical,
        ScanCompleteness::Complete,
        SkillGovernance::Prohibited,
    )?;
    vault.ingest_skill_scan_verdict(&skill, hash, &verdict, TimeRange { start: 5, end: 5 }, 5)?;
    let fit = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    let PackInstallDisposition::Candidate(receipt) = vault.install_pack(&fit)? else {
        panic!("scanner rules hit");
    };
    assert_eq!(
        receipt.candidate_reason,
        Some(PackCandidateReason::RulesHit)
    );
    assert!(vault.installed_pack("alice.tools")?.is_none());
    assert_eq!(
        vault.get_skill_record(&skill)?.unwrap().lifecycle_status,
        crate::skill::SkillLifecycle::Candidate
    );
    Ok(())
}
#[test]
fn update_changes_hash_and_card_without_reconsent_or_stale_replay() -> Result<()> {
    // A structural kind is an immutable global identity; this update changes only
    // the manifest's requested permissions, not a registered kind identity.
    let mut files = source(false)?.files().to_vec();
    files.retain(|f| !f.path.starts_with("knowledge/kinds/"));
    let manifest = String::from_utf8(
        files
            .iter()
            .find(|f| f.path == "PACK.md")
            .unwrap()
            .content
            .clone(),
    )
    .expect("utf8 fixture");
    files
        .iter_mut()
        .find(|f| f.path == "PACK.md")
        .unwrap()
        .content = manifest
        .lines()
        .filter(|line| !line.starts_with("kinds:"))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let source = PackSource::from_files(files)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Verified, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    let old = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    let PackInstallDisposition::Installed(original) = vault.install_pack(&old)? else {
        panic!("first");
    };
    assert!(vault.install_pack(&old).is_err());
    let mut files = source.files().to_vec();
    let manifest = String::from_utf8(
        files
            .iter()
            .find(|f| f.path == "PACK.md")
            .unwrap()
            .content
            .clone(),
    )
    .expect("utf8 fixture");
    files
        .iter_mut()
        .find(|f| f.path == "PACK.md")
        .unwrap()
        .content = manifest
        .replace("version: 1", "version: 2")
        .replace("mail.read", "mail.write")
        .into_bytes();
    let updated = PackSource::from_files(files)?;
    let new_ref = HubRef::new(
        reference.hub_id,
        "pack/v2",
        HubPin::ContentHash(updated.content_hash().to_hex()),
    )?;
    let new_id = fetched_fixture(&vault, &updated, &new_ref, &publisher, 4)?;
    let fresh = vault.prepare_pack_install(new_id, &new_ref, &publisher, &policy())?;
    assert_eq!(fresh.permissions().grants, ["mail.write"]);
    assert_eq!(fresh.permissions().widening_grants, ["mail.write"]);
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&fresh)? else {
        panic!("updated");
    };
    assert_eq!(receipt.content_hash, updated.content_hash().to_hex());
    assert_eq!(receipt.permissions.grants, ["mail.write"]);
    assert_eq!(receipt.skills, original.skills);
    let unchanged = EntityId::from_hex(&receipt.skills[0])?;
    assert_eq!(
        vault
            .get_skill_record(&unchanged)?
            .unwrap()
            .lifecycle_status,
        crate::skill::SkillLifecycle::Active
    );
    assert!(
        vault
            .edges_out(&unchanged)?
            .iter()
            .all(|edge| edge.kind != crate::edge::EdgeKind::Supersedes)
    );
    assert!(vault.candidate_pack(&updated)?.is_none());
    Ok(())
}
#[test]
fn bundled_skill_revision_supersedes_old_and_widened_capability_reaches_fit() -> Result<()> {
    struct WideningFit;
    impl PackFitPolicy for WideningFit {
        fn evaluate(&self, _source: &PackSource, card: &PackPermissions) -> Result<PackFitVerdict> {
            assert!(card.widening_grants.is_empty());
            assert_eq!(card.widening_bundled_skills.len(), 1);
            assert_eq!(card.widening_bundled_skills[0].skill_id, "alice.format");
            assert_eq!(card.widening_bundled_skills[0].env, ["MAIL_SCOPE"]);
            Ok(PackFitVerdict {
                fits: true,
                rules_hit: false,
                code_auto_install: true,
            })
        }
    }
    let mut files = source(false)?.files().to_vec();
    files.retain(|file| !file.path.starts_with("knowledge/kinds/"));
    let pack = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    pack.content = String::from_utf8(pack.content.clone())
        .expect("fixture utf8")
        .lines()
        .filter(|line| !line.starts_with("kinds:"))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let first = PackSource::from_files(files.clone())?;
    let (_dir, vault, _owner, reference, publisher) = fixture(SkillHubTrustTier::Verified, &first)?;
    let id = fetched_fixture(&vault, &first, &reference, &publisher, 3)?;
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    let PackInstallDisposition::Installed(first_receipt) = vault.install_pack(&ask)? else {
        panic!("first");
    };
    let old_id = EntityId::from_hex(&first_receipt.skills[0])?;
    let pack = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    pack.content = String::from_utf8(pack.content.clone())
        .expect("fixture utf8")
        .replace("version: 1", "version: 2")
        .into_bytes();
    let skill = files
        .iter_mut()
        .find(|file| file.path == "skills/format/SKILL.md")
        .unwrap();
    skill.content = b"---\nname: alice.format\ndescription: format\nversion: 2\nrequires-env: [\"MAIL_SCOPE\"]\n---\nKeep new facts exact.\n".to_vec();
    let revised = PackSource::from_files(files)?;
    let new_ref = HubRef::new(
        reference.hub_id,
        "pack/v2",
        HubPin::ContentHash(revised.content_hash().to_hex()),
    )?;
    let new_source = fetched_fixture(&vault, &revised, &new_ref, &publisher, 4)?;
    let ask = vault.prepare_pack_install(new_source, &new_ref, &publisher, &WideningFit)?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("revised");
    };
    assert_eq!(
        receipt.permissions.widening_bundled_skills[0].env,
        ["MAIL_SCOPE"]
    );
    let new_id = EntityId::from_hex(&receipt.skills[0])?;
    assert_ne!(new_id, old_id);
    assert_eq!(
        vault.get_skill_record(&old_id)?.unwrap().lifecycle_status,
        crate::skill::SkillLifecycle::Superseded
    );
    assert_eq!(
        vault.get_skill_record(&new_id)?.unwrap().lifecycle_status,
        crate::skill::SkillLifecycle::Active
    );
    assert_eq!(
        vault
            .edges_out(&new_id)?
            .iter()
            .filter(|edge| edge.kind == crate::edge::EdgeKind::Supersedes && edge.target == old_id)
            .count(),
        1
    );
    assert!(
        vault
            .load_attempt_skill_pack(crate::attempt_queue::AttemptId::now(), &old_id, 7)
            .is_err()
    );
    Ok(())
}
#[test]
fn same_pack_historical_alias_does_not_prevent_next_supersession() -> Result<()> {
    let mut files = source(false)?.files().to_vec();
    files.retain(|file| !file.path.starts_with("knowledge/kinds/"));
    let pack = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    pack.content = String::from_utf8(pack.content.clone())
        .expect("utf8 fixture")
        .lines()
        .filter(|line| !line.starts_with("kinds:"))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let v1 = PackSource::from_files(files.clone())?;
    let (_dir, vault, _owner, hub, publisher) = fixture(SkillHubTrustTier::Verified, &v1)?;
    let id = fetched_fixture(&vault, &v1, &hub, &publisher, 3)?;
    let ask = vault.prepare_pack_install(id, &hub, &publisher, &policy())?;
    let PackInstallDisposition::Installed(first) = vault.install_pack(&ask)? else {
        panic!("v1");
    };
    let old = EntityId::from_hex(&first.skills[0])?;
    let pack = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    pack.content = String::from_utf8(pack.content.clone())
        .expect("utf8 fixture")
        .replace("version: 1", "version: 2")
        .into_bytes();
    let v2 = PackSource::from_files(files.clone())?;
    let second_ref = HubRef::new(
        hub.hub_id,
        "pack/v2",
        HubPin::ContentHash(v2.content_hash().to_hex()),
    )?;
    let id = fetched_fixture(&vault, &v2, &second_ref, &publisher, 4)?;
    let ask = vault.prepare_pack_install(id, &second_ref, &publisher, &policy())?;
    vault.install_pack(&ask)?;
    assert_eq!(vault.skill_hub_provenance_count(&old)?, 2);
    let pack = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    pack.content = String::from_utf8(pack.content.clone())
        .expect("utf8 fixture")
        .replace("version: 2", "version: 3")
        .into_bytes();
    let skill = files
        .iter_mut()
        .find(|file| file.path == "skills/format/SKILL.md")
        .unwrap();
    skill.content = b"---\nname: alice.format\ndescription: format\nversion: 3\n---\nKeep the latest facts exact.\n".to_vec();
    let v3 = PackSource::from_files(files)?;
    let third_ref = HubRef::new(
        hub.hub_id,
        "pack/v3",
        HubPin::ContentHash(v3.content_hash().to_hex()),
    )?;
    let id = fetched_fixture(&vault, &v3, &third_ref, &publisher, 5)?;
    let ask = vault.prepare_pack_install(id, &third_ref, &publisher, &policy())?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("v3");
    };
    let next = EntityId::from_hex(&receipt.skills[0])?;
    assert_eq!(
        vault.get_skill_record(&old)?.unwrap().lifecycle_status,
        crate::skill::SkillLifecycle::Superseded
    );
    assert!(
        vault
            .edges_out(&next)?
            .iter()
            .any(|edge| edge.kind == crate::edge::EdgeKind::Supersedes && edge.target == old)
    );
    Ok(())
}
#[test]
fn dropping_a_sole_active_bundled_skill_refuses_update() -> Result<()> {
    let mut files = source(false)?.files().to_vec();
    files.retain(|file| !file.path.starts_with("knowledge/kinds/"));
    let manifest = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    manifest.content = String::from_utf8(manifest.content.clone())
        .expect("fixture utf8")
        .lines()
        .filter(|line| !line.starts_with("kinds:"))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let source = PackSource::from_files(files.clone())?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Verified, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    let PackInstallDisposition::Installed(original) = vault.install_pack(&ask)? else {
        panic!("first");
    };
    files.retain(|file| !file.path.starts_with("skills/"));
    let manifest = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    manifest.content = String::from_utf8(manifest.content.clone())
        .expect("fixture utf8")
        .replace("version: 1", "version: 2")
        .into_bytes();
    let dropped = PackSource::from_files(files)?;
    let new_ref = HubRef::new(
        reference.hub_id,
        "pack/v2",
        HubPin::ContentHash(dropped.content_hash().to_hex()),
    )?;
    let new_id = fetched_fixture(&vault, &dropped, &new_ref, &publisher, 4)?;
    let next = vault.prepare_pack_install(new_id, &new_ref, &publisher, &policy())?;
    assert!(vault.install_pack(&next).is_err());
    let old_id = EntityId::from_hex(&original.skills[0])?;
    assert_eq!(vault.installed_pack("alice.tools")?, Some(*original));
    assert_eq!(
        vault.get_skill_record(&old_id)?.unwrap().lifecycle_status,
        crate::skill::SkillLifecycle::Active
    );
    Ok(())
}
#[test]
fn agent_pack_and_section_share_fit_path_with_typed_permission_card() -> Result<()> {
    struct Bindings;
    impl crate::context_board::SectionBindingResolver for Bindings {
        fn state_family_exists(&self, family: &crate::context_board::StateFamilyRef) -> bool {
            family.family == "claim" && family.version == 1
        }
        fn authority_lane_exists(&self, lane: &crate::context_board::AuthorityLaneRef) -> bool {
            lane.0 == "read"
        }
        fn budget_policy_exists(&self, budget: &crate::context_board::BudgetPolicyRef) -> bool {
            budget.0 == crate::context_board::PLUGIN_SECTION_BUDGET_POLICY_REF
        }
    }

    let section = serde_json::json!({"section_id":"alice.tools.panel", "state_family":{"family":"claim","version":1},
        "verbs":["board.expand"], "authority_lane":"read", "budget_policy":"board.plugin_sections.v1"});
    let source = PackSource::from_files(vec![
        HubFile::new("PACK.md", b"---\nname: alice.tools\ndescription: agent\nversion: 1\nkind: agent\nfacets: {\"identity\":\"identity.md\",\"policy\":\"policy.md\",\"skills\":\"skills.json\",\"knowledge\":\"knowledge/selected.json\"}\n---\nAgent source\n"),
        HubFile::new("identity.md", b"Agent identity"), HubFile::new("policy.md", b"Agent policy"),
        HubFile::new("skills.json", b"[]"),
        HubFile::new("knowledge/selected.json", b"[]"),
        HubFile::new("knowledge/sections/alice.tools.panel.json", serde_json::to_vec(&section).unwrap()),
    ])?;
    let (dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Community, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    let paused = vault.prepare_pack_install(
        id,
        &reference,
        &publisher,
        &Policy {
            fits: true,
            rules_hit: true,
            code_auto_install: true,
        },
    )?;
    assert!(matches!(
        vault.install_pack(&paused)?,
        PackInstallDisposition::Candidate(_)
    ));
    assert!(
        crate::context_board::PluginSectionRegistry::rebuild(&vault, &Bindings)
            .expect("registry rebuild")
            .is_empty()
    );
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    assert_eq!(ask.permissions().section_verbs, ["board.expand"]);
    assert_eq!(ask.permissions().section_authorities, ["read"]);
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("agent pack");
    };
    assert_eq!(receipt.sections.len(), 1);
    assert_eq!(receipt.sections[0].section_id, "alice.tools.panel");
    let registry = crate::context_board::PluginSectionRegistry::rebuild(&vault, &Bindings)
        .expect("registry rebuild");
    let section_id = crate::context_board::SectionId("alice.tools.panel".into());
    assert!(registry.get_pack_section(&section_id).is_some());
    assert_eq!(
        crate::context_board::render_pack_sections(&registry, &[])
            .expect("pack render")
            .len(),
        1
    );
    drop(vault);
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.map_size = 16 * 1024 * 1024;
    let reopened = Vault::open(dir.path(), config)?;
    assert!(
        crate::context_board::PluginSectionRegistry::rebuild(&reopened, &Bindings)
            .expect("reopen rebuild")
            .get_pack_section(&section_id)
            .is_some()
    );
    Ok(())
}
#[test]
fn invalid_bundled_skill_rolls_back_install() -> Result<()> {
    let mut files = source(false)?.files().to_vec();
    files
        .iter_mut()
        .find(|f| f.path == "skills/format/SKILL.md")
        .unwrap()
        .content = b"missing required folder manifest".to_vec();
    let source = PackSource::from_files(files)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Community, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    // Capability disclosure now parses every bundled folder before fit.
    assert!(
        vault
            .prepare_pack_install(id, &reference, &publisher, &policy())
            .is_err()
    );
    assert!(vault.installed_pack("alice.tools")?.is_none());
    assert!(vault.pack_byte_map_snapshot()?.is_none());
    assert!(vault.pack_for_predicate("alice.tools.topic")?.is_none());
    assert_eq!(vault.get_pack_source(&id)?, Some(source));
    Ok(())
}
