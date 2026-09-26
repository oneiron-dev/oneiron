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
    vault.install_pack(&old)?;
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
    assert!(vault.candidate_pack(&updated)?.is_none());
    Ok(())
}
#[test]
fn agent_pack_and_section_share_fit_path_with_typed_permission_card() -> Result<()> {
    let section = serde_json::json!({"section_id":"alice.tools.panel", "state_family":{"family":"claim","version":1},
        "verbs":["board.expand"], "authority_lane":"read", "budget_policy":"board.plugin_sections.v1"});
    let source = PackSource::from_files(vec![
        HubFile::new("PACK.md", b"---\nname: alice.tools\ndescription: agent\nversion: 1\nkind: agent\n---\nAgent source\n"),
        HubFile::new("identity.md", b"Agent identity"), HubFile::new("policy.md", b"Agent policy"),
        HubFile::new("skills.json", format!("[\"{}\"]", "ab".repeat(32))),
        HubFile::new("knowledge/sections/alice.tools.panel.json", serde_json::to_vec(&section).unwrap()),
    ])?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Community, &source)?;
    let id = fetched_fixture(&vault, &source, &reference, &publisher, 3)?;
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    assert_eq!(ask.permissions().section_verbs, ["board.expand"]);
    assert_eq!(ask.permissions().section_authorities, ["read"]);
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("agent pack");
    };
    assert_eq!(receipt.sections.len(), 1);
    assert_eq!(receipt.sections[0].section_id, "alice.tools.panel");
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
    let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
    assert!(vault.install_pack(&ask).is_err());
    assert!(vault.installed_pack("alice.tools")?.is_none());
    assert!(vault.pack_byte_map_snapshot()?.is_none());
    Ok(())
}
