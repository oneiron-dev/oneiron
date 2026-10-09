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
fn assert_bundled_source_line(
    vault: &Vault,
    pack_ref: &HubRef,
    skill: &EntityId,
    lifecycle: &str,
    outcome: &str,
) -> Result<()> {
    let record = vault.get_skill_record(skill)?.expect("bundled skill");
    let reference = super::pack_skill_hub_ref(
        pack_ref,
        "format",
        record.content_hash.expect("bundled skill hash"),
    )?;
    let receipt = vault
        .hub_import_receipt(skill, &reference)?
        .expect("source receipt");
    assert_eq!(receipt.installed_as.as_str(), lifecycle);
    assert_eq!(receipt.disposition.as_str(), outcome);
    assert_eq!(receipt.hub_id, pack_ref.hub_id.to_hex());
    assert_eq!(receipt.ref_string, reference.ref_string);
    crate::test_util::authorize_readers(vault, &["pack-reader"]);
    let read = vault.scoped_read(crate::claim::ScopedReadActorKey::new("pack-reader").unwrap());
    let changed = crate::context_board::SessionReadSet::default().refresh(&read, 16)?;
    let rendered = crate::context_board::render_board_block(
        &crate::context_board::BoardFrame {
            header: &crate::context_board::BoardBlockHeader {
                epoch: 1,
                scope: "base".into(),
            },
            legend: &crate::context_board::BoardLegend::canonical(),
            sections: &[],
            changes: Some(&changed),
        },
        crate::context_board::BoardBudgetRequest {
            harness_default_tok: 0,
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )
    .expect("board render");
    assert!(rendered.text.contains("changed_install["));
    assert!(rendered.text.contains(&receipt.hub_id));
    assert!(rendered.text.contains(&reference.ref_string));
    assert!(rendered.text.contains(&format!("{lifecycle}/{outcome}")));
    Ok(())
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
    // Boundary fixtures stage a full 16 MiB source plus its catalog indexes.
    config.map_size = 128 * 1024 * 1024;
    // Install admission resolves the seeded policy manifest. The generic
    // legacy helper deindexes it and cannot serve this fixture.
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
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
struct SourceAdapter {
    hub: EntityId,
    kind: SkillHubKind,
    endpoint: String,
    source: PackSource,
}
impl crate::skill_hub::SkillHubAdapter for SourceAdapter {
    fn hub_id(&self) -> EntityId {
        self.hub
    }
    fn kind(&self) -> SkillHubKind {
        self.kind
    }
    fn endpoint(&self) -> Option<&str> {
        Some(&self.endpoint)
    }
    fn fetch_package(&self, _: &HubRef) -> Result<crate::skill_hub::HubPackage> {
        Err(crate::Error::EntityNotFound)
    }
}
impl PackSourceAdapter for SourceAdapter {
    fn fetch_pack_source(&self, _: &HubRef) -> Result<PackSource> {
        Ok(self.source.clone())
    }
}
/// `(provider, verdict)` of every active scan row on these exact bytes.
fn scan_rows(vault: &Vault, source: &PackSource) -> Result<Vec<(String, String)>> {
    let text = |value: &rmpv::Value, key: &str| match value {
        rmpv::Value::Map(fields) => fields
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .and_then(|(_, value)| value.as_str())
            .map(str::to_owned),
        _ => None,
    };
    let mut rows = vault
        .skill_scan_verdicts_for_content_hash(source.content_hash())?
        .iter()
        .map(|body| {
            (
                text(&body.value, "provider").expect("scan provider"),
                text(&body.value, "verdict").expect("scan verdict"),
            )
        })
        .collect::<Vec<_>>();
    rows.sort();
    Ok(rows)
}
#[test]
fn knowledge_only_pack_fetch_scans_the_tree_and_keys_verdicts_by_content_hash() -> Result<()> {
    use crate::skill_hub::{
        ScanCompleteness, ScanRiskLevel, ScanVerdict, SkillGovernance, SkillScanReceipt,
    };
    let knowledge = |rows: &str| {
        PackSource::from_files(vec![
            HubFile::new(
                "PACK.md",
                b"---\nname: alice.catalog\ndescription: data\nversion: 1\nkind: capability\n---\nData only.\n".to_vec(),
            ),
            HubFile::new("knowledge/catalog.json", rows.as_bytes().to_vec()),
        ])
    };
    let source = knowledge(r#"{"rows":[]}"#)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Verified, &source)?;
    let endpoint = vault.skill_hub_record(&reference.hub_id)?.endpoint;
    let fetch = |source: &PackSource, reference: &HubRef, at: u64| {
        let adapter = SourceAdapter {
            hub: reference.hub_id,
            kind: SkillHubKind::HttpIndex,
            endpoint: endpoint.clone(),
            source: source.clone(),
        };
        let occurred = TimeRange { start: at, end: at };
        vault.fetch_pack_from_adapter(&adapter, reference, &publisher, occurred, at)
    };
    let static_only = vec![(
        crate::skill_scan::SCAN_PROVIDER_STATIC_PACK_V1.to_owned(),
        "unknown".to_owned(),
    )];
    assert!(scan_rows(&vault, &source)?.is_empty());
    // The hub fetch door scans a pack with no SKILL records at all.
    let (source_id, pinned) = fetch(&source, &reference, 3)?;
    assert_eq!(scan_rows(&vault, &source)?, static_only);
    // Identical bytes fetched again reuse their evidence.
    fetch(&source, &reference, 4)?;
    assert_eq!(scan_rows(&vault, &source)?, static_only);
    let ask = vault.prepare_pack_install(source_id, &pinned, &publisher, &policy())?;
    assert_eq!(ask.scan_risk(), Some(ScanRiskLevel::None));
    // An independent provider's disagreement is a second row on the same hash.
    let flagged = SkillScanReceipt::new(
        "fixture.external",
        4,
        ScanVerdict::Suspicious,
        ScanRiskLevel::High,
        ScanCompleteness::Complete,
        SkillGovernance::Discouraged,
    )?;
    let at = TimeRange { start: 4, end: 4 };
    vault.ingest_pack_scan_verdict(&source_id, &flagged, at, 4)?;
    assert_eq!(scan_rows(&vault, &source)?.len(), 2);
    // The verdict is a signal on the ask, never the gate.
    let ask = vault.prepare_pack_install(source_id, &pinned, &publisher, &policy())?;
    assert_eq!(ask.scan_risk(), Some(ScanRiskLevel::High));
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("a scan signal does not block a fitting pack");
    };
    assert!(receipt.skills.is_empty());
    // A new tree hash inherits none of the old tree's verdicts.
    let next = knowledge(r#"{"rows":[1]}"#)?;
    let next_ref = HubRef::new(
        reference.hub_id,
        "pack",
        HubPin::ContentHash(next.content_hash().to_hex()),
    )?;
    let (next_id, next_pinned) = fetch(&next, &next_ref, 5)?;
    assert_eq!(scan_rows(&vault, &next)?, static_only);
    assert_eq!(scan_rows(&vault, &source)?.len(), 2);
    let ask = vault.prepare_pack_install(next_id, &next_pinned, &publisher, &policy())?;
    assert_eq!(ask.scan_risk(), Some(ScanRiskLevel::None));
    Ok(())
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
        assert_eq!(receipt.kind, PackKind::Capability);
        assert_eq!(receipt.adapter, None);
        assert_eq!(receipt.engine_version, None);
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
        assert_bundled_source_line(&vault, &reference, &skill, "active", "installed")?;
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
        let crate::attempt_queue::ClaimOutcome::Claimed(leased) = queue.claim_kind(
            "pack.runtime",
            crate::attempt_queue::ClaimAttempt {
                lease_owner: "worker".into(),
                now: 8,
            },
        )?
        else {
            panic!("lease")
        };
        let loaded = vault.load_attempt_skill_pack(
            attempt.id,
            &skill,
            "worker",
            leased.attempt_count,
            "fixture/model@1",
            8,
        )?;
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
        assert_bundled_source_line(
            &vault,
            &reference,
            &skill,
            "candidate",
            if rules_hit {
                "rules_hit"
            } else {
                "code_auto_install_off"
            },
        )?;
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
fn pinned_bundled_skill_scanner_signal_does_not_override_fit() -> Result<()> {
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
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&fit)? else {
        panic!("fit-ready pack installs despite advisory scanner signal");
    };
    assert_eq!(receipt.candidate_reason, None);
    assert!(vault.installed_pack("alice.tools")?.is_some());
    let stored = vault.get_skill_record(&skill)?.unwrap();
    assert_eq!(
        stored.lifecycle_status,
        crate::skill::SkillLifecycle::Active
    );
    assert_eq!(
        stored.approval_status,
        crate::claim::ClaimApprovalStatus::Auto
    );
    assert_bundled_source_line(&vault, &reference, &skill, "active", "installed")?;
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
            .load_attempt_skill_pack(
                crate::attempt_queue::AttemptId::now(),
                &old_id,
                "worker",
                1,
                "fixture/model@1",
                7
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn last_shared_pack_owner_supersedes_old_revision() -> Result<()> {
    let mut files = source(false)?.files().to_vec();
    files.retain(|file| !file.path.starts_with("knowledge/kinds/"));
    let manifest = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    manifest.content = String::from_utf8(manifest.content.clone())
        .expect("fixture UTF-8")
        .lines()
        .filter(|line| !line.starts_with("kinds:"))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    let first = PackSource::from_files(files.clone())?;
    let (_dir, vault, _owner, hub, publisher) = fixture(SkillHubTrustTier::Verified, &first)?;
    let second_files = |files: &[HubFile]| -> Vec<HubFile> {
        files
            .iter()
            .cloned()
            .map(|mut file| {
                if file.path == "PACK.md" {
                    file.content = String::from_utf8(file.content)
                        .expect("fixture UTF-8")
                        .replace("alice.tools", "alice.other")
                        .into_bytes();
                }
                file
            })
            .collect()
    };
    let install = |source: &PackSource, label: &str, at: u64| -> Result<PackInstallReceipt> {
        let reference = HubRef::new(
            hub.hub_id,
            label,
            HubPin::ContentHash(source.content_hash().to_hex()),
        )?;
        let id = fetched_fixture(&vault, source, &reference, &publisher, at)?;
        let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
        let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
            panic!("post-fit install")
        };
        Ok(*receipt)
    };
    let second = PackSource::from_files(second_files(&files))?;
    let a1 = install(&first, "a/v1", 3)?;
    let b1 = install(&second, "b/v1", 4)?;
    assert_eq!(a1.skills, b1.skills); // one shared holder by content hash
    let old_id = EntityId::from_hex(&a1.skills[0])?;
    let manifest = files
        .iter_mut()
        .find(|file| file.path == "PACK.md")
        .unwrap();
    manifest.content = String::from_utf8(manifest.content.clone())
        .expect("fixture UTF-8")
        .replace("version: 1", "version: 2")
        .into_bytes();
    let skill = files
        .iter_mut()
        .find(|file| file.path == "skills/format/SKILL.md")
        .unwrap();
    skill.content =
        b"---\nname: alice.format\ndescription: format\nversion: 2\n---\nKeep new facts exact.\n"
            .to_vec();
    let first_v2 = PackSource::from_files(files.clone())?;
    let second_v2 = PackSource::from_files(second_files(&files))?;
    let a2 = install(&first_v2, "a/v2", 5)?;
    let new_id = EntityId::from_hex(&a2.skills[0])?;
    assert_ne!(old_id, new_id);
    assert_eq!(
        vault.get_skill_record(&old_id)?.unwrap().lifecycle_status,
        crate::skill::SkillLifecycle::Active
    ); // B still owns v1
    let b2 = install(&second_v2, "b/v2", 6)?;
    assert_eq!(a2.skills, b2.skills);
    assert_eq!(
        vault.get_skill_record(&old_id)?.unwrap().lifecycle_status,
        crate::skill::SkillLifecycle::Superseded
    );
    assert_eq!(
        vault
            .edges_out(&new_id)?
            .iter()
            .filter(|edge| edge.kind == crate::edge::EdgeKind::Supersedes && edge.target == old_id)
            .count(),
        1
    );
    let queue = crate::attempt_queue::AttemptQueue::new(&vault);
    let crate::attempt_queue::EnqueueOutcome::Enqueued(attempt) =
        queue.enqueue(crate::attempt_queue::EnqueueAttempt {
            kind: "pack.runtime".into(),
            payload: vec![],
            dedupe_key: None,
            run_id: None,
            now: 7,
        })?
    else {
        panic!("attempt")
    };
    let crate::attempt_queue::ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "pack.runtime",
        crate::attempt_queue::ClaimAttempt {
            lease_owner: "worker".into(),
            now: 8,
        },
    )?
    else {
        panic!("lease")
    };
    assert!(
        vault
            .load_attempt_skill_pack(
                attempt.id,
                &old_id,
                "worker",
                leased.attempt_count,
                "fixture/model@1",
                8
            )
            .is_err()
    );
    assert!(
        vault
            .load_attempt_skill_pack(
                attempt.id,
                &new_id,
                "worker",
                leased.attempt_count,
                "fixture/model@1",
                8
            )
            .is_ok()
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

    let section = serde_json::json!({"section_id":"example.worker.panel", "state_family":{"family":"claim","version":1},
        "verbs":["board.expand"], "authority_lane":"read", "budget_policy":"board.plugin_sections.v1"});
    let mut files = super::tests::agent_files()?;
    files.push(HubFile::new(
        "knowledge/sections/example.worker.panel.json",
        serde_json::to_vec(&section).expect("section JSON"),
    ));
    let source = PackSource::from_files(files)?;
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
    assert_eq!(receipt.sections[0].section_id, "example.worker.panel");
    let registry = crate::context_board::PluginSectionRegistry::rebuild(&vault, &Bindings)
        .expect("registry rebuild");
    let section_id = crate::context_board::SectionId("example.worker.panel".into());
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
fn predicate_collision_names_both_packs_in_either_install_order() -> Result<()> {
    // A parent and nested pack may each declare the same valid global name.
    let parent = PackSource::from_files(
        source(false)?
            .files()
            .iter()
            .cloned()
            .map(|mut file| {
                if file.path == "PACK.md" {
                    file.content = String::from_utf8(file.content)
                        .unwrap()
                        .replace("alice.tools.topic", "alice.tools.sub.topic")
                        .into_bytes();
                }
                file
            })
            .collect(),
    )?;
    let nested = PackSource::from_files(
        source(false)?
            .files()
            .iter()
            .cloned()
            .map(|mut file| {
                if file.path == "PACK.md" || file.path.starts_with("knowledge/") {
                    file.path = file.path.replace("alice.tools", "alice.tools.sub");
                    file.content = String::from_utf8(file.content)
                        .unwrap()
                        .replace("alice.tools", "alice.tools.sub")
                        .into_bytes();
                }
                file
            })
            .collect(),
    )?;
    for (first, second) in [(&parent, &nested), (&nested, &parent)] {
        let (_dir, vault, _owner, hub, publisher) = fixture(SkillHubTrustTier::Verified, first)?;
        let mut asks = Vec::new();
        for source in [first, second] {
            let reference = HubRef::new(
                hub.hub_id,
                "pack",
                HubPin::ContentHash(source.content_hash().to_hex()),
            )?;
            let id = fetched_fixture(&vault, source, &reference, &publisher, 3)?;
            let ask = vault.prepare_pack_install(id, &reference, &publisher, &policy())?;
            asks.push(ask);
        }
        let PackInstallDisposition::Installed(receipt) = vault.install_pack(&asks[0])? else {
            panic!("first pack installs");
        };
        let byte_map = vault.pack_byte_map_snapshot()?;
        let err = vault.install_pack(&asks[1]).unwrap_err();
        assert!(matches!(
            &err,
            crate::error::Error::Registry(
                crate::error::RegistryError::PackPredicateNameCollision {
                    predicate,
                    installed_pack,
                    installing_pack,
                }
            ) if predicate == "alice.tools.sub.topic"
                && installed_pack == &first.manifest().name
                && installing_pack == &second.manifest().name
        ));
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::PackPredicateNameCollision
        );
        let message = err.to_string();
        for name in [
            "alice.tools.sub.topic",
            &first.manifest().name,
            &second.manifest().name,
        ] {
            assert!(message.contains(name), "missing {name} in {message}");
        }
        assert_eq!(
            vault.installed_pack(&first.manifest().name)?,
            Some(*receipt.clone())
        );
        assert!(vault.installed_pack(&second.manifest().name)?.is_none());
        assert_eq!(
            vault.pack_for_predicate("alice.tools.sub.topic")?,
            Some(*receipt)
        );
        assert_eq!(vault.pack_byte_map_snapshot()?, byte_map);
    }
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

struct WrongCodeRecipe;
impl PackFitPolicy for WrongCodeRecipe {
    fn evaluate(&self, _source: &PackSource, _card: &PackPermissions) -> Result<PackFitVerdict> {
        Ok(PackFitVerdict {
            fits: true,
            rules_hit: false,
            code_auto_install: true,
        })
    }
    fn qualify_script(&self, source: &PackSource) -> Result<Option<PackQualification>> {
        let mut qualified = QualifiedScript.qualify(source)?;
        qualified
            .runtime
            .as_mut()
            .expect("fixture runtime")
            .runtime_id = "unrelated-runtime".into();
        Ok(Some(qualified))
    }
}
#[test]
fn script_install_refuses_a_runtime_other_than_the_code_mode_interpreter() -> Result<()> {
    let source = PackSource::from_files(echo_script_files())?;
    let (_dir, vault, _owner, hub, publisher) = fixture(SkillHubTrustTier::Verified, &source)?;
    let id = fetched_fixture(&vault, &source, &hub, &publisher, 3)?;
    assert!(
        vault
            .prepare_pack_install(id, &hub, &publisher, &WrongCodeRecipe)
            .is_err()
    );
    assert!(vault.installed_pack("fixture.echo")?.is_none());
    Ok(())
}

struct QualifiedScript;
impl PackQualifier for QualifiedScript {
    fn qualify(&self, source: &PackSource) -> Result<PackQualification> {
        Ok(PackQualification {
            suite: "fixture".into(),
            report_hash: "12".repeat(32),
            passed: true,
            advisory_accepted: true,
            advisory: "fixture".into(),
            runtime: Some(PackRuntimeRecipe {
                adapter: source.manifest().adapter.clone().unwrap(),
                runtime_id: crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME.into(),
                runtime_hash: "23".repeat(32),
            }),
        })
    }
}
impl PackFitPolicy for QualifiedScript {
    fn evaluate(&self, _source: &PackSource, _card: &PackPermissions) -> Result<PackFitVerdict> {
        Ok(PackFitVerdict {
            fits: true,
            rules_hit: false,
            code_auto_install: true,
        })
    }
    fn qualify_script(&self, source: &PackSource) -> Result<Option<PackQualification>> {
        Ok(Some(self.qualify(source)?))
    }
}
fn echo_script_files() -> Vec<HubFile> {
    vec![
        HubFile::new(
            "PACK.md",
            include_bytes!("../../../tests/fixtures/echo_pack/PACK.md").to_vec(),
        ),
        HubFile::new(
            "scripts/adapter.js",
            include_bytes!("../../../tests/fixtures/echo_pack/scripts/adapter.js").to_vec(),
        ),
        HubFile::new(
            "scripts/input.json",
            include_bytes!("../../../tests/fixtures/echo_pack/scripts/input.json").to_vec(),
        ),
    ]
}
