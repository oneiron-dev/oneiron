use rmpv::Value;

use super::*;
use crate::VaultConfig;
use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::skill::{SkillLifecycle, canonical_skill_tree_hash};
use crate::skill_hub::{HubFile, HubPin, HubRef, SkillCapabilitySurface};
use crate::temporal::TimeRange;

/// A synthetic GitHub-token-shaped fixture. Not a credential: the detector
/// keys on shape, and this string is 36 hex-ish characters of nothing.
const SECRET_FIXTURE: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let temp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(temp.path(), VaultConfig::default()).expect("open vault");
    (temp, vault)
}

fn record(skill_id: &str) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        "scan fixture description",
        "1.0.0",
        ClaimApprovalStatus::Auto,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    )
}

fn package_of(skill_id: &str, content: &[u8], capabilities: SkillCapabilitySurface) -> HubPackage {
    let mut record = record(skill_id);
    record.content_hash =
        Some(canonical_skill_tree_hash([("SKILL.md", content)]).expect("fixture hash"));
    HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", content.to_vec())],
        capabilities,
    )
}

fn hub_ref() -> HubRef {
    HubRef::new(EntityId::now(), "skills/scan-fixture", HubPin::None).expect("hub ref")
}

fn row_text<'a>(body: &'a crate::claim::ClaimBody, key: &str) -> Option<&'a str> {
    let Value::Map(entries) = &body.value else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
}

// ═══ the static pass ════════════════════════════════════════════════════════

#[test]
fn clean_tree_scans_unknown_at_no_risk() -> Result<()> {
    let package = package_of(
        "fixture.clean",
        b"# clean skill\nnothing to see\n",
        SkillCapabilitySurface::default(),
    );
    let receipt = run_static_skill_scan(&package, 7)?;

    assert_eq!(receipt.provider, SCAN_PROVIDER_STATIC_V1);
    assert_eq!(receipt.scanned_at, 7);
    assert_eq!(receipt.risk_level, ScanRiskLevel::None);
    assert_eq!(receipt.completeness, ScanCompleteness::Complete);
    assert_eq!(receipt.governance, SkillGovernance::Recommended);
    // A pattern scan finds known-bad shapes; it never establishes cleanliness,
    // and `clean` is read downstream as a real clearance.
    assert_eq!(receipt.verdict, ScanVerdict::Unknown);
    Ok(())
}

#[test]
fn embedded_credential_in_tree_scans_high_and_suspicious() -> Result<()> {
    let body = format!("# skill\nexport TOKEN={SECRET_FIXTURE}\n");
    let package = package_of(
        "fixture.secret-file",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    let receipt = run_static_skill_scan(&package, 7)?;

    assert_eq!(receipt.risk_level, ScanRiskLevel::High);
    assert_eq!(receipt.verdict, ScanVerdict::Suspicious);
    assert_eq!(receipt.governance, SkillGovernance::Discouraged);
    Ok(())
}

#[test]
fn embedded_credential_in_record_text_scans_high() -> Result<()> {
    let mut package = package_of(
        "fixture.secret-desc",
        b"# clean tree\n",
        SkillCapabilitySurface::default(),
    );
    // The tree is clean; the credential rides the RECORD, which is why the
    // encoded record is scanned alongside the files.
    package.record.desc = format!("use {SECRET_FIXTURE} to authenticate");
    let receipt = run_static_skill_scan(&package, 7)?;

    assert_eq!(receipt.risk_level, ScanRiskLevel::High);
    assert_eq!(receipt.verdict, ScanVerdict::Suspicious);
    Ok(())
}

#[test]
fn capability_breadth_grades_below_the_default_dial() -> Result<()> {
    let ordinary = run_static_skill_scan(
        &package_of(
            "fixture.bins",
            b"# tool skill\n",
            SkillCapabilitySurface::default().with_bin("rg"),
        ),
        7,
    )?;
    assert_eq!(ordinary.risk_level, ScanRiskLevel::Low);

    // An env requirement asks for the host process's environment, which is
    // where credentials live — graded above ordinary surface, still under the
    // default dial, so it records signal without asking for a tap.
    let env = run_static_skill_scan(
        &package_of(
            "fixture.env",
            b"# env skill\n",
            SkillCapabilitySurface::default()
                .with_bin("rg")
                .with_env("API_TOKEN"),
        ),
        7,
    )?;
    assert_eq!(env.risk_level, ScanRiskLevel::Medium);
    assert!(env.risk_level < DEFAULT_ACTIVATION_RISK_THRESHOLD);
    Ok(())
}

#[test]
fn empty_tree_scans_partial() -> Result<()> {
    let package = HubPackage::new(
        record("fixture.empty"),
        Vec::new(),
        SkillCapabilitySurface::default(),
    );
    let receipt = run_static_skill_scan(&package, 7)?;

    assert_eq!(receipt.completeness, ScanCompleteness::Partial);
    assert_eq!(receipt.verdict, ScanVerdict::Unknown);
    Ok(())
}

#[test]
fn oversized_file_is_scanned_to_budget_and_reported_partial() -> Result<()> {
    let mut content = vec![b'a'; MAX_SCAN_BYTES_PER_FILE + 64];
    content[..SECRET_FIXTURE.len()].copy_from_slice(SECRET_FIXTURE.as_bytes());
    let package = package_of(
        "fixture.oversize",
        &content,
        SkillCapabilitySurface::default(),
    );
    let receipt = run_static_skill_scan(&package, 7)?;

    // Coverage is truncated, and says so — but the head of the file was really
    // read, so a credential at the top is still caught.
    assert_eq!(receipt.completeness, ScanCompleteness::Partial);
    assert_eq!(receipt.risk_level, ScanRiskLevel::High);
    Ok(())
}

// ═══ the activation consult ═════════════════════════════════════════════════

#[test]
fn secret_bearing_import_gates_proposed_and_clean_import_stays_auto() -> Result<()> {
    let (_temp, vault) = open_vault();

    let clean = package_of(
        "fixture.gate-clean",
        b"# clean skill\n",
        SkillCapabilitySurface::default(),
    );
    let clean_hash = clean.content_hash()?;
    vault.import_skill_from_hub(&hub_ref(), &clean, t(1), 2)?;
    assert_eq!(
        scan_gate_for_activation(&vault, clean_hash)?,
        ActivationPosture::AutoEligible
    );

    let body = format!("# skill\nexport TOKEN={SECRET_FIXTURE}\n");
    let risky = package_of(
        "fixture.gate-risky",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    let risky_hash = risky.content_hash()?;
    vault.import_skill_from_hub(&hub_ref(), &risky, t(3), 4)?;
    assert_eq!(
        scan_gate_for_activation(&vault, risky_hash)?,
        ActivationPosture::ProposedRequired {
            risk: ScanRiskLevel::High
        },
        "a credential-bearing import asks for an owner tap at activation"
    );
    Ok(())
}

#[test]
fn activation_escalates_auto_to_proposed_without_refusing() -> Result<()> {
    let (_temp, vault) = open_vault();
    let body = format!("# skill\nexport TOKEN={SECRET_FIXTURE}\n");
    let package = package_of(
        "fixture.activate-risky",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    let entity = vault.import_skill_from_hub(&hub_ref(), &package, t(1), 2)?;

    let mut active = vault.get_skill_record(&entity)?.expect("imported skill");
    active.lifecycle_status = SkillLifecycle::Active;
    active.approval_status = ClaimApprovalStatus::Auto;
    vault.update_skill_record(&entity, &active, t(3), 4)?;

    let stored = vault.get_skill_record(&entity)?.expect("activated skill");
    assert_eq!(
        stored.lifecycle_status,
        SkillLifecycle::Active,
        "the dial escalates consent; it never blocks the activation"
    );
    assert_eq!(stored.approval_status, ClaimApprovalStatus::Proposed);
    Ok(())
}

#[test]
fn activation_leaves_clean_skills_and_owner_approvals_alone() -> Result<()> {
    let (_temp, vault) = open_vault();

    let clean = package_of(
        "fixture.activate-clean",
        b"# clean skill\n",
        SkillCapabilitySurface::default(),
    );
    let clean_entity = vault.import_skill_from_hub(&hub_ref(), &clean, t(1), 2)?;
    let mut active = vault
        .get_skill_record(&clean_entity)?
        .expect("imported skill");
    active.lifecycle_status = SkillLifecycle::Active;
    active.approval_status = ClaimApprovalStatus::Auto;
    vault.update_skill_record(&clean_entity, &active, t(3), 4)?;
    assert_eq!(
        vault
            .get_skill_record(&clean_entity)?
            .expect("activated skill")
            .approval_status,
        ClaimApprovalStatus::Auto
    );

    // An owner tap already answered the question this dial asks, so the
    // escalation never rewrites it.
    let body = format!("# skill\nexport TOKEN={SECRET_FIXTURE}\n");
    let risky = package_of(
        "fixture.activate-approved",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    let risky_entity = vault.import_skill_from_hub(&hub_ref(), &risky, t(5), 6)?;
    let mut approved = vault
        .get_skill_record(&risky_entity)?
        .expect("imported skill");
    approved.lifecycle_status = SkillLifecycle::Active;
    approved.approval_status = ClaimApprovalStatus::Approved;
    vault.update_skill_record(&risky_entity, &approved, t(7), 8)?;
    assert_eq!(
        vault
            .get_skill_record(&risky_entity)?
            .expect("activated skill")
            .approval_status,
        ClaimApprovalStatus::Approved
    );
    Ok(())
}

#[test]
fn the_risk_dial_moves_the_gate() -> Result<()> {
    let (_temp, vault) = open_vault();
    let package = package_of(
        "fixture.dial",
        b"# env skill\n",
        SkillCapabilitySurface::default().with_env("API_TOKEN"),
    );
    let content_hash = package.content_hash()?;
    vault.import_skill_from_hub(&hub_ref(), &package, t(1), 2)?;

    assert_eq!(
        skill_scan_activation_risk_threshold(&vault)?,
        DEFAULT_ACTIVATION_RISK_THRESHOLD
    );
    assert_eq!(
        scan_gate_for_activation(&vault, content_hash)?,
        ActivationPosture::AutoEligible
    );

    set_skill_scan_activation_risk_threshold(&vault, ScanRiskLevel::Medium)?;
    assert_eq!(
        skill_scan_activation_risk_threshold(&vault)?,
        ScanRiskLevel::Medium
    );
    assert_eq!(
        scan_gate_for_activation(&vault, content_hash)?,
        ActivationPosture::ProposedRequired {
            risk: ScanRiskLevel::Medium
        }
    );
    Ok(())
}

// ═══ the producer ═══════════════════════════════════════════════════════════

#[test]
fn import_produces_a_verdict_row_with_no_manual_ingest() -> Result<()> {
    let (_temp, vault) = open_vault();
    let package = package_of(
        "fixture.producer",
        b"# produced skill\n",
        SkillCapabilitySurface::default(),
    );
    let content_hash = package.content_hash()?;
    vault.import_skill_from_hub(&hub_ref(), &package, t(1), 2)?;

    let rows = vault.skill_scan_verdicts_for_content_hash(content_hash)?;
    assert_eq!(rows.len(), 1, "the import door ingests its own scan");
    assert_eq!(
        row_text(&rows[0], "provider"),
        Some(SCAN_PROVIDER_STATIC_V1)
    );
    Ok(())
}

#[test]
fn re_importing_known_bytes_adds_no_second_static_row() -> Result<()> {
    let (_temp, vault) = open_vault();
    let package = package_of(
        "fixture.producer-idempotent",
        b"# produced skill\n",
        SkillCapabilitySurface::default(),
    );
    let content_hash = package.content_hash()?;
    vault.import_skill_from_hub(&hub_ref(), &package, t(1), 2)?;
    // A second hub alias over the SAME canonical bytes: the static pass is a
    // pure function of those bytes, so re-running it would mint a duplicate
    // that differs only in its timestamp.
    vault.import_skill_from_hub(&hub_ref(), &package, t(3), 4)?;

    assert_eq!(
        vault
            .skill_scan_verdicts_for_content_hash(content_hash)?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn content_hash_change_on_sync_re_scans() -> Result<()> {
    let (_temp, vault) = open_vault();
    let reference = hub_ref();
    let first = package_of(
        "fixture.producer-sync",
        b"# first revision\n",
        SkillCapabilitySurface::default(),
    );
    let entity = vault.import_skill_from_hub(&reference, &first, t(1), 2)?;

    let body = format!("# second revision\nexport TOKEN={SECRET_FIXTURE}\n");
    let mut second = package_of(
        "fixture.producer-sync",
        body.as_bytes(),
        SkillCapabilitySurface::default(),
    );
    second.record.version = "1.1.0".to_owned();
    let second_hash = second.content_hash()?;
    vault.sync_skill_from_hub(
        &entity,
        &reference,
        &second,
        crate::skill_hub::HubSyncPolicy::MirrorOfHub,
        t(3),
        4,
    )?;

    let rows = vault.skill_scan_verdicts_for_content_hash(second_hash)?;
    assert_eq!(rows.len(), 1, "new bytes get their own scan");
    assert_eq!(row_text(&rows[0], "riskLevel"), Some("high"));
    Ok(())
}
