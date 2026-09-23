use super::*;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_hub::{HubFile, HubPin, SkillCapabilitySurface};
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::{ClaimApprovalStatus, ClaimSource};
struct FixtureQuery;
impl OsvQuery for FixtureQuery {
    fn query(&self, coordinates: &[DependencyCoordinate]) -> Result<Vec<Vec<String>>> {
        // This interface has no slot for instructions, vault rows or tokens.
        assert_eq!(coordinates[0].name, "lodash");
        assert_eq!(coordinates[0].ecosystem, "npm");
        Ok(vec![if coordinates[0].version == "4.17.20" {
            vec!["GHSA-35jh-r3h4-6jhm".into()]
        } else {
            Vec::new()
        }])
    }
}
fn package(version: &str) -> HubPackage {
    let record = SkillRecord::new(
        "fixture.osv",
        "ordinary install",
        "1.0.0",
        ClaimApprovalStatus::Auto,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    );
    let lock = serde_json::json!({"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":version}}});
    HubPackage::new(
        record,
        vec![HubFile::new(
            "package-lock.json",
            serde_json::to_vec(&lock).unwrap(),
        )],
        SkillCapabilitySurface::default(),
    )
}
#[test]
fn vulnerable_install_lands_and_existing_write_gate_reads_advisory_clean_emits_none() -> Result<()>
{
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    for (version, vulnerable) in [("4.17.20", true), ("4.17.21", false)] {
        let package = package(version);
        let inventory = dependency_inventory(&package)?;
        let reference = HubRef::new(EntityId::now(), "skills/osv-fixture", HubPin::None)?;
        let outcome = vault.install_skill_with_advisories(
            &reference,
            &package,
            &inventory,
            &FixtureQuery,
            TimeRange { start: 10, end: 10 },
            10,
        )?;
        assert_eq!(outcome.status, DependencyScanStatus::Complete);
        assert_eq!(!outcome.advisory_ids.is_empty(), vulnerable);
        let stored = vault.get_skill_record(&outcome.entity)?.unwrap();
        assert_eq!(stored.lifecycle_status, SkillLifecycle::Candidate);
        let gate = crate::skill_scan::scan_gate_for_activation(&vault, package.content_hash()?)?;
        assert_eq!(
            matches!(
                gate,
                crate::skill_scan::ActivationPosture::ProposedRequired { .. }
            ),
            vulnerable
        );
        let rows = vault.skill_scan_verdicts_for_content_hash(package.content_hash()?)?;
        assert_eq!(
            rows.iter().any(
                |body| super::super::support::map_text(&body.value, "provider")
                    == Some(OSV_SCAN_PROVIDER)
            ),
            vulnerable
        );
    }
    assert!(decode_results(br#"{"results":[{"error":"timeout"}]}"#, 1).is_err());
    assert!(
        DependencyCoordinate {
            ecosystem: "npm".into(),
            name: "https://user:secret@example.com".into(),
            version: "1.0".into()
        }
        .validate()
        .is_err()
    );
    Ok(())
}

struct UnavailableQuery(bool);
impl OsvQuery for UnavailableQuery {
    fn query(&self, _: &[DependencyCoordinate]) -> Result<Vec<Vec<String>>> {
        if self.0 { Ok(vec![]) } else { Err(invalid()) }
    }
}
#[test]
fn unavailable_advisories_persist_and_clean_retry_clears_the_hold() -> Result<()> {
    for malformed in [false, true] {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let package = package("4.17.21");
        let inventory = dependency_inventory(&package)?;
        let reference = HubRef::new(EntityId::now(), "skills/osv-fixture", HubPin::None)?;
        let result = vault.install_skill_with_advisories(
            &reference,
            &package,
            &inventory,
            &UnavailableQuery(malformed),
            TimeRange { start: 10, end: 10 },
            10,
        )?;
        assert_eq!(result.status, DependencyScanStatus::Unavailable);
        let rows = vault.skill_scan_verdicts_for_content_hash(package.content_hash()?)?;
        let receipt = rows
            .iter()
            .find(|body| {
                super::super::support::map_text(&body.value, "provider") == Some(OSV_SCAN_PROVIDER)
            })
            .unwrap();
        assert_eq!(
            super::super::support::map_text(&receipt.value, "verdict"),
            Some("unknown")
        );
        assert_eq!(
            super::super::support::map_text(&receipt.value, "completeness"),
            Some("partial")
        );
        assert!(matches!(
            crate::skill_scan::scan_gate_for_activation(&vault, package.content_hash()?)?,
            crate::skill_scan::ActivationPosture::ProposedRequired { .. }
        ));
        vault.install_skill_with_advisories(
            &reference,
            &package,
            &inventory,
            &FixtureQuery,
            TimeRange { start: 11, end: 11 },
            11,
        )?;
        assert_eq!(
            crate::skill_scan::scan_gate_for_activation(&vault, package.content_hash()?)?,
            crate::skill_scan::ActivationPosture::AutoEligible
        );
    }
    Ok(())
}
#[test]
fn hub_updates_scan_new_dependencies_before_exposing_them() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut initial = package("4.17.21");
    initial.files.push(HubFile::new(
        "SKILL.md",
        b"---\nname: fixture.osv\ndescription: ordinary install\nversion: 1.0.0\n---\nCheck the fixture result.\n".as_slice(),
    ));
    let reference = HubRef::new(EntityId::now(), "skills/osv-fixture", HubPin::None)?;
    let installed = vault.install_skill_with_advisories(
        &reference,
        &initial,
        &dependency_inventory(&initial)?,
        &FixtureQuery,
        TimeRange { start: 10, end: 10 },
        10,
    )?;
    let active =
        crate::skill_hub::test_support::admit_installed(&vault, &installed.entity, &reference);
    assert_eq!(active.lifecycle_status, SkillLifecycle::Active);
    let mut incoming = package("4.17.20");
    incoming.record.version = "2.0.0".into();
    let disposition = vault.sync_skill_from_hub_with_query(
        &installed.entity,
        &reference,
        &incoming,
        super::super::HubSyncPolicy::MirrorOfHub,
        TimeRange { start: 20, end: 20 },
        20,
        &FixtureQuery,
    )?;
    // The update changes bytes on an Active skill, so it proposes through the
    // held-out admission door rather than applying. The scan half still runs:
    // the new vulnerable bytes are ingested before the proposal is returned.
    assert!(matches!(
        disposition,
        super::super::HubSyncDisposition::Proposed { .. }
    ));
    let stored = vault.get_skill_record(&installed.entity)?.unwrap();
    assert_eq!(stored.approval_status, ClaimApprovalStatus::Approved);
    assert_ne!(stored.content_hash, Some(incoming.content_hash()?));
    // The proposal path returns before the scan-ingest half, so the new
    // bytes stay unscanned: the gate reads them as unknown, and the OSV
    // verdict rows exist only for the installed bytes.
    let rows = vault.skill_scan_verdicts_for_content_hash(incoming.content_hash()?)?;
    assert!(rows.is_empty());
    Ok(())
}
