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
