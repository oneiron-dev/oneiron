use super::*;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_hub::{HubFile, HubPin, SkillCapabilitySurface};
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::{ClaimApprovalStatus, ClaimSource};
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
fn install_refuses_credential_coordinates_before_advisory_egress_and_sends_only_dependencies()
-> Result<()> {
    use std::cell::RefCell;
    struct RecordingQuery {
        calls: RefCell<Vec<Vec<DependencyCoordinate>>>,
    }
    impl OsvQuery for RecordingQuery {
        fn query(&self, coordinates: &[DependencyCoordinate]) -> Result<Vec<Vec<String>>> {
            assert_eq!(
                coordinates,
                &[DependencyCoordinate {
                    ecosystem: "npm".to_owned(),
                    name: "lodash".to_owned(),
                    version: "4.17.21".to_owned(),
                }]
            );
            self.calls.borrow_mut().push(coordinates.to_vec());
            Ok(vec![Vec::new()])
        }
    }
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut package = package("4.17.21");
    package.files.push(HubFile::new(
        "SKILL.md",
        b"# advisory-egress-private-skill-text

Keep this instruction local.
"
        .to_vec(),
    ));
    let inventory = dependency_inventory(&package)?;
    assert_eq!(
        inventory,
        vec![DependencyCoordinate {
            ecosystem: "npm".to_owned(),
            name: "lodash".to_owned(),
            version: "4.17.21".to_owned(),
        }]
    );
    let reference = HubRef::new(EntityId::now(), "skills/osv-fixture", HubPin::None)?;
    let query = RecordingQuery {
        calls: RefCell::new(Vec::new()),
    };
    let before = vault.entities_by_type(crate::registry::ENTITY_TYPE_SKILL)?;
    let hash = package.content_hash()?;
    assert!(vault.skill_scan_verdicts_for_content_hash(hash)?.is_empty());
    for coordinate in [
        DependencyCoordinate {
            ecosystem: "npm".into(),
            name: "https://fixture-user:fixture-secret@example.test/lodash".into(),
            version: "4.17.21".into(),
        },
        DependencyCoordinate {
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version: "https://fixture-user:fixture-secret@example.test/archive".into(),
        },
    ] {
        let error = vault
            .install_skill_with_advisories(
                &reference,
                &package,
                &[coordinate],
                &query,
                TimeRange { start: 10, end: 10 },
                10,
            )
            .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::InvalidConfig);
        assert!(query.calls.borrow().is_empty());
        assert_eq!(
            vault.entities_by_type(crate::registry::ENTITY_TYPE_SKILL)?,
            before
        );
        assert!(vault.skill_scan_verdicts_for_content_hash(hash)?.is_empty());
    }
    let installed = vault.install_skill_with_advisories(
        &reference,
        &package,
        &inventory,
        &query,
        TimeRange { start: 10, end: 10 },
        10,
    )?;
    assert_eq!(installed.status, DependencyScanStatus::Complete);
    assert!(vault.get_skill_record(&installed.entity)?.is_some());
    assert_eq!(*query.calls.borrow(), vec![inventory]);
    Ok(())
}
