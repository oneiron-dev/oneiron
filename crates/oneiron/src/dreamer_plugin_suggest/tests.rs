//! Dreamer plugin-suggestion unit tests.

use super::*;
use crate::context_board::{
    AuthorityLaneRef, BudgetPolicyRef, PLUGIN_SECTION_BUDGET_POLICY_REF,
    SECTION_MANIFEST_SCHEMA_VERSION, SectionId, SectionManifest, SectionManifestProvenance,
    SectionVerbRef, StateFamilyRef,
};

const PACK_HASH_HEX: &str = "4444444444444444444444444444444444444444444444444444444444444444";

fn hub_ref() -> HubRef {
    HubRef::new(
        EntityId::from_bytes([0x22; 16]).unwrap(),
        "demo-pack@1.0.0",
        HubPin::ContentHash(PACK_HASH_HEX.to_owned()),
    )
    .unwrap()
}

fn manifest(name: &str) -> SectionManifestEnvelope {
    SectionManifestEnvelope {
        schema_version: SECTION_MANIFEST_SCHEMA_VERSION,
        manifest: SectionManifest {
            section_id: SectionId("demo_rows".to_owned()),
            name: name.to_owned(),
            state_family: StateFamilyRef {
                family: "demo.rows".to_owned(),
                version: 1,
            },
            verbs: vec![SectionVerbRef("board.expand".to_owned())],
            authority_lane: AuthorityLaneRef("plugin.demo".to_owned()),
            budget_policy: BudgetPolicyRef(PLUGIN_SECTION_BUDGET_POLICY_REF.to_owned()),
            provenance: SectionManifestProvenance {
                pack_id: "demo-pack".to_owned(),
                skill_id: "sk_demo".to_owned(),
                skill_version: "1.0.0".to_owned(),
                content_hash_hex: PACK_HASH_HEX.to_owned(),
            },
        },
    }
}

fn candidate(name: &str, version: &str) -> PackCandidate {
    PackCandidate {
        hub_ref: hub_ref(),
        target_skill_ref: EntityId::from_bytes([0x33; 16]).unwrap(),
        pack_id: "demo-pack".to_owned(),
        label: name.to_owned(),
        description: "demo".to_owned(),
        version: version.to_owned(),
        content_hash_hex: PACK_HASH_HEX.to_owned(),
        manifest: manifest(name),
    }
}

fn notice(pattern_key: &str) -> WorkflowPatternNotice {
    WorkflowPatternNotice {
        pattern_key: pattern_key.to_owned(),
        summary: "observed a repeated manual workflow".to_owned(),
        evidence_refs: vec![EntityId::from_bytes([0x44; 16]).unwrap()],
        observed_at: 1_000,
    }
}

/// Length prefixing is what stops two different tuples from hashing the
/// same way by concatenation.
#[test]
fn field_boundaries_cannot_be_shifted_between_fields() {
    let mut left = candidate("Demo", "1.0.0");
    left.pack_id = "ab".to_owned();
    left.version = "c".to_owned();
    let mut right = candidate("Demo", "1.0.0");
    right.pack_id = "a".to_owned();
    right.version = "bc".to_owned();
    assert_ne!(
        plugin_suggestion_key(&notice("demo.rows"), &left).expect("left"),
        plugin_suggestion_key(&notice("demo.rows"), &right).expect("right"),
    );
}

/// The local adapter surfaces only packs that both ship a strictly
/// decodable manifest AND declare the state family the notice names. A
/// manifest-less pack, an undecodable one, and an unrelated one are all
/// SKIPPED — and discovery/fetch write nothing, so nothing is installed
/// before consent.
#[test]
fn local_catalog_skips_invalid_and_unrelated_rows_and_imports_nothing() {
    use crate::claim::ClaimApprovalStatus;
    use crate::skill::{SkillLifecycle, SkillRecord};
    use crate::skill_hub::{
        HubFile, HubIndexEntry, HubPackage, SkillCapabilitySurface, SkillHubKind,
    };

    struct Hub {
        packages: Vec<(HubIndexEntry, HubPackage)>,
    }

    impl SkillHubAdapter for Hub {
        fn hub_id(&self) -> EntityId {
            EntityId::from_bytes([0x22; 16]).unwrap()
        }
        fn kind(&self) -> SkillHubKind {
            SkillHubKind::LocalDir
        }
        fn fetch_package(&self, hub_ref: &HubRef) -> crate::error::Result<HubPackage> {
            self.packages
                .iter()
                .find(|(entry, _)| entry.ref_string == hub_ref.ref_string)
                .map(|(_, package)| package.clone())
                .ok_or(crate::error::Error::EntityNotFound)
        }
        fn discover(&self) -> crate::error::Result<Vec<HubIndexEntry>> {
            Ok(self
                .packages
                .iter()
                .map(|(entry, _)| entry.clone())
                .collect())
        }
    }

    fn package(skill_id: &str, files: Vec<HubFile>) -> HubPackage {
        HubPackage::new(
            SkillRecord::new(
                skill_id,
                "pack",
                "1.0.0",
                ClaimApprovalStatus::Auto,
                SkillLifecycle::Candidate,
                ClaimSource::Imported,
                0.5,
                false,
                true,
                Vec::new(),
                Value::Map(vec![(Value::from("hub"), Value::from("local"))]),
            ),
            files,
            SkillCapabilitySurface::default(),
        )
    }

    // The pack ships its RECIPE. Whatever identity it claims is
    // overwritten by the engine, so the shipped provenance is a
    // placeholder on purpose — a pack cannot vouch for itself.
    let mut shipped = manifest("Good");
    shipped.manifest.provenance.skill_id = "sk_lies".to_owned();
    shipped.manifest.provenance.skill_version = "9.9.9".to_owned();
    let good = package(
        "sk_good",
        vec![HubFile::new(
            PACK_SECTION_MANIFEST_PATH,
            encode_section_manifest(&shipped).unwrap(),
        )],
    );
    let good_hash = good.content_hash().unwrap();

    let bare = package(
        "sk_bare",
        vec![HubFile::new("SKILL.md", b"# no manifest".to_vec())],
    );
    let bare_hash = bare.content_hash().unwrap();
    let broken = package(
        "sk_broken",
        vec![HubFile::new(
            PACK_SECTION_MANIFEST_PATH,
            b"not messagepack".to_vec(),
        )],
    );
    let broken_hash = broken.content_hash().unwrap();

    let entry = |name: &str, hash, package: HubPackage| {
        (
            HubIndexEntry {
                name: name.to_owned(),
                description: "pack".to_owned(),
                version: "1.0.0".to_owned(),
                content_hash: hash,
                ref_string: format!("{name}@1.0.0"),
            },
            package,
        )
    };
    let hub = Hub {
        packages: vec![
            entry("good", good_hash, good),
            entry("bare", bare_hash, bare),
            entry("broken", broken_hash, broken),
        ],
    };

    let catalog = LocalSkillHubPackCatalog { adapter: &hub };
    // The manifest declares `demo.rows`; only a notice naming that
    // pattern matches, and only the well-formed pack survives.
    let matched = catalog
        .candidates(&notice("demo.rows"))
        .expect("catalog reads");
    assert_eq!(
        matched.len(),
        1,
        "manifest-less and broken rows are skipped"
    );
    // The ENGINE's identity won, not the pack's claim.
    assert_eq!(matched[0].content_hash_hex, good_hash.to_hex());
    assert_eq!(
        matched[0].manifest.manifest.provenance.content_hash_hex,
        good_hash.to_hex()
    );
    assert_eq!(matched[0].manifest.manifest.provenance.skill_id, "sk_good");
    assert_eq!(
        matched[0].manifest.manifest.provenance.skill_version,
        "1.0.0"
    );

    assert!(
        catalog
            .candidates(&notice("unrelated.pattern"))
            .expect("catalog reads")
            .is_empty(),
        "a pack for another state family is not a candidate"
    );
}
