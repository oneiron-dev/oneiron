//! ARCH-0053 skills-epic forward oracle (authored by the ONE-1735 opener).
//!
//! Every test here is `#[ignore = "armed by ONE-XXXX"]`: it encodes the
//! ACCEPTANCE CONTRACT of a later SK ticket at contract level, compiled
//! against today's public API. Arming rules (wave-2 board, path-opener
//! pattern):
//!
//! - The arming ticket removes its `#[ignore]`, replaces the marked seam
//!   lines (`// ARM(ONE-XXXX): …` + red assert) with real machinery calls,
//!   and may adapt signatures/plumbing to the landed API.
//! - Count-asserts are the contract: they are NEVER weakened, loosened to
//!   `any()`/`is_empty()` negations, or deleted. The path leader screens
//!   every edit to this file.
//! - Wire-shape asserts (map key sets, pinned strings) may be renamed by
//!   the arming ticket ONLY if its ticket text pins different names; the
//!   cardinalities stay.
//!
//! Scope: SK-02 (ONE-1736), SK-03 (ONE-1741), SK-04 (ONE-1737),
//! SK-05 (ONE-1738), SK-06 (ONE-1739). SK-07 (ONE-1740) is docs-only and
//! owned elsewhere; SK-01 (ONE-1735) ships live tests in
//! `src/skill/tests.rs`, not here.
//!
//! FULLY ARMED as of ONE-1739 (SK-06): every contract here now runs against
//! landed machinery, so a red here is a regression, never an un-built layer.

use oneiron::{
    ClaimApprovalStatus, ClaimSource, EntityId, Result, TimeRange, Vault, VaultConfig,
    skill::SkillContentHash, skill::SkillLifecycle, skill::SkillRecord,
    skill::canonical_skill_tree_hash, skill_hub::HubDependencyResolution, skill_hub::HubFile,
    skill_hub::HubPackage, skill_hub::HubPin, skill_hub::HubRef, skill_hub::SkillCapabilitySurface,
};
use rmpv::Value;

// ─── shared fixtures ────────────────────────────────────────────────────

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn provenance() -> Value {
    Value::Map(vec![(Value::from("source"), Value::from("oracle-fixture"))])
}

fn imported_candidate(skill_id: &str, tree_hash: SkillContentHash) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        "Imported oracle fixture skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.9,
        false,
        true,
        Vec::new(),
        provenance(),
    )
    .with_content_hash(tree_hash)
}

// These legacy source fixtures have metadata outside SKILL.md. The Native
// syntax tag does not grant trust or bypass held-out activation.
fn native_package(
    record: SkillRecord,
    files: Vec<HubFile>,
    capabilities: SkillCapabilitySurface,
) -> HubPackage {
    HubPackage {
        format: oneiron::skill_hub::SkillPackageFormat::Native,
        ..HubPackage::new(record, files, capabilities)
    }
}

fn fixture_tree_hash() -> SkillContentHash {
    canonical_skill_tree_hash([("SKILL.md", b"# oracle fixture skill\n".as_slice())])
        .expect("fixture tree hashes")
}

fn alternate_tree_hash() -> SkillContentHash {
    canonical_skill_tree_hash([("SKILL.md", b"# a different tree\n".as_slice())])
        .expect("fixture tree hashes")
}

/// Projection/attribution fixtures use an owner-authored skill. Marketplace
/// admission is exercised by the hub gate tests, not bypassed with an Active flip.
fn put_active_native_skill(vault: &Vault, id: &EntityId, skill_id: &str) -> Result<SkillRecord> {
    let mut candidate = imported_candidate(skill_id, fixture_tree_hash());
    candidate.source = ClaimSource::UserStated;
    vault.put_skill_record(id, &candidate, t(10), 11)?;
    let mut active = candidate;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(id, &active, t(12), 13)?;
    Ok(active)
}

// ═══ SK-02 · ONE-1736 — SKILL_HUB entity + adapters + rug-pull diff ═════

/// Contract (ARCH-0053 §7, ONE-1736): NO TRUST CHAINING. A dependency
/// pointing into another hub inherits NOTHING from the importing hub's
/// trust tier — resolution refuses (fail closed) and materializes no
/// entity.
#[test]
fn sk02_cross_hub_dependency_inherits_nothing_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill_entity = EntityId::now();
    put_active_native_skill(&vault, &skill_entity, "oracle.skill.deps")?;
    // The entity the dependency WOULD materialize as, if trust chained.
    let dep_entity = EntityId::now();

    let importing_ref = HubRef::new(EntityId::now(), "skills/oracle-parent", HubPin::None)?;
    let dependency_ref = HubRef::new(EntityId::now(), "skills/oracle-dependency", HubPin::None)?;
    let dependency_package = native_package(
        imported_candidate("oracle.skill.cross-hub-dependency", alternate_tree_hash()),
        vec![HubFile::new("SKILL.md", b"# a different tree\n".to_vec())],
        SkillCapabilitySurface::default(),
    );
    let resolution_refused = matches!(
        vault.resolve_hub_dependency(
            &importing_ref,
            &dependency_ref,
            &dep_entity,
            Some(&dependency_package),
            t(20),
            21,
        )?,
        HubDependencyResolution::RefusedCrossHub
    );

    assert!(
        resolution_refused,
        "armed by ONE-1736: cross-hub dependency must refuse, not inherit trust"
    );
    assert_eq!(
        vault.get_skill_record(&dep_entity)?,
        None,
        "refusal materializes nothing"
    );
    Ok(())
}
