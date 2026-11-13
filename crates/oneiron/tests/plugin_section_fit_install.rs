//! FIX-LIST [FIT-INSTALL-AUTO-CLAIM-PENDS-AT-GATE]: under ARCH-0053
//! ("Everything installs; permissions ask"), a code-free section whose
//! requests its caller already holds installs at once. The production door
//! `vault.packs.sections.propose` (`Memory::plugin_section_propose_holding`)
//! decides that by the deterministic fit, and a ready fit lands the install
//! claim through `Offer::land_in_txn` (context_board/plugin/fit_install.rs).
//!
//! Two refusals stood between a ready fit and the install:
//! - The install claim and its fit receipt are about the SKILL, so
//!   `ClaimBody::new` gives them the SKILL's substrate facet, which no row
//!   holds: the birth gate refuses them InvalidFacet (#4389). #7205 (FIX
//!   [CLAIM-FACET-BIRTH-GATE-CENSUS]) stamps both with a stored facet.
//! - Past the facet, the claim (Auto, source Generated, raw door, no actor)
//!   pends at the gate under the shipped policy: no `generated` source-trust
//!   row binds its writer, and `plugin.*` takes the criticality floor.
//!
//! Either way the writer rolls back and the door answers the owner's
//! permission ask instead, so a ready fit never installs. The second test
//! stores the SKILL's facet first, as #7205 would give the claim a stored
//! facet, so its red shows the gate refusal alone. Engine RULING
//! FIT-INSTALL-DESIGN = A: the install claim lands under the engine's own
//! fit install writer, a host-provisioned MACHINE that the shipped manifest
//! binds one actor ceiling row and one `generated` source-trust row to.
//!
//! Fixture: a device vault rooted by its host, which provisions the engine's
//! MACHINE writers (as a serving host does on every open; the shipped
//! manifest is seeded on create), its owner as the caller, a hub skill
//! imported Active through a ready rule fit, and a code-free section on it
//! whose verb and lane the caller holds. The controls: a fit short of ready
//! still asks the owner, and the owner's revoke undoes a fitted install.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test plugin_section_fit_install`
#![cfg(feature = "test-support")]
// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_board::{
    AuthorityLaneRef, BudgetPolicyRef, EngineSectionBindings, PLUGIN_SECTION_BUDGET_POLICY_REF,
    PluginSectionRegistry, SECTION_MANIFEST_SCHEMA_VERSION, SectionId, SectionManifest,
    SectionManifestEnvelope, SectionManifestProvenance, SectionVerbRef, StateFamilyRef,
};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{
    PluginSectionInstallOutcome, PluginSectionProposeRequest, PluginSectionRevokeRequest,
    PluginSectionTargetInput,
};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    CallerPermissions, HubFile, HubPackage, HubPin, HubRef, HubSyncPolicy, RuleSkillFit,
    SkillCapabilitySurface, SkillHubAdapter, SkillHubKind, SkillHubRecord, SkillHubTrustTier,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const HUB_ENDPOINT: &str = "https://example.invalid/index.json";
const SKILL_ID: &str = "sk_open_tasks";
const SKILL_VERSION: &str = "1.0.0";
const SECTION_ID: &str = "open_task_digest";

/// A host that judges the caller's credential to hold every permission.
struct HoldsAll;
impl CallerPermissions for HoldsAll {
    fn holds(&self, _permission: &str) -> bool {
        true
    }
}

/// A host that judges the caller to hold the section's lane but not its
/// verb.
struct HoldsLaneOnly;
impl CallerPermissions for HoldsLaneOnly {
    fn holds(&self, permission: &str) -> bool {
        permission == "lane:read"
    }
}

/// The configured hub's transport, answering its one pinned package.
struct PinnedHub {
    hub: EntityId,
    package: HubPackage,
}
impl SkillHubAdapter for PinnedHub {
    fn hub_id(&self) -> EntityId {
        self.hub
    }
    fn kind(&self) -> SkillHubKind {
        SkillHubKind::HttpIndex
    }
    fn endpoint(&self) -> Option<&str> {
        Some(HUB_ENDPOINT)
    }
    fn fetch_package(&self, _: &HubRef) -> oneiron::error::Result<HubPackage> {
        Ok(self.package.clone())
    }
}

fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

/// A code-free package: one SKILL.md, no `scripts/`, no capability.
fn package() -> HubPackage {
    let record = SkillRecord::new(
        SKILL_ID,
        "open task digest",
        SKILL_VERSION,
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("hub-folder"),
        )]),
    );
    HubPackage::new(
        record,
        vec![HubFile::new(
            "SKILL.md",
            format!(
                "---\nname: {SKILL_ID}\ndescription: open task digest\nversion: {SKILL_VERSION}\n---\n# Open tasks\n"
            )
            .into_bytes(),
        )],
        SkillCapabilitySurface::default(),
    )
}

/// A section on the skill with production bindings: family `claim` v1,
/// lane `read`, one exported section verb.
fn manifest(content_hash_hex: String) -> SectionManifestEnvelope {
    SectionManifestEnvelope {
        schema_version: SECTION_MANIFEST_SCHEMA_VERSION,
        manifest: SectionManifest {
            section_id: SectionId(SECTION_ID.to_owned()),
            name: "Open task digest".to_owned(),
            state_family: StateFamilyRef {
                family: "claim".to_owned(),
                version: 1,
            },
            verbs: vec![SectionVerbRef("self.focus.refresh".to_owned())],
            authority_lane: AuthorityLaneRef("read".to_owned()),
            budget_policy: BudgetPolicyRef(PLUGIN_SECTION_BUDGET_POLICY_REF.to_owned()),
            provenance: SectionManifestProvenance {
                pack_id: "open-tasks-pack".to_owned(),
                skill_id: SKILL_ID.to_owned(),
                skill_version: SKILL_VERSION.to_owned(),
                content_hash_hex,
            },
        },
    }
}

/// The owner's offer of a code-free section on a skill imported Active.
/// `vault` is declared before `_dir`, so the vault closes before its
/// directory is removed.
struct Offered {
    vault: Vault,
    owner_id: EntityId,
    owner: AuthenticatedOwner,
    skill: EntityId,
    request: PluginSectionProposeRequest,
    _dir: tempfile::TempDir,
}

fn offered() -> Offered {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open(dir.path(), config).expect("open the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // The host roots the vault and provisions the engine's MACHINE writers,
    // as a serving host does each time it opens the vault.
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner = vault
        .authenticate_owner(
            owner_id,
            &owner_id.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("authenticated owner");

    // The skill: imported Active from a configured hub through a ready fit.
    let package = package();
    let content_hash_hex = package.content_hash().expect("canonical hash").to_hex();
    let hub = EntityId::now();
    let configuration = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        HUB_ENDPOINT,
        SkillHubTrustTier::Community,
        HubSyncPolicy::ContentHashFrozen,
    )
    .expect("hub configuration");
    vault
        .configure_skill_hub(&owner, &hub, &configuration, at(4), 4)
        .expect("configure the hub");
    let publisher = vault
        .admit_skill_publisher(&owner, "publisher:fit-install", hub)
        .expect("admit the publisher");
    let source = HubRef::new(
        hub,
        "open-tasks-pack@1.0.0",
        HubPin::ContentHash(content_hash_hex.clone()),
    )
    .expect("hub ref");
    let skill = vault
        .import_marketplace_skill_from_adapter(
            &PinnedHub { hub, package },
            &source,
            &publisher,
            &RuleSkillFit::new(&HoldsAll),
            at(5),
            5,
        )
        .expect("import the skill");
    let record = vault
        .get_skill_record(&skill)
        .expect("read the skill")
        .expect("the imported skill");
    assert_eq!(
        record.lifecycle_status,
        SkillLifecycle::Active,
        "a ready fit imports the skill Active"
    );

    // The owner offers a code-free section whose verb and lane they hold.
    let request = PluginSectionProposeRequest {
        manifest: manifest(content_hash_hex),
        target: PluginSectionTargetInput::ExistingSkill { skill_ref: skill },
        turn_ref: "turn:fit-install-1".to_owned(),
    };
    Offered {
        vault,
        owner_id,
        owner,
        skill,
        request,
        _dir: dir,
    }
}

/// Whether the rebuilt section registry admits the offered section.
fn admitted(offered: &Offered) -> bool {
    PluginSectionRegistry::rebuild(&offered.vault, &EngineSectionBindings)
        .expect("rebuild the section registry")
        .get(&SectionId(SECTION_ID.to_owned()))
        .is_some()
}

/// Runs the production door as the owner and expects the install at once:
/// a live Auto install claim the rebuilt registry admits. Answers the
/// install claim.
fn assert_installs(offered: &Offered) -> EntityId {
    let outcome = offered
        .vault
        .memory(offered.owner_id, EdgeActorClass::Human)
        .plugin_section_propose_holding(&offered.request, &HoldsAll)
        .expect("the propose door answers");
    let PluginSectionInstallOutcome::Installed {
        claim_ref,
        permissions,
        ..
    } = &outcome
    else {
        panic!("a ready fit installs the section at once (ARCH-0053): {outcome:?}");
    };
    assert_eq!(
        permissions,
        &vec!["lane:read".to_owned(), "verb:self.focus.refresh".to_owned()],
        "the install names every permission the fit evaluated: {outcome:?}"
    );
    let claim = EntityId::from_hex(claim_ref).expect("the install claim ref");
    let body = offered
        .vault
        .get_claim(&claim)
        .expect("read the install claim")
        .expect("the install claim is stored");
    assert_eq!(
        (body.approval, body.lifecycle, body.source),
        (
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            Some(ClaimSource::Generated)
        ),
        "the install claim lands live, Auto and Generated"
    );
    assert!(
        admitted(offered),
        "the rebuilt registry admits the installed section"
    );
    claim
}

#[test]
fn ready_fit_installs_a_code_free_section_under_the_shipped_gate() {
    assert_installs(&offered());
}

/// The control: a caller who does not hold the section's verb gets the
/// owner's permission ask, naming it, and nothing installs.
#[test]
fn fit_short_of_ready_still_asks_the_owner() {
    let offered = offered();
    let outcome = offered
        .vault
        .memory(offered.owner_id, EdgeActorClass::Human)
        .plugin_section_propose_holding(&offered.request, &HoldsLaneOnly)
        .expect("the propose door answers");
    let PluginSectionInstallOutcome::PermissionAsk {
        analysis,
        pending_ref,
        ..
    } = &outcome
    else {
        panic!("a fit short of ready asks the owner: {outcome:?}");
    };
    assert!(
        analysis.contains("verb:self.focus.refresh"),
        "the ask names the verb the caller does not hold: {outcome:?}"
    );
    assert!(
        pending_ref.starts_with("gate:"),
        "the ask waits on the owner's gate consent: {outcome:?}"
    );
    assert!(
        !admitted(&offered),
        "an asked section is not admitted before the owner answers"
    );
}

/// The owner's revoke retracts a fitted install, and the rebuilt registry
/// drops its section.
#[test]
fn owner_revoke_undoes_a_fitted_install() {
    let offered = offered();
    let claim = assert_installs(&offered);
    let revoked = offered
        .vault
        .memory(offered.owner_id, EdgeActorClass::Human)
        .plugin_section_revoke_as_owner(
            &offered.owner,
            &PluginSectionRevokeRequest {
                claim_ref: Some(claim.to_hex()),
                section_id: None,
            },
        )
        .expect("the owner revokes the install");
    assert_eq!(
        revoked.claim_refs,
        vec![claim.to_hex()],
        "the revoke retracts the install claim"
    );
    let body = offered
        .vault
        .get_claim(&claim)
        .expect("read the install claim")
        .expect("the install claim is stored");
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(
        !admitted(&offered),
        "a revoked section leaves the rebuilt registry"
    );
}

/// The same offer with the SKILL's substrate FACET stored first, so the
/// install claim's facet resolves (as #7205 gives it a stored facet) and
/// only the gate stands between the fit and the install.
#[test]
fn ready_fit_installs_with_the_skill_facet_stored() {
    let offered = offered();
    offered
        .vault
        .put_entity(
            &oneiron::claim::substrate_facet_id(offered.skill).expect("the skill's facet id"),
            ENTITY_TYPE_FACET,
            at(6),
            6,
            &rmp_serde::to_vec_named(&json!({"name": "open task digest facet"}))
                .expect("facet body"),
        )
        .expect("store the skill's facet");
    assert_installs(&offered);
}
