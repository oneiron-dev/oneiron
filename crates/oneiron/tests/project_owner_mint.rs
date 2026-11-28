//! The owner's project mint (FIX [OWNER-PROJECT-MINT-DOOR]; Engine ACCEPT
//! 28 Nov 14:48): `vault.projects.mint {name, parent?, intent_key}` and its
//! read `vault.projects.minted`, through the engine acts the host doors call.
//!
//! - T1: the owner mints a lane under the root and the first tenant's child
//!   under the lane; the GPU line takes the lane (`vault.gpu.lines.set`
//!   refused NoProject before) and seats the child as its family
//!   (`families.admit` refused NotChild before); the owner leads both and no
//!   Grant is minted; the read lists both.
//! - T2: the same key and ask answer the same project and write nothing.
//! - T3: the same key with another name or parent is refused; another key
//!   with the same fields mints a second project.
//! - T4: a parent the vault does not serve (a missing id, another entity
//!   kind, a deleted project) is refused, and a refusal keeps no intent.
//! - T5: a name is one line without NUL, 1 to 128 bytes once trimmed; an
//!   intent key is not blank.
//! - T6: a deleted project leaves the read with its mint row, and its key's
//!   replay is refused.
//! - T7: the embedded handle refuses the mint and serves the read as the
//!   embedded owner, through the verb rows.
//! - T8: the read pages in mint order, 1 to 500 rows a page.
//!
//! On main neither door exists, so every test fails to build there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test project_owner_mint`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    BudgetPolicy, GpuLineFamilyAdmitRequest, GpuLinePolicy, GpuLineSetRequest, Track, gpu_seconds,
};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryError,
};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::owner_project_mint::mint_row_stored;
use oneiron::workspace_roster::{
    OwnerMintedProject, OwnerMintedProjectsRequest, OwnerProjectMintAnswer,
    OwnerProjectMintRequest, VAULT_PROJECTS_MINT,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

const PERIOD_SECS: u64 = 1_209_600;
const ANCHOR_MS: u64 = 1_000_000;
/// A moment inside the line's period 0.
const NOW_MS: u64 = ANCHOR_MS + 60_000;

/// A rooted vault with its embedded owner bound to the host, the owner's
/// proof and the host's slip issuer, as `gpu_line_doors.rs` opens it.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound to host");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault
        .sign_owner_project(
            &owner_proof,
            &vault
                .owner_project_signer(&issuer)
                .expect("owner project signer"),
            vault.root_project().expect("root project"),
        )
        .expect("the owner signs the root project");
    Fixture {
        vault,
        owner,
        issuer,
        owner_proof,
        _dir: dir,
    }
}

impl Fixture {
    fn root(&self) -> EntityId {
        self.vault.root_project().expect("root project")
    }

    /// `vault.projects.mint` as its host door runs it.
    fn try_mint(
        &self,
        name: &str,
        parent: Option<EntityId>,
        key: &str,
    ) -> Result<OwnerProjectMintAnswer, MemoryError> {
        let signer = self
            .vault
            .owner_project_signer(&self.issuer)
            .expect("owner project signer");
        self.vault.mint_owner_project(
            &self.owner_proof,
            &signer,
            &OwnerProjectMintRequest {
                name: name.to_owned(),
                parent,
                intent_key: key.to_owned(),
            },
        )
    }

    fn mint(&self, name: &str, parent: Option<EntityId>, key: &str) -> OwnerProjectMintAnswer {
        self.try_mint(name, parent, key)
            .unwrap_or_else(|error| panic!("the owner mints {name:?}: {error:?}"))
    }

    /// Every row `vault.projects.minted` answers, from its first page.
    fn minted(&self) -> Vec<OwnerMintedProject> {
        self.vault
            .owner_minted_projects(&self.owner_proof, &OwnerMintedProjectsRequest::default())
            .expect("the owner reads the minted projects")
            .projects
    }

    fn standing_grants(&self) -> usize {
        self.vault
            .active_standing_consent_grants()
            .expect("standing Grants")
            .len()
    }
}

fn refused_as(result: Result<OwnerProjectMintAnswer, MemoryError>, code: &str, mark: &str) {
    let error = result.expect_err(mark);
    assert_eq!(error.code, code, "{mark}: {error:?}");
    assert!(error.message.contains(mark), "{mark}: {error:?}");
}

/// The lane's policy: the open-models budget with no offer and no role, as
/// the first tenant's line is first set (offers: []).
fn policy() -> GpuLinePolicy {
    GpuLinePolicy {
        unit: gpu_seconds(),
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        offers: Vec::new(),
        machines: Vec::new(),
        leads: Vec::new(),
        reviewers: Vec::new(),
        planners: Vec::new(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget: BudgetPolicy {
            allowance_units: 345_600,
            pinned_parts: (1, 3),
            floor_arms: 2,
            rung_caps_secs: vec![1_800, 10_800, 172_800],
            seat_cap: 6,
            seat_reserve_floors: 1,
            new_idea_slots_per_period: 4,
            review_check_secs: 600,
            max_running_per_family: 1,
            forecast_required: true,
            window_periods: 3,
            ..BudgetPolicy::default()
        },
    }
}

/// T1.
#[test]
fn the_owner_mints_the_lane_and_its_child_and_the_line_takes_them() {
    let fixture = fixture();
    let root = fixture.root();
    let grants = fixture.standing_grants();

    let lane = fixture.mint("neon-lane", None, "lane-project-1");
    assert!(!lane.replayed, "{lane:?}");
    assert_eq!(lane.project.name, "neon-lane");
    assert_eq!(lane.project.parent, root, "no parent is the root");
    assert_eq!(lane.project.parents, vec![root]);
    assert_eq!(lane.project.minted_by, VAULT_PROJECTS_MINT);
    let lane = lane.project.project;

    let neon = fixture.mint("neon", Some(lane), "neon-project-1");
    assert_eq!(neon.project.parent, lane);
    assert_eq!(neon.project.parents, vec![lane]);
    let neon = neon.project.project;

    for (id, parent) in [(lane, root), (neon, lane)] {
        let record = fixture
            .vault
            .project(id)
            .expect("project read")
            .expect("the fold serves the minted project");
        assert_eq!(record.parents, vec![parent.to_hex()], "{record:?}");
        assert_eq!(record.leader, fixture.owner.to_hex(), "the owner leads it");
        assert!(record.board.is_empty(), "{record:?}");
        assert_eq!(record.roster, vec![fixture.owner.to_hex()], "{record:?}");
    }
    assert_eq!(
        fixture.standing_grants(),
        grants,
        "owner proof only: the mint writes no Grant"
    );

    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    memory
        .set_gpu_line(
            Some(&fixture.owner_proof),
            &GpuLineSetRequest {
                intent_key: "neon-line-set-1".to_owned(),
                project: lane,
                policy: policy(),
            },
            NOW_MS,
        )
        .unwrap_or_else(|error| panic!("the line takes the minted lane: {error:?}"));
    memory
        .admit_gpu_line_family(
            Some(&fixture.owner_proof),
            &GpuLineFamilyAdmitRequest {
                intent_key: "neon-family-admit-1".to_owned(),
                project: lane,
                family: neon,
                track: Track::Demand,
            },
            NOW_MS,
        )
        .unwrap_or_else(|error| panic!("the line seats the minted child: {error:?}"));

    let minted = fixture.minted();
    let rows: Vec<_> = minted
        .iter()
        .map(|row| (row.project, row.name.as_str(), row.parent))
        .collect();
    assert_eq!(rows, vec![(lane, "neon-lane", root), (neon, "neon", lane)]);
}

/// T2.
#[test]
fn the_same_key_and_ask_answer_the_same_project() {
    let fixture = fixture();
    let first = fixture.mint("neon-lane", None, "lane-project-1");
    let again = fixture.mint("neon-lane", None, "lane-project-1");
    assert!(again.replayed, "{again:?}");
    assert_eq!(again.project, first.project);
    assert_eq!(fixture.minted(), vec![first.project]);
}

/// T3.
#[test]
fn the_same_key_with_other_fields_is_refused() {
    let fixture = fixture();
    let root = fixture.root();
    let first = fixture.mint("neon-lane", None, "lane-project-1");
    refused_as(
        fixture.try_mint("other-lane", None, "lane-project-1"),
        MEMORY_CODE_INVALID_STATE,
        "different ask",
    );
    refused_as(
        fixture.try_mint("neon-lane", Some(root), "lane-project-1"),
        MEMORY_CODE_INVALID_STATE,
        "different ask",
    );
    assert_eq!(fixture.minted(), vec![first.project.clone()]);

    let second = fixture.mint("neon-lane", None, "lane-project-2");
    assert!(!second.replayed);
    assert_ne!(second.project.project, first.project.project);
    assert_eq!(fixture.minted().len(), 2);
}

/// T4.
#[test]
fn the_parent_must_be_a_project_the_vault_serves() {
    let fixture = fixture();
    let facet = EntityId::now();
    fixture
        .vault
        .put_entity(
            &facet,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .expect("a FACET row");
    let gone = fixture.mint("gone", None, "gone-project-1").project.project;
    assert!(fixture.vault.delete_entity(&gone).expect("delete"));
    let before = fixture.minted();

    for parent in [EntityId::now(), facet, gone] {
        refused_as(
            fixture.try_mint("neon", Some(parent), "neon-project-1"),
            MEMORY_CODE_NOT_FOUND,
            "no such project",
        );
    }
    assert_eq!(fixture.minted(), before, "a refused mint writes nothing");

    // A refusal keeps no intent: the same key mints under a served parent.
    let neon = fixture.mint("neon", None, "neon-project-1");
    assert!(!neon.replayed);
    assert_eq!(neon.project.parent, fixture.root());
}

/// T5.
#[test]
fn the_name_is_one_line_and_the_key_is_not_blank() {
    let fixture = fixture();
    for (index, name) in [
        String::new(),
        "   ".to_owned(),
        "a".repeat(129),
        "two\nlines".to_owned(),
        "a\rb".to_owned(),
        "nul\0".to_owned(),
    ]
    .iter()
    .enumerate()
    {
        refused_as(
            fixture.try_mint(name, None, &format!("bad-name-{index}")),
            MEMORY_CODE_BAD_REQUEST,
            "project name",
        );
    }
    let error = fixture
        .try_mint("neon", None, "  ")
        .expect_err("a blank intent key");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{error:?}");
    assert!(fixture.minted().is_empty());

    let longest = "a".repeat(128);
    assert_eq!(
        fixture.mint(&longest, None, "longest").project.name,
        longest
    );
    assert_eq!(
        fixture.mint("  neon  ", None, "trimmed").project.name,
        "neon",
        "the name is kept trimmed"
    );
}

/// T6.
#[test]
fn a_deleted_project_leaves_the_read() {
    let fixture = fixture();
    let lane = fixture.mint("neon-lane", None, "lane-project-1").project;
    let neon = fixture
        .mint("neon", Some(lane.project), "neon-project-1")
        .project;
    assert!(mint_row_stored(&fixture.vault, neon.project).expect("row read"));

    assert!(fixture.vault.delete_entity(&neon.project).expect("delete"));
    assert_eq!(fixture.minted(), vec![lane]);
    assert!(
        !mint_row_stored(&fixture.vault, neon.project).expect("row read"),
        "the name leaves with its project"
    );
    refused_as(
        fixture.try_mint("neon", Some(fixture.minted()[0].project), "neon-project-1"),
        MEMORY_CODE_INVALID_STATE,
        "is gone",
    );
}

/// T7.
#[test]
fn the_embedded_handle_refuses_the_mint_and_serves_the_read() {
    let fixture = fixture();
    let lane = fixture.mint("neon-lane", None, "lane-project-1").project;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let refused = oneiron::task_verb::sdk::invoke(
        &memory,
        "vault.projects.mint",
        json!({"name": "neon", "intent_key": "neon-project-1"}),
    )
    .map(drop)
    .map_err(|error| format!("{error:?}"))
    .expect_err("the embedded handle holds no host signer");
    assert!(
        refused.contains("authenticated owner and owner signer"),
        "the refusal sends the owner to the host's door: {refused}"
    );
    assert_eq!(fixture.minted(), vec![lane.clone()]);

    let page = oneiron::task_verb::sdk::invoke(&memory, "vault.projects.minted", json!({}))
        .unwrap_or_else(|error| panic!("the embedded owner reads the row: {error:?}"));
    assert_eq!(
        page["projects"][0]["project"],
        json!(lane.project),
        "{page}"
    );
    assert_eq!(
        page["projects"][0]["minted_by"], VAULT_PROJECTS_MINT,
        "{page}"
    );
}

/// T8.
#[test]
fn the_read_pages_in_mint_order() {
    let fixture = fixture();
    let ids: Vec<_> = (0..3)
        .map(|index| {
            fixture
                .mint(&format!("lane-{index}"), None, &format!("lane-{index}"))
                .project
                .project
        })
        .collect();
    let page = |after: Option<EntityId>, limit: Option<u32>| {
        fixture.vault.owner_minted_projects(
            &fixture.owner_proof,
            &OwnerMintedProjectsRequest { after, limit },
        )
    };
    let first = page(None, Some(2)).expect("first page");
    assert_eq!(
        first
            .projects
            .iter()
            .map(|row| row.project)
            .collect::<Vec<_>>(),
        ids[..2].to_vec()
    );
    assert_eq!(first.next_after, Some(ids[1]));
    let last = page(first.next_after, Some(2)).expect("last page");
    assert_eq!(
        last.projects
            .iter()
            .map(|row| row.project)
            .collect::<Vec<_>>(),
        ids[2..].to_vec()
    );
    assert_eq!(last.next_after, None);
    for limit in [0, 501] {
        let error = page(None, Some(limit)).expect_err("a limit outside 1..=500");
        assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{error:?}");
    }
    assert_eq!(page(None, Some(500)).expect("500 rows").projects.len(), 3);
}
