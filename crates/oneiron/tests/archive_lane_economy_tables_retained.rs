//! FIX LANE-ECONOMY-TABLES-ARCHIVE-CLASS (P2; OPUS-LE-ARMS PLAN 25 Nov 17:23; Engine ANSWER
//! LE-ARCHIVE-PERIOD-SEED = A, 25 Nov 19:32): the whole-vault archive carries the lane
//! economy's five side tables (`EXPERIMENT_ARM`, `EXPERIMENT_ARM_UNIT`, `GPU_LINE`,
//! `GPU_LINE_PERIOD`, `LANE_ECONOMY_INTENT`) as retained copies, and no import door, the
//! owner's restore included, writes one of their rows live. A two-rule period's row stays home
//! while its cohort seed is sealed on the store clock (the get view withholds the seed until
//! the period ends); once the period ends the row travels whole. A one-rule period always
//! travels.
//!
//! Red on main: the five tables are unclassified (tests/archive_side_catalogue_unclassified.txt),
//! so the export carries no row of them.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test archive_lane_economy_tables_retained`.
#![cfg(oneiron_test_support)]

use std::io::Cursor;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{ArmAdmitRequest, ArmContractAsk, RunnerRef, arm_admit_as};
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    BudgetPolicy, ClaimState, Draw, DrawSource, GpuLineFamilyAdmitRequest, GpuLinePolicy,
    GpuLineSetRequest, RuleRef, Track, UnitClaim, UnitPurpose, gpu_seconds, open_claim_in_txn,
};
use oneiron::llm::run_admission::{Allocation, AllocationRef, LeaseUnit, gpu_line_allocation_id};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::lane_economy_archive::{LANE_ECONOMY_TABLES, exported_rows, live_rows};
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_store::ports::manual_clock::ManualClock;

/// The store clock's start, in seconds: 21 Sep 2026, so period 0 has ended on any later
/// machine's wall clock.
const T0_SECS: u64 = 1_790_000_000;
const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
/// Period 0 starts where the store clock starts.
const ANCHOR_MS: u64 = T0_SECS * 1_000;
/// Before period 0: the owner sets the line and seats the family.
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
/// A moment inside period 0.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// The rung-1 cap: one first allowance.
const RUNG_1_SECS: u64 = 1_800;
/// The market left beside the floor: less than one first allowance.
const MARKET_SECS: u64 = 300;

/// A rooted vault on a manual store clock at `T0_SECS`, with its embedded owner bound to the
/// host and the owner's proof, as `experiment_arm_admit.rs` builds it.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let clock = ManualClock::new(T0_SECS);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("fresh vault");
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
        clock,
        owner,
        issuer,
        owner_proof,
        _dir: dir,
    }
}

fn wallet() -> WalletRef {
    WalletRef {
        issuer: "host".to_owned(),
        id: "gpu".to_owned(),
    }
}

/// One demand floor of one first allowance, no pinned share, no seat reserve, no new-idea
/// pool, a market smaller than one first allowance, one rung, and `rules`.
fn policy(rules: Vec<RuleRef>) -> GpuLinePolicy {
    GpuLinePolicy {
        unit: gpu_seconds(),
        wallet: wallet(),
        offers: Vec::new(),
        machines: Vec::new(),
        leads: Vec::new(),
        reviewers: Vec::new(),
        planners: Vec::new(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget: BudgetPolicy {
            allowance_units: RUNG_1_SECS + MARKET_SECS,
            pinned_parts: (0, 3),
            floor_arms: 1,
            rung_caps_secs: vec![RUNG_1_SECS],
            seat_reserve_floors: 0,
            new_idea_slots_per_period: 0,
            rules,
            ..BudgetPolicy::default()
        },
    }
}

impl Fixture {
    /// An owner-born lane project under the root.
    fn project_under(&self, parent: EntityId, depth_remaining: u64) -> EntityId {
        let id = EntityId::now();
        let mut record = ProjectRecord::new(
            id,
            Some(parent),
            self.vault.root_project().expect("root project"),
            self.owner,
        )
        .expect("project record");
        record.depth_remaining = depth_remaining;
        create_owner_project(
            &self.vault,
            &self.issuer,
            &self.owner_proof,
            &self
                .vault
                .owner_project_signer(&self.issuer)
                .expect("owner project signer"),
            self.owner,
            id,
            &record,
        )
        .unwrap_or_else(|error| panic!("the owner bears project {id:?}: {error:?}"));
        id
    }

    fn lane(&self) -> EntityId {
        self.project_under(self.vault.root_project().expect("root project"), 2)
    }

    /// The owner sets `lane`'s line with `rules` at `now_ms`, under an intent key of that lane:
    /// an intent key names one ask of its asker and verb, whatever the project.
    fn set_line(&self, lane: EntityId, rules: Vec<RuleRef>, now_ms: u64) {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: format!("set-{}", lane.to_hex()),
                    project: lane,
                    policy: policy(rules),
                },
                now_ms,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
    }

    /// A one-rule lane holding a row of each of the five tables: the line and the owner's
    /// intents (set before period 0), a seated family, an admitted arm (whose admission mints
    /// period 0) and one claimed unit of it.
    fn lane_with_every_row(&self) -> EntityId {
        let lane = self.lane();
        self.set_line(lane, vec![RuleRef::PAYOFF_SHARE_1], BEFORE_MS);
        let family = self.project_under(lane, 0);
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .admit_gpu_line_family(
                Some(&self.owner_proof),
                &GpuLineFamilyAdmitRequest {
                    intent_key: "seat".to_owned(),
                    project: lane,
                    family,
                    track: Track::Demand,
                },
                BEFORE_MS,
            )
            .unwrap_or_else(|error| panic!("the owner seats the family: {error:?}"));
        let admitted = arm_admit_as(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            Some(&self.owner_proof),
            &ArmAdmitRequest {
                intent_key: "arm".to_owned(),
                line: lane,
                family,
                type_ref: TypeRef::root(1),
                title: "the arm".to_owned(),
                contract: ArmContractAsk {
                    path: "contracts/arm.md".to_owned(),
                    sha256: "01".repeat(32),
                    note: None,
                    claimed_frozen_at_ms: Some(BEFORE_MS),
                },
                runner: RunnerRef {
                    model: "open-model-runner".to_owned(),
                    actor: None,
                },
                supersedes: None,
                ledger_rows: Vec::new(),
                card_digest: None,
            },
            NOW_MS,
        )
        .expect("the owner admits an arm into the family's floor");
        let allocation = Allocation {
            reference: AllocationRef {
                id: gpu_line_allocation_id(&lane),
                generation: 1,
            },
            units: RUNG_1_SECS + MARKET_SECS,
            unit: LeaseUnit::new("gpu_seconds").expect("unit"),
            wallet: Some(wallet()),
        };
        let claim = UnitClaim {
            id: EntityId::now(),
            arm: admitted.arm.id,
            rung: 1,
            unit_key: "check/shard-1".to_owned(),
            attempt: 1,
            line: lane,
            family,
            period: 0,
            purpose: UnitPurpose::Work,
            workload: "ab".repeat(32),
            machine: None,
            code_sha: "c0de".repeat(10),
            contract_sha256: "01".repeat(32),
            reserved_secs: RUNG_1_SECS,
            draws: vec![Draw {
                source: DrawSource::Floor,
                units: RUNG_1_SECS,
            }],
            wallet: wallet(),
            allocation: allocation.reference.clone(),
            grant: None,
            reserved_by: Some(self.owner),
            reserved_at_ms: NOW_MS,
            ask_digest: "ad".repeat(32),
            state: ClaimState::Claimed,
            revision: 1,
        };
        self.vault
            .with_write_txn(|txn| open_claim_in_txn(&self.vault, txn, &allocation, &[], &claim))
            .expect("the claim's write")
            .expect("the allocation admits the claim");
        lane
    }

    /// A two-rule lane whose line is set inside period 0, which mints period 0 with a cohort
    /// seed.
    fn two_rule_lane(&self) -> EntityId {
        let lane = self.lane();
        self.set_line(
            lane,
            vec![RuleRef::PAYOFF_SHARE_1, RuleRef::EVEN_SPLIT_1],
            NOW_MS,
        );
        lane
    }

    fn period_seed(&self, lane: &EntityId) -> Option<[u8; 32]> {
        self.vault
            .gpu_line_period(lane, 0)
            .expect("read")
            .expect("period 0")
            .cohort_seed
    }
}

/// The live rows of `table` in `vault`, sorted.
fn live(vault: &Vault, table: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows =
        live_rows(vault, table).unwrap_or_else(|error| panic!("{table}'s live rows: {error:?}"));
    rows.sort();
    rows
}

/// The rows of `table` `vault`'s whole-vault export carries, sorted (the export orders them by
/// their retained identity, not by source key).
fn exported(vault: &Vault, table: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = exported_rows(vault, table)
        .unwrap_or_else(|error| panic!("{table}'s exported rows: {error:?}"));
    rows.sort();
    rows
}

/// Whether a `GPU_LINE_PERIOD` key (lane id, big-endian u32 index) is one of `lane`'s.
fn of_lane(key: &[u8], lane: &EntityId) -> bool {
    key.len() == 20 && key[..16] == lane.as_bytes()[..]
}

#[test]
fn the_export_carries_each_lane_economy_table_and_holds_a_sealed_period_home() {
    let fixture = fixture();
    let lane = fixture.lane_with_every_row();
    let two_rule = fixture.two_rule_lane();
    assert!(
        fixture.period_seed(&two_rule).is_some(),
        "a two-rule mint draws a seed"
    );
    assert_eq!(fixture.period_seed(&lane), None, "one rule: no seed");

    // Inside period 0 on the store clock.
    for table in LANE_ECONOMY_TABLES {
        let live = live(&fixture.vault, table);
        assert!(!live.is_empty(), "{table} holds a live row");
        let carried = exported(&fixture.vault, table);
        if table == "GPU_LINE_PERIOD" {
            let (sealed, open): (Vec<_>, Vec<_>) = live
                .into_iter()
                .partition(|(key, _)| of_lane(key, &two_rule));
            assert_eq!(sealed.len(), 1, "the two-rule lane's period 0");
            assert!(
                open.iter().any(|(key, _)| of_lane(key, &lane)),
                "the one-rule lane's period 0"
            );
            assert_eq!(
                carried, open,
                "the export carries the one-rule period whole and holds the sealed one home"
            );
        } else {
            assert_eq!(
                carried, live,
                "the export carries every {table} row byte for byte"
            );
        }
    }

    // A second before the period ends the seed is still sealed.
    fixture.clock.set(T0_SECS + PERIOD_SECS - 1);
    assert!(
        !exported(&fixture.vault, "GPU_LINE_PERIOD")
            .iter()
            .any(|(key, _)| of_lane(key, &two_rule)),
        "sealed until end_ms"
    );

    // At end_ms the period has ended: its row travels whole, the seed with it.
    fixture.clock.set(T0_SECS + PERIOD_SECS);
    assert_eq!(
        exported(&fixture.vault, "GPU_LINE_PERIOD"),
        live(&fixture.vault, "GPU_LINE_PERIOD"),
        "every period row travels once its period has ended"
    );
    assert_eq!(
        ANCHOR_MS + PERIOD_MS,
        (T0_SECS + PERIOD_SECS) * 1_000,
        "period 0 ends at the clock's new reading"
    );
}

/// A fresh destination on the host's clock, later than any reading of the source's manual store
/// clock, so the engine seeds' times differ without a wait, as `campaign_house_voice_guide.rs`
/// opens its restored vault.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the destination vault");
    let vault =
        Vault::open(dir.path(), VaultConfig::default()).expect("open the destination vault");
    (dir, vault)
}

#[test]
fn no_import_door_writes_a_lane_economy_row_live() {
    let fixture = fixture();
    fixture.lane_with_every_row();
    fixture.two_rule_lane();
    // After period 0, so every period row travels.
    fixture.clock.set(T0_SECS + PERIOD_SECS);
    let source: Vec<_> = LANE_ECONOMY_TABLES
        .iter()
        .map(|table| (*table, exported(&fixture.vault, table)))
        .collect();
    for (table, rows) in &source {
        assert!(!rows.is_empty(), "the source archive carries {table} rows");
    }
    let archive = fixture
        .vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();

    let (_owner_dir, owner_dest) = open_later_vault();
    let owner = owner_dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    let dest_proof = owner_dest
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the destination owner's proof");
    owner_dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_proof)
        .expect("the owner's restore");
    let (_actor_dir, actor_dest) = open_later_vault();
    let actor = actor_dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    actor_dest
        .import_whole_vault_archive_from_with_actor(
            Cursor::new(&archive),
            &WriteActor::new(actor, EdgeActorClass::Human),
        )
        .expect("the actor import");
    let (_bare_dir, bare_dest) = open_later_vault();
    bare_dest
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import");

    for (door, dest) in [
        ("owner", &owner_dest),
        ("actor", &actor_dest),
        ("actorless", &bare_dest),
    ] {
        for (table, rows) in &source {
            assert!(
                live(dest, table).is_empty(),
                "the {door} import writes no {table} row live"
            );
            assert_eq!(
                &exported(dest, table),
                rows,
                "the {door} destination keeps every {table} row as an inert copy and carries it on"
            );
        }
    }
}
