//! `vault.arms.units.reserve` and `vault.arms.units.cancel` through the engine doors.
//!
//! - T9–T10: settled seconds count across attempts and periods; rung 2 needs a promotion.
//! - T14 (claim half), T15: logical replay, intent conflicts, and the contract and workload pins.
//! - T45: two callers race for the last room, and exactly one reserves it.
//! - T47 (custody half), T48: an unstarted claim lapses but an unconfirmed start holds its room.
//! - T59: the reviewer's separate bound and the family's cost.
//! - T62 (reserve half): a new-idea arm reserves only at rung 1.
//! - Budget-refusal rows and cancellation, including authorization and replay.
//! - T13, T14 (start half), T46, T47 (start half): the one start gate. A unit's job starts only
//!   through its claim; a refused start returns the hold once; a plain start or resume on a
//!   line-managed offer is refused; a released claim cannot start; a started unit's job is
//!   cancelled through the unit door only.
//! - The owner's write-off of a unit's live job ends its claim in the same write (pass 33, 8.4).
//! - Row RSI-ARM-RESULT: a unit's result binding rides its claim into its job's quote (an
//!   immediate unit and a waiting one), only to rows the caller reads, and its landed result's
//!   report names the arm, the rung and the contract.
//!
//! The earlier tests change the claim through the start test door and start no GPU job. The
//! start-gate tests call `Vault::start_claimed_gpu_job` with an in-memory connector that counts
//! its creates and terminations; no test calls a node or the network.
#![cfg(oneiron_test_support)]

use std::sync::{Arc, Barrier};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineRole, MeshMachineAddress, pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ARMS_UNITS_CANCEL_VERB, ARMS_UNITS_RESERVE_VERB, ArmAdmitRequest, ArmContractAsk, ArmRung,
    ExperimentArm, HoldEndCause, RungState, RunnerRef, UnitCancel, UnitCancelRequest,
    UnitReserveRequest, UnitView, arm_admit_as, unit_cancel_as, unit_reserve_as,
};
use oneiron::federation::{Scope, ScopeAxis, WalletRef};
use oneiron::gpu_job::{GpuJobEnd, GpuJobTerminal, MeterVerdict};
use oneiron::gpu_line::{
    BudgetPolicy, ClaimKey, ClaimState, DIFFERENT_ASK, Draw, DrawSource, GpuLineFamilyAdmitRequest,
    GpuLinePolicy, GpuLineSetRequest, IntentAsk, IntentStand, LineRefusal, LineRefusalKey,
    SpendRow, Track, UnattributedJob, UnitCharge, UnitClaim, UnitEnd, UnitEndReport, UnitPurpose,
    claims_at_rung_in_txn, gpu_seconds, line_refusals_in_txn, mint_first_in_txn,
    record_node_answer_in_txn, settle_unit_in_txn,
};
use oneiron::job_workload::{
    DeviceClaim, DeviceKind, JOB_ALPN, NetworkMode, NoScreenModel, ResourceRequest, ScopeKind,
    Sharing, WorkloadApproveRequest, WorkloadCaller, WorkloadPin, WorkloadPinRequest,
    WorkloadStanding,
};
use oneiron::memory::{
    MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory,
    MemoryError, MemoryResult,
};
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::registry::ENTITY_TYPE_MACHINE;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::experiment_arm_rows::put_arm;
use oneiron::test_doors::gpu_line_hold_is_the_claim::{read_txn, start_claim};
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::store_writes::last_committed_write;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::work_order::WaitRule;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const ANCHOR_MS: u64 = 1_000_000;
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
const NOW_MS: u64 = ANCHOR_MS + 60_000;
const NEXT_MS: u64 = NOW_MS + PERIOD_SECS * 1_000;
const RUNG_1_SECS: u64 = 1_800;
const MARKET_SECS: u64 = 300;
const CUSTODY_MS: u64 = 600_000;
const LAPSED_MS: u64 = NOW_MS + CUSTODY_MS;
const REVIEW_SECS: u64 = 600;
// In the tight-room tests the wallet has room for one of these, not two.
// Two would still fit the rung cap and the arm's draw plan.
const LAST_UNIT_SECS: u64 = 900;
const OCCUPIED_SECS: u64 = RUNG_1_SECS + MARKET_SECS - LAST_UNIT_SECS;
const OFFER: &str = "fixture-gpu";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const CONTRACT_PATH: &str = "contracts/arm.md";
const CONTRACT_SHA256: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    machine: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    // A node answer belongs to this process's writer lease.
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh owned vault");
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
    let machine = job_machine(&vault, &issuer);
    Fixture {
        vault,
        owner,
        issuer,
        owner_proof,
        machine,
        _dir: dir,
    }
}

/// A paired MACHINE with a live job-protocol grant, without a listener or connector.
fn job_machine(vault: &Vault, issuer: &HostSlipIssuer) -> EntityId {
    let machine = EntityId::now();
    vault
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            1,
            b"test machine",
        )
        .expect("the machine's holder row");
    let device = SigningKey::from_bytes(&[31; 32]);
    let transport = SigningKey::from_bytes(&[32; 32]);
    let device_key = device.verifying_key().to_bytes();
    let endpoint_key = transport.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(issuer, Scope::top(), 3600)
        .expect("pairing link");
    let holder = machine.to_hex();
    let proof = device
        .sign(
            &pairing_binding_transcript(&link.code, &device_key, &holder)
                .expect("pairing transcript"),
        )
        .to_bytes();
    let pair = vault
        .redeem_pairing_link(issuer, &link.code, &holder, device_key, &proof)
        .expect("machine redeems pairing link");
    // The binding transcript from authority/mesh_machine.rs, also used by
    // doors_read_standing_heads.rs. The holder and transport both sign it.
    let mut binding = b"oneiron/mesh-machine-binding/v1\0".to_vec();
    binding.extend_from_slice(machine.as_bytes());
    binding.extend_from_slice(&endpoint_key);
    vault
        .bind_mesh_machine(
            issuer,
            machine,
            MeshMachineAddress {
                endpoint_key,
                direct_addrs: Vec::new(),
                relay_url: None,
            },
            device_key,
            pair.claims.slip_id,
            [
                &device.sign(&binding).to_bytes(),
                &transport.sign(&binding).to_bytes(),
            ],
        )
        .expect("bind the machine's endpoint");
    vault
        .set_mesh_alpn_grant(issuer, machine, endpoint_key, JOB_ALPN, true)
        .expect("grant the machine the job protocol");
    machine
}

#[derive(Default)]
struct Roles {
    leads: Vec<EntityId>,
    reviewers: Vec<EntityId>,
}

#[derive(Clone, Copy)]
struct Agent {
    actor: EntityId,
    grant: EntityId,
}

impl Fixture {
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
        .expect("the owner bears the project");
        id
    }

    fn agent(&self, name: &str) -> Agent {
        let actor = self
            .vault
            .ensure_agent_principal(name)
            .expect("named agent principal");
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            ["read", ARMS_UNITS_RESERVE_VERB, ARMS_UNITS_CANCEL_VERB]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent: actor,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: Default::default(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .expect("the owner mints the agent a Grant");
        assert!(minted.grant.confers, "agent={name}");
        Agent {
            actor,
            grant: minted.grant.grant_ref,
        }
    }

    fn caller(&self, agent: Option<Agent>) -> (Memory<'_>, Option<&AuthenticatedOwner>) {
        match agent {
            None => (
                self.vault.memory(self.owner, EdgeActorClass::Human),
                Some(&self.owner_proof),
            ),
            Some(agent) => (self.vault.memory(agent.actor, EdgeActorClass::Agent), None),
        }
    }

    fn lane(&self, roles: Roles, track: Track, floor_arms: u32) -> ExperimentArm {
        let lane = self.project_under(self.vault.root_project().expect("root project"), 2);
        let family = self.project_under(lane, 0);
        let (memory, owner) = self.caller(None);
        memory
            .set_gpu_line(
                owner,
                &GpuLineSetRequest {
                    intent_key: "set-line".to_owned(),
                    project: lane,
                    policy: GpuLinePolicy {
                        unit: gpu_seconds(),
                        wallet: WalletRef {
                            issuer: "host".to_owned(),
                            id: "gpu".to_owned(),
                        },
                        offers: vec![OFFER.to_owned()],
                        machines: vec![self.machine],
                        leads: roles.leads,
                        reviewers: roles.reviewers,
                        planners: Vec::new(),
                        period_secs: PERIOD_SECS,
                        period_anchor_ms: ANCHOR_MS,
                        budget: BudgetPolicy {
                            allowance_units: u64::from(floor_arms) * RUNG_1_SECS + MARKET_SECS,
                            floor_arms,
                            rung_caps_secs: vec![RUNG_1_SECS, RUNG_1_SECS],
                            new_idea_slots_per_period: if track == Track::NewIdea { 1 } else { 0 },
                            review_check_secs: REVIEW_SECS,
                            ..BudgetPolicy::default()
                        },
                    },
                },
                BEFORE_MS,
            )
            .expect("set the line before period 0");
        memory
            .admit_gpu_line_family(
                owner,
                &GpuLineFamilyAdmitRequest {
                    intent_key: "seat-family".to_owned(),
                    project: lane,
                    family,
                    track,
                },
                BEFORE_MS,
            )
            .expect("seat the family before period 0");
        arm_admit_as(
            &memory,
            owner,
            &ArmAdmitRequest {
                intent_key: "admit-arm".to_owned(),
                line: lane,
                family,
                type_ref: TypeRef::root(1),
                title: "fixture arm".to_owned(),
                contract: ArmContractAsk {
                    path: CONTRACT_PATH.to_owned(),
                    sha256: CONTRACT_SHA256.to_owned(),
                    note: None,
                    claimed_frozen_at_ms: Some(BEFORE_MS),
                },
                runner: RunnerRef {
                    model: "fixture-runner".to_owned(),
                    actor: None,
                },
                supersedes: None,
                ledger_rows: Vec::new(),
                card_digest: None,
            },
            NOW_MS,
        )
        .expect("admit the arm with a first allowance")
        .arm
    }

    fn answer(&self, arm: &ExperimentArm, now_ms: u64, occupied_secs: u64) {
        let jobs: Vec<_> = (occupied_secs > 0)
            .then(|| UnattributedJob {
                node_key: "restored-job:0".to_owned(),
                secs: occupied_secs,
                ended: true,
            })
            .into_iter()
            .collect();
        self.vault
            .with_write_txn(|txn| {
                let period = mint_first_in_txn(&self.vault, txn, &arm.line, now_ms)?
                    .expect("mint")
                    .expect("line")
                    .period
                    .expect("current period");
                record_node_answer_in_txn(
                    &self.vault,
                    txn,
                    &period.allocation.allocation(gpu_seconds()).reference,
                    self.machine,
                    &jobs,
                    now_ms,
                )
            })
            .expect("record the machine's answer for this generation");
    }

    fn ask(
        &self,
        arm: &ExperimentArm,
        unit: &str,
        secs: u64,
        starter: Option<Agent>,
    ) -> UnitReserveRequest {
        let caller = WorkloadCaller::Owner(&self.owner_proof);
        let pin = WorkloadPin {
            template: "fixture-template".to_owned(),
            template_digest: "a1".repeat(32),
            commit: COMMIT.to_owned(),
            contract_sha256: arm.contract.sha256.clone(),
            contract_path: arm.contract.path.clone(),
            entry: "arms/run.py".to_owned(),
            args: vec![unit.to_owned()],
            request: ResourceRequest {
                cpu_threads: 0,
                memory_mib: 512,
                disk_mib: 128,
                maximum_secs: secs,
                devices: vec![DeviceClaim {
                    kind: DeviceKind::Gpu,
                    count: 1,
                    memory_mib: 0,
                    features: Vec::new(),
                    sharing: Sharing::Exclusive,
                }],
            },
            scope: ScopeKind::Host,
            network: NetworkMode::None,
            outputs: Vec::new(),
        };
        // The pin door is the caller's memory handle (pass 34, 6.5): the
        // vault owner's pin goes at once, so no screen runs and no project or
        // check-in is named.
        let pinned = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .pin_job_workload(
                &WorkloadPinRequest {
                    pin,
                    project: None,
                    check_in_ref: None,
                },
                &NoScreenModel,
                NOW_MS,
            )
            .expect("the owner pins the workload");
        let workload = pinned.workload.digest;
        let approved = self
            .vault
            .approve_job_workload(
                caller,
                &WorkloadApproveRequest {
                    workload: workload.clone(),
                    machines: vec![self.machine.to_hex()],
                    // The owner may start any approved workload; agents must be named by Grant.
                    starters: starter
                        .into_iter()
                        .map(|agent| agent.grant.to_hex())
                        .collect(),
                    expires_at_ms: NEXT_MS + PERIOD_SECS * 1_000,
                },
                NOW_MS,
            )
            .expect("the owner approves the workload");
        assert_eq!(approved.workload.standing, WorkloadStanding::Approved);
        UnitReserveRequest {
            intent_key: format!("reserve-{unit}-{secs}"),
            line: arm.line,
            arm: arm.id,
            rung: 1,
            unit_key: unit.to_owned(),
            attempt: 1,
            purpose: UnitPurpose::Work,
            offer: OFFER.to_owned(),
            workload,
            machine: Some(self.machine),
            code_sha: COMMIT.to_owned(),
            contract_sha256: arm.contract.sha256.clone(),
            secs,
            result: None,
            wait: WaitRule::No,
        }
    }

    fn reserve(
        &self,
        agent: Option<Agent>,
        ask: &UnitReserveRequest,
        at_ms: u64,
    ) -> MemoryResult<UnitView> {
        let (memory, owner) = self.caller(agent);
        unit_reserve_as(&memory, owner, ask, at_ms)
    }

    /// The withdrawal of an unstarted unit, as its view; a started unit's admitted cancel
    /// answers the view the cancel read.
    fn cancel(
        &self,
        agent: Option<Agent>,
        ask: &UnitReserveRequest,
        at_ms: u64,
    ) -> MemoryResult<UnitView> {
        self.cancel_outcome(agent, ask, at_ms)
            .map(|outcome| match outcome {
                UnitCancel::Withdrawn(view) => view,
                UnitCancel::JobStarted(started) => started.view().clone(),
            })
    }

    fn cancel_outcome(
        &self,
        agent: Option<Agent>,
        ask: &UnitReserveRequest,
        at_ms: u64,
    ) -> MemoryResult<UnitCancel> {
        let (memory, owner) = self.caller(agent);
        unit_cancel_as(
            &memory,
            owner,
            &UnitCancelRequest {
                line: ask.line,
                arm: ask.arm,
                rung: ask.rung,
                unit_key: ask.unit_key.clone(),
                attempt: ask.attempt,
            },
            at_ms,
        )
    }

    fn claims(&self, arm: &ExperimentArm, rung: u8) -> Vec<UnitClaim> {
        let txn = read_txn(&self.vault).expect("read snapshot");
        claims_at_rung_in_txn(&self.vault, &txn, &arm.id, rung).expect("read claim rows")
    }

    fn refusals(&self, arm: &ExperimentArm, period: u32) -> Vec<(LineRefusalKey, LineRefusal)> {
        let txn = read_txn(&self.vault).expect("read snapshot");
        line_refusals_in_txn(&self.vault, &txn, &arm.line, period).expect("read refusal rows")
    }

    fn start(&self, ask: &UnitReserveRequest) -> ClaimKey {
        let key = ClaimKey::of(ask.arm, ask.rung, &ask.unit_key, ask.attempt);
        start_claim(&self.vault, &key).expect("start the claim through the test door");
        key
    }

    fn settle(&self, ask: &UnitReserveRequest, job: EntityId, at_ms: u64) -> UnitClaim {
        let key = self.start(ask);
        let report = UnitEndReport::Machine(GpuJobTerminal {
            end: GpuJobEnd::Exited { code: 0 },
            measured_secs: Some(ask.secs),
            billed_secs: ask.secs,
            meter: MeterVerdict::Agreed,
            machine: Some(self.machine),
            device_id: Some(OFFER.to_owned()),
            outputs: Vec::new(),
        });
        let settlement = self
            .vault
            .with_write_txn(|txn| settle_unit_in_txn(&self.vault, txn, &key, &job, &report, at_ms))
            .expect("terminal write transaction")
            .expect("machine end settles the claim");
        assert!(!settlement.replayed);
        let ClaimState::Ended(terminal) = &settlement.claim.state else {
            panic!("not ended")
        };
        assert_eq!(terminal.end, UnitEnd::Settled);
        assert_eq!(terminal.charged_secs, ask.secs);
        settlement.claim
    }
}

fn refused_as(result: MemoryResult<UnitView>, code: &str, prefix: &str) {
    let error: MemoryError = result.expect_err("the unit door should refuse this ask");
    assert_eq!(error.code, code, "{error:?}");
    assert!(
        error.message.starts_with(prefix),
        "expected {prefix:?}: {error:?}"
    );
}

fn only_claim(claims: &[UnitClaim]) -> &UnitClaim {
    let [claim] = claims else {
        panic!("expected exactly one claim: {claims:?}")
    };
    claim
}

fn only_refusal(rows: &[(LineRefusalKey, LineRefusal)]) -> &(LineRefusalKey, LineRefusal) {
    let [row] = rows else {
        panic!("expected exactly one refusal: {rows:?}")
    };
    row
}

/// T9.
#[test]
fn the_rung_cap_counts_every_attempt_and_period() {
    let fixture = fixture();
    let arm = fixture.lane(Roles::default(), Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, 0);

    let oversized = fixture.ask(&arm, "oversized", RUNG_1_SECS + 1, None);
    refused_as(
        fixture.reserve(None, &oversized, NOW_MS),
        MEMORY_CODE_BUDGET_SPENT,
        "over_rung_cap:",
    );
    assert!(fixture.claims(&arm, 1).is_empty());
    let period_zero = fixture.refusals(&arm, 0);
    let (_, row) = only_refusal(&period_zero);
    assert_eq!(row.reason, "over_rung_cap");
    assert_eq!(row.asked_secs, 1_801);
    assert_eq!(row.room, RUNG_1_SECS);
    assert!(row.short.is_none());

    let first = fixture.ask(&arm, "model-check", 1_200, None);
    let reserved = fixture
        .reserve(None, &first, NOW_MS)
        .expect("first attempt fits");
    let settled = fixture.settle(&first, reserved.job, NOW_MS + first.secs * 1_000);
    assert_eq!(settled.period, 0);

    fixture.answer(&arm, NEXT_MS, 0);
    let mut next = fixture.ask(&arm, &first.unit_key, 700, None);
    next.attempt = 2;
    refused_as(
        fixture.reserve(None, &next, NEXT_MS),
        MEMORY_CODE_BUDGET_SPENT,
        "over_rung_cap:",
    );
    assert_eq!(fixture.claims(&arm, 1), vec![settled]);
    assert_eq!(fixture.refusals(&arm, 0), period_zero);
    let period_one = fixture.refusals(&arm, 1);
    let (key, row) = only_refusal(&period_one);
    assert_eq!(key.period, 1);
    assert_eq!(row.reason, "over_rung_cap");
    assert_eq!(row.asked_secs, 700);
    assert_eq!(row.room, 600);
    assert!(row.short.is_none());
    assert!(fixture.vault.gpu_jobs().expect("read GPU jobs").is_empty());
}

/// T10.
#[test]
fn a_rung_two_unit_needs_a_promotion_record() {
    let fixture = fixture();
    let mut arm = fixture.lane(Roles::default(), Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, 0);
    let mut ask = fixture.ask(&arm, "rung-two", 60, None);
    ask.rung = 2;
    refused_as(
        fixture.reserve(None, &ask, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        "rung_not_promoted:",
    );

    // A rung row alone is not proof that a reviewer opened it.
    arm.rungs.push(ArmRung::open(2, None));
    arm.revision += 1;
    put_arm(&fixture.vault, &arm).expect("stand rung 2 without a promotion record");
    refused_as(
        fixture.reserve(None, &ask, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        "rung_not_promoted:",
    );
    assert!(fixture.claims(&arm, 1).is_empty());
    assert!(fixture.claims(&arm, 2).is_empty());
    assert!(fixture.refusals(&arm, 0).is_empty());
}

/// T14, the claim half.
#[test]
fn a_reserve_retried_after_a_lost_answer_gets_the_same_claim() {
    let fixture = fixture();
    let arm = fixture.lane(Roles::default(), Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, 0);
    let ask = fixture.ask(&arm, "same-attempt", 60, None);
    let first = fixture
        .reserve(None, &ask, NOW_MS)
        .expect("first reservation");
    assert!(!first.replayed);

    let mut retry = ask.clone();
    retry.intent_key = "new-intent-after-lost-answer".to_owned();
    let again = fixture
        .reserve(None, &retry, NOW_MS)
        .expect("logical attempt replays");
    assert!(again.replayed);
    assert_eq!(again.job, first.job);
    let rows = fixture.claims(&arm, 1);
    let claim = only_claim(&rows);
    assert_eq!(claim.id, first.job);
    assert_eq!(claim.state, ClaimState::Claimed);

    retry.machine = None;
    refused_as(
        fixture.reserve(None, &retry, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        DIFFERENT_ASK,
    );
    retry.intent_key = "new-intent-different-ask".to_owned();
    refused_as(
        fixture.reserve(None, &retry, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        "attempt_conflict:",
    );
    assert_eq!(fixture.claims(&arm, 1), rows);
    assert!(fixture.refusals(&arm, 0).is_empty());
    assert!(fixture.vault.gpu_jobs().expect("read GPU jobs").is_empty());
}

/// T15.
#[test]
fn a_changed_contract_digest_refuses_the_reservation() {
    let fixture = fixture();
    let arm = fixture.lane(Roles::default(), Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, 0);
    let ask = fixture.ask(&arm, "pinned", 60, None);
    let mut changed = ask.clone();
    changed.contract_sha256 = "b2".repeat(32);
    refused_as(
        fixture.reserve(None, &changed, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        "contract_changed:",
    );

    changed = ask.clone();
    changed.code_sha = "b2".repeat(20);
    refused_as(
        fixture.reserve(None, &changed, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        "workload_mismatch:",
    );

    changed = ask;
    changed.secs += 1;
    refused_as(
        fixture.reserve(None, &changed, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        "maximum_mismatch:",
    );
    assert!(fixture.claims(&arm, 1).is_empty());
    assert!(fixture.refusals(&arm, 0).is_empty());
}

/// T45.
#[test]
fn two_reserves_for_the_last_room_admit_one() {
    let fixture = fixture();
    let arm = fixture.lane(Roles::default(), Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, OCCUPIED_SECS);
    let left = fixture.ask(&arm, "left", LAST_UNIT_SECS, None);
    let right = fixture.ask(&arm, "right", LAST_UNIT_SECS, None);
    let gate = Barrier::new(2);
    let reserve = |ask: &UnitReserveRequest| {
        gate.wait();
        fixture.reserve(None, ask, NOW_MS)
    };
    let (first, second) = std::thread::scope(|scope| {
        let a = scope.spawn(|| reserve(&left));
        let b = scope.spawn(|| reserve(&right));
        (
            a.join().expect("left caller"),
            b.join().expect("right caller"),
        )
    });
    let (winner, loser) = match (first, second) {
        (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
        other => panic!("one caller must win and the other must be refused: {other:?}"),
    };
    refused_as(Err(loser), MEMORY_CODE_BUDGET_SPENT, "budget_denied:");
    assert!(!winner.replayed);
    assert_eq!(winner.room_left_secs, Some(0));
    let claims = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&claims).id, winner.job);
    let rows = fixture.refusals(&arm, 0);
    let (_, row) = only_refusal(&rows);
    assert_eq!(row.reason, "budget_denied");
    assert_eq!(row.asked_secs, LAST_UNIT_SECS);
    assert_eq!(row.room, 0);
}

/// T47, the custody half.
#[test]
fn a_claim_past_its_custody_is_released_by_the_next_attempt() {
    let fixture = fixture();
    let arm = fixture.lane(Roles::default(), Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, OCCUPIED_SECS);
    let first = fixture.ask(&arm, "retryable", LAST_UNIT_SECS, None);
    let claimed = fixture
        .reserve(None, &first, NOW_MS)
        .expect("first attempt");
    let mut next = first.clone();
    next.intent_key = "attempt-two".to_owned();
    next.attempt = 2;

    refused_as(
        fixture.reserve(None, &next, LAPSED_MS - 1),
        MEMORY_CODE_INVALID_STATE,
        "attempt_open:",
    );
    let claims = fixture.claims(&arm, 1);
    let prior = only_claim(&claims);
    assert_eq!(prior.state, ClaimState::Claimed);
    assert_eq!(prior.reserved_at_ms + CUSTODY_MS, LAPSED_MS);

    let successor = fixture
        .reserve(None, &next, LAPSED_MS)
        .expect("custody ends at the boundary");
    assert_eq!(successor.state, "claimed");
    assert!(!successor.replayed);
    assert_ne!(successor.job, claimed.job);
    let claims = fixture.claims(&arm, 1);
    let [prior, current] = claims.as_slice() else {
        panic!("expected two attempts: {claims:?}")
    };
    assert_eq!((prior.attempt, current.attempt), (1, 2));
    assert_eq!(current.state, ClaimState::Claimed);
    let ClaimState::Ended(terminal) = &prior.state else {
        panic!("still open: {prior:?}")
    };
    assert_eq!(terminal.end, UnitEnd::Released("custody_lapsed".to_owned()));
    assert_eq!(terminal.ended_at_ms, LAPSED_MS);

    let replay = fixture
        .reserve(None, &first, LAPSED_MS)
        .expect("read ended attempt by replay");
    assert!(replay.replayed);
    assert_eq!(replay.job, claimed.job);
    assert_eq!(replay.end.as_deref(), Some("released: custody_lapsed"));
    assert!(fixture.refusals(&arm, 0).is_empty());
}

/// T48.
#[test]
fn an_unconfirmed_unit_holds_its_room_and_admits_no_successor() {
    let fixture = fixture();
    let arm = fixture.lane(Roles::default(), Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, OCCUPIED_SECS);
    let first = fixture.ask(&arm, "unconfirmed", LAST_UNIT_SECS, None);
    let claimed = fixture
        .reserve(None, &first, NOW_MS)
        .expect("first attempt");
    fixture.start(&first);
    let mut next = first.clone();
    next.intent_key = "attempt-two".to_owned();
    next.attempt = 2;
    let after_custody = LAPSED_MS + 1;
    refused_as(
        fixture.reserve(None, &next, after_custody),
        MEMORY_CODE_INVALID_STATE,
        "attempt_open:",
    );
    assert!(fixture.refusals(&arm, 0).is_empty());

    let other = fixture.ask(&arm, "other-unit", LAST_UNIT_SECS, None);
    refused_as(
        fixture.reserve(None, &other, after_custody),
        MEMORY_CODE_BUDGET_SPENT,
        "budget_denied:",
    );
    let claims = fixture.claims(&arm, 1);
    let claim = only_claim(&claims);
    assert_eq!(claim.id, claimed.job);
    assert_eq!(claim.state, ClaimState::Started);
    assert_eq!(claim.reserved_secs, LAST_UNIT_SECS);
    let rows = fixture.refusals(&arm, 0);
    let (_, row) = only_refusal(&rows);
    assert_eq!(row.reason, "budget_denied");
    assert_eq!(row.room, 0);
}

/// T59.
#[test]
fn a_review_check_is_bounded_and_is_the_familys_cost() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let reviewer = fixture.agent("reviewer");
    let roles = Roles {
        leads: vec![lead.grant],
        reviewers: vec![reviewer.grant],
    };
    // Two floor allowances leave room for review even after work spends the full rung cap.
    let mut arm = fixture.lane(roles, Track::Demand, 2);
    fixture.answer(&arm, NOW_MS, 0);
    let work = fixture.ask(&arm, "work", RUNG_1_SECS, Some(lead));
    let reserved = fixture
        .reserve(Some(lead), &work, NOW_MS)
        .expect("work fills the rung cap");
    let review_at = NOW_MS + RUNG_1_SECS * 1_000;
    let work_claim = fixture.settle(&work, reserved.job, review_at);
    arm.rungs[0].state = RungState::AwaitingReview;
    assert!(arm.end_hold(review_at, HoldEndCause::RungClosed));
    arm.revision += 1;
    put_arm(&fixture.vault, &arm).expect("stand the rung awaiting review");

    let mut check = fixture.ask(&arm, "review-check", REVIEW_SECS, Some(reviewer));
    check.purpose = UnitPurpose::ReviewCheck;
    let reviewed = fixture
        .reserve(Some(reviewer), &check, review_at)
        .expect("review has its own bound");
    assert_eq!(reviewed.purpose, UnitPurpose::ReviewCheck);
    let floor_draws = vec![Draw {
        source: DrawSource::Floor,
        units: REVIEW_SECS,
    }];
    assert_eq!(reviewed.draws, floor_draws);

    let mut extra = fixture.ask(&arm, "extra-review", 1, Some(reviewer));
    extra.purpose = UnitPurpose::ReviewCheck;
    refused_as(
        fixture.reserve(Some(reviewer), &extra, review_at),
        MEMORY_CODE_INVALID_STATE,
        "over_review_check:",
    );
    let mut blocked_work = fixture.ask(&arm, "extra-work", 1, Some(lead));
    refused_as(
        fixture.reserve(Some(lead), &blocked_work, review_at),
        MEMORY_CODE_INVALID_STATE,
        "rung_not_open:",
    );
    blocked_work.purpose = UnitPurpose::ReviewCheck;
    refused_as(
        fixture.reserve(Some(lead), &blocked_work, review_at),
        MEMORY_CODE_FORBIDDEN,
        "vault.arms.units.reserve: not_this_line:",
    );

    let review_claim = fixture.settle(&check, reviewed.job, review_at + REVIEW_SECS * 1_000);
    assert_eq!(review_claim.grant, Some(reviewer.grant));
    assert_eq!(
        review_claim.spend_row(),
        SpendRow::Unit {
            arm: arm.id,
            family: arm.family,
            period: 0,
            draws: floor_draws,
            charge: UnitCharge::Settled(REVIEW_SECS),
        }
    );
    let claims = fixture.claims(&arm, 1);
    assert_eq!(claims.len(), 2);
    assert!(claims.contains(&work_claim) && claims.contains(&review_claim));
    assert!(fixture.refusals(&arm, 0).is_empty());
}

#[test]
fn a_budget_refusal_writes_one_refusal_row_and_nothing_else() {
    let fixture = fixture();
    let arm = fixture.lane(Roles::default(), Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, OCCUPIED_SECS);
    let ask = fixture.ask(&arm, "too-large-for-wallet", LAST_UNIT_SECS + 1, None);
    let period = fixture
        .vault
        .gpu_line_period(&arm.line, 0)
        .expect("read period");
    let line = fixture.vault.gpu_line(&arm.line).expect("read line");
    let workload = fixture
        .vault
        .job_workload(&ask.workload)
        .expect("read workload");
    assert!(fixture.refusals(&arm, 0).is_empty());
    let before = last_committed_write(&fixture.vault);
    refused_as(
        fixture.reserve(None, &ask, NOW_MS),
        MEMORY_CODE_BUDGET_SPENT,
        "budget_denied:",
    );
    assert_eq!(last_committed_write(&fixture.vault), before + 1);

    let rows = fixture.refusals(&arm, 0);
    let (key, row) = only_refusal(&rows);
    assert_eq!(
        *key,
        LineRefusalKey {
            line: arm.line,
            period: 0,
            sequence: 0
        }
    );
    assert_eq!(row.family, arm.family);
    assert_eq!(row.arm, Some(arm.id));
    assert_eq!(row.rung, 1);
    assert_eq!(row.asked_secs, ask.secs);
    assert_eq!(row.reason, "budget_denied");
    assert_eq!(row.by, Some(fixture.owner));
    assert_eq!(row.at_ms, NOW_MS);
    assert_eq!(row.room, LAST_UNIT_SECS);
    assert!(fixture.claims(&arm, 1).is_empty());
    assert!(fixture.vault.gpu_jobs().expect("read GPU jobs").is_empty());
    assert_eq!(
        fixture.vault.experiment_arm(&arm.id).expect("read arm"),
        Some(arm.clone())
    );
    assert_eq!(fixture.vault.gpu_line(&arm.line).expect("read line"), line);
    assert_eq!(
        fixture
            .vault
            .gpu_line_period(&arm.line, 0)
            .expect("read period"),
        period
    );
    assert_eq!(
        fixture
            .vault
            .job_workload(&ask.workload)
            .expect("read workload"),
        workload
    );

    // `stand_in_txn` returns New only if the (actor, verb, intent key) row is absent,
    // regardless of this probe's ask digest.
    let intent = IntentAsk::new(fixture.owner, ARMS_UNITS_RESERVE_VERB, &ask.intent_key, &())
        .expect("frame the refused intent key");
    let txn = read_txn(&fixture.vault).expect("read snapshot");
    assert!(matches!(
        intent
            .stand_in_txn(&fixture.vault, &txn)
            .expect("read intent"),
        Ok(IntentStand::New)
    ));
}

#[test]
fn a_cancelled_unit_returns_its_room_and_a_repeat_answers_it() {
    let fixture = fixture();
    let lead = fixture.agent("reserver");
    let other_lead = fixture.agent("other-lead");
    let roles = Roles {
        leads: vec![lead.grant, other_lead.grant],
        ..Roles::default()
    };
    let arm = fixture.lane(roles, Track::Demand, 1);
    fixture.answer(&arm, NOW_MS, OCCUPIED_SECS);
    let first = fixture.ask(&arm, "to-withdraw", LAST_UNIT_SECS, Some(lead));
    let reserved = fixture
        .reserve(Some(lead), &first, NOW_MS)
        .expect("claim the last room");
    let next = fixture.ask(&arm, "takes-returned-room", LAST_UNIT_SECS, Some(lead));
    refused_as(
        fixture.reserve(Some(lead), &next, NOW_MS),
        MEMORY_CODE_BUDGET_SPENT,
        "budget_denied:",
    );
    refused_as(
        fixture.cancel(Some(other_lead), &first, NOW_MS),
        MEMORY_CODE_FORBIDDEN,
        "vault.arms.units.cancel: not_the_reserver:",
    );
    let claims = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&claims).state, ClaimState::Claimed);

    let cancelled = fixture
        .cancel(Some(lead), &first, NOW_MS)
        .expect("withdraw the unstarted claim");
    assert_eq!(cancelled.job, reserved.job);
    assert_eq!(cancelled.state, "ended");
    assert_eq!(cancelled.end.as_deref(), Some("released: withdrawn"));
    assert!(!cancelled.replayed);
    let replay = fixture
        .cancel(Some(lead), &first, NOW_MS)
        .expect("repeat answers the withdrawn claim");
    assert_eq!(
        replay,
        UnitView {
            replayed: true,
            ..cancelled
        }
    );

    let replacement = fixture
        .reserve(Some(lead), &next, NOW_MS)
        .expect("the same ask now fits");
    assert_eq!(replacement.room_left_secs, Some(0));
    fixture.start(&next);
    // A started unit's cancel is admitted for its reserver and ends its job through the scoped
    // path (row M2-C part 2); the claim ends at the job's terminal.
    let UnitCancel::JobStarted(started) = fixture
        .cancel_outcome(Some(lead), &next, NOW_MS)
        .expect("the reserver may cancel its started unit")
    else {
        panic!("a started unit's cancel is the cancel of its job")
    };
    assert_eq!(started.job(), replacement.job);
    assert_eq!(started.view().state, "started");
    let claims = fixture.claims(&arm, 1);
    assert_eq!(claims.len(), 2);
    let ended = claims
        .iter()
        .find(|claim| claim.id == reserved.job)
        .expect("withdrawn claim");
    let ClaimState::Ended(terminal) = &ended.state else {
        panic!("the withdrawal did not stand")
    };
    assert_eq!(terminal.end, UnitEnd::Released("withdrawn".to_owned()));
    assert_eq!(terminal.charged_secs, 0);
    let started = claims
        .iter()
        .find(|claim| claim.id == replacement.job)
        .expect("started claim");
    assert_eq!(started.state, ClaimState::Started);
    let rows = fixture.refusals(&arm, 0);
    assert_eq!(only_refusal(&rows).1.reason, "budget_denied");
}

/// T62, the reserve half.
#[test]
fn a_new_idea_arm_reserves_at_rung_one_only() {
    let fixture = fixture();
    let arm = fixture.lane(Roles::default(), Track::NewIdea, 1);
    fixture.answer(&arm, NOW_MS, 0);
    assert_eq!(arm.track, Track::NewIdea);
    let hold = arm
        .first_allowance
        .as_ref()
        .expect("hold on the new-idea floor");
    assert_eq!(
        hold.draws,
        vec![Draw {
            source: DrawSource::Floor,
            units: RUNG_1_SECS
        }]
    );
    let first = fixture.ask(&arm, "new-idea", RUNG_1_SECS, None);
    let reserved = fixture
        .reserve(None, &first, NOW_MS)
        .expect("new ideas can reserve rung 1");
    assert_eq!(
        reserved.draws,
        vec![Draw {
            source: DrawSource::FirstAllowance,
            units: RUNG_1_SECS
        }]
    );

    let mut later = first;
    later.rung = 2;
    later.intent_key = "new-idea-rung-two".to_owned();
    refused_as(
        fixture.reserve(None, &later, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        "new_idea_rung_one_only:",
    );
    let claims = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&claims).id, reserved.job);
    assert!(fixture.claims(&arm, 2).is_empty());
    assert!(fixture.refusals(&arm, 0).is_empty());
}

// The claimed-start tests use the same door as the server, not Fixture::start's claim-only hook.
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::gpu_job::{
    GpuConnectorError, GpuEndReason, GpuJob, GpuJobActor, GpuJobConnector, GpuJobError,
    GpuJobPermits, GpuJobQuote, GpuJobRequest, GpuJobSignal, GpuJobSpec, GpuJobStart, GpuJobState,
    GpuJobVerb, GpuOffer, GpuResourceRef, GpuResourceStatus, GpuTermination, LineStartRefused,
    PriceShape, UnitJobStart,
};
use oneiron::gpu_line::{allocation_standing_in_txn, stored_period_in_txn};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{
    BudgetLine, CheckpointRef, DeclaredMaximum, JobMaximum, KeyCustody, LeaseUnit, MaximumShown,
    MemoryReceipts, OfferRoute, PaidConnector, Payer, RunAdmission, RunDeclaration,
};

#[derive(Default)]
struct UnitJobConnector {
    create_refusal: Option<&'static str>,
    creates: AtomicUsize,
    status_calls: AtomicUsize,
    terminations: AtomicUsize,
    write_offs: AtomicUsize,
    statuses: Mutex<VecDeque<GpuResourceStatus>>,
    billed_secs: u64,
    checkpoint_signal: Option<GpuJobSignal>,
}

impl GpuJobConnector for UnitJobConnector {
    fn create(&self, key: &str, _spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        self.creates.fetch_add(1, Ordering::Relaxed);
        if let Some(reason) = self.create_refusal {
            return Err(GpuConnectorError::Refused {
                reason: reason.to_owned(),
            });
        }
        Ok(GpuResourceRef(format!("resource-{key}")))
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        panic!("unexpected find for {key}");
    }

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        self.status_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .statuses
            .lock()
            .expect("scripted status lock")
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected status for {resource:?}")))
    }

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        assert_eq!(
            Some(signal),
            self.checkpoint_signal,
            "unexpected signal for {resource:?}"
        );
        Ok(())
    }

    fn terminate(&self, _resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        self.terminations.fetch_add(1, Ordering::Relaxed);
        Ok(GpuTermination::Confirmed {
            billed_secs: self.billed_secs,
        })
    }

    fn write_off(&self, _job: &GpuJob, _now_ms: u64) -> Result<(), GpuConnectorError> {
        self.write_offs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct UnitJobs {
    offer: GpuOffer,
    permits: GpuJobPermits,
    connector: UnitJobConnector,
}

impl UnitJobs {
    fn new(create_refusal: Option<&'static str>) -> Self {
        Self {
            offer: GpuOffer {
                name: OFFER.to_owned(),
                class: "fixture-class".to_owned(),
                provider: "fixture-provider".to_owned(),
                region: "fixture-region".to_owned(),
                connector: PaidConnector {
                    connector: OFFER.to_owned(),
                    route: OfferRoute::new(OFFER, "https://gpu.example.invalid").expect("route"),
                    locality: ModelLocality::ThirdParty,
                    payer: Payer::Local,
                    credential_binding: None,
                    catalog_revision: None,
                    custody: KeyCustody::T0,
                    unit_cost: 1,
                    cost_unit: gpu_seconds(),
                    rates: Vec::new(),
                },
                price_shape: PriceShape::AtOneironList,
                list_cost_per_second: None,
                startup_secs: 0,
                teardown_secs: 0,
                rounding_secs: 0,
            },
            permits: GpuJobPermits::new(),
            connector: UnitJobConnector {
                create_refusal,
                ..UnitJobConnector::default()
            },
        }
    }

    fn with_statuses(mut self, statuses: impl IntoIterator<Item = GpuResourceStatus>) -> Self {
        self.connector.statuses = Mutex::new(statuses.into_iter().collect());
        self
    }

    fn with_billed_secs(mut self, billed_secs: u64) -> Self {
        self.connector.billed_secs = billed_secs;
        self
    }

    fn with_checkpoint_signal(mut self, percent: u8) -> Self {
        self.connector.checkpoint_signal = Some(GpuJobSignal::CheckpointDue { percent });
        self
    }

    fn creates(&self) -> usize {
        self.connector.creates.load(Ordering::Relaxed)
    }

    fn calls(&self) -> (usize, usize, usize) {
        (
            self.creates(),
            self.connector.status_calls.load(Ordering::Relaxed),
            self.connector.terminations.load(Ordering::Relaxed),
        )
    }

    fn quote(
        &self,
        fixture: &Fixture,
        ask: &UnitReserveRequest,
        view: &UnitView,
        at_ms: u64,
    ) -> (ClaimKey, GpuJobQuote) {
        let (key, request) = fixture.unit_request(ask, view, at_ms);
        let quote = self
            .offer
            .quote_for(view.job, &request, ask.secs, at_ms)
            .expect("quote the claim's job");
        (key, quote)
    }

    fn start(
        &self,
        fixture: &Fixture,
        lead: Agent,
        key: &ClaimKey,
        quote: &GpuJobQuote,
        at_ms: u64,
    ) -> Result<GpuJob, GpuJobError> {
        let (memory, _) = fixture.caller(Some(lead));
        let agent = memory.gpu_job_agent();
        fixture.vault.start_claimed_gpu_job(
            UnitJobStart {
                actor: GpuJobActor::Agent(&agent),
                offer: &self.offer,
                quote,
            },
            key,
            &self.permits,
            &self.connector,
            at_ms,
        )
    }
}

impl Fixture {
    fn lead_arm(&self, lead: Agent, occupied_secs: u64) -> ExperimentArm {
        let arm = self.lane(
            Roles {
                leads: vec![lead.grant],
                ..Roles::default()
            },
            Track::Demand,
            1,
        );
        self.answer(&arm, NOW_MS, occupied_secs);
        arm
    }

    fn unit_request(
        &self,
        ask: &UnitReserveRequest,
        view: &UnitView,
        at_ms: u64,
    ) -> (ClaimKey, GpuJobRequest) {
        assert_eq!(view.state, "claimed");
        let key = ClaimKey::of(ask.arm, ask.rung, &ask.unit_key, ask.attempt);
        let request = self
            .vault
            .unit_job_request(&key, at_ms)
            .expect("read job request")
            .expect("the claim has not started");
        assert_eq!(request.job_type, "pinned_workload");
        assert_eq!(request.image, ask.workload);
        assert_eq!(request.maximum_secs, Some(ask.secs));
        assert_eq!(
            request.inputs["machine"].as_str(),
            Some(self.machine.to_hex().as_str())
        );
        (key, request)
    }

    fn allocation_room(&self, claim: &UnitClaim) -> u64 {
        let txn = read_txn(&self.vault).expect("read snapshot");
        let period = stored_period_in_txn(&self.vault, &txn, &claim.line, claim.period)
            .expect("read period")
            .expect("the claim's period");
        allocation_standing_in_txn(
            &self.vault,
            &txn,
            &period.allocation.allocation(gpu_seconds()),
            &[self.machine],
        )
        .expect("read allocation standing")
        .room()
    }

    fn lead_with_gpu_cancel(&self) -> Agent {
        let actor = self
            .vault
            .ensure_agent_principal("gpu-cancel-lead")
            .expect("named agent principal");
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            [
                "read",
                ARMS_UNITS_RESERVE_VERB,
                ARMS_UNITS_CANCEL_VERB,
                GpuJobVerb::Cancel.name(),
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent: actor,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: Default::default(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .expect("mint the lead's Grant with generic GPU cancel");
        assert!(minted.grant.confers);
        Agent {
            actor,
            grant: minted.grant.grant_ref,
        }
    }
}

fn assert_released(claim: &UnitClaim, reason: &str, at_ms: u64) {
    let ClaimState::Ended(terminal) = &claim.state else {
        panic!("expected released claim: {claim:?}");
    };
    assert_eq!(terminal.end, UnitEnd::Released(reason.to_owned()));
    assert_eq!(terminal.charged_secs, 0);
    assert_eq!(terminal.ended_at_ms, at_ms);
}

/// T13: both a provider refusal and a start-gate refusal return the hold once.
#[test]
fn a_refused_start_returns_its_draws_once() {
    {
        let fixture = fixture();
        let lead = fixture.agent("lead");
        let arm = fixture.lead_arm(lead, OCCUPIED_SECS);
        let ask = fixture.ask(&arm, "provider-refusal", LAST_UNIT_SECS, Some(lead));
        let first = fixture
            .reserve(Some(lead), &ask, NOW_MS)
            .expect("claim the last room");
        assert_eq!(first.room_left_secs, Some(0));
        let reason = "fixture provider refused create";
        let jobs = UnitJobs::new(Some(reason));
        let (key, quote) = jobs.quote(&fixture, &ask, &first, NOW_MS);

        let held = jobs
            .start(&fixture, lead, &key, &quote, NOW_MS)
            .expect("provider refusal returns a held job");
        assert_eq!(held.id, first.job);
        assert_eq!(held.claim, Some(key));
        assert_eq!(
            held.state,
            GpuJobState::Held {
                reason: reason.to_owned()
            }
        );
        assert_eq!(
            fixture
                .vault
                .gpu_job(&first.job)
                .expect("read held job")
                .as_ref(),
            Some(&held)
        );
        let rows = fixture.claims(&arm, 1);
        let ended = only_claim(&rows);
        assert_eq!(ended.key(), key);
        assert_released(ended, reason, NOW_MS);
        assert_eq!(fixture.allocation_room(ended), ask.secs);

        let next = UnitReserveRequest {
            intent_key: "provider-refusal-attempt-two".to_owned(),
            attempt: 2,
            ..ask
        };
        let replacement = fixture
            .reserve(Some(lead), &next, NOW_MS)
            .expect("the full ask fits again");
        assert_eq!(replacement.state, "claimed");
        assert_ne!(replacement.job, first.job);
        assert_eq!(replacement.room_left_secs, first.room_left_secs);
        assert_eq!(replacement.draws, first.draws);

        let before_replay = fixture.claims(&arm, 1);
        let report = UnitEndReport::Refused {
            reason: reason.to_owned(),
        };
        let replay = fixture
            .vault
            .with_write_txn(|txn| {
                settle_unit_in_txn(&fixture.vault, txn, &key, &first.job, &report, NOW_MS + 1)
            })
            .expect("settlement transaction")
            .expect("same refusal replays");
        assert!(replay.replayed);
        assert_eq!(&replay.claim, ended);
        assert_eq!(fixture.claims(&arm, 1), before_replay);
        assert_eq!(
            Some(fixture.allocation_room(ended)),
            replacement.room_left_secs
        );
        assert_eq!(jobs.creates(), 1);
    }

    {
        let fixture = fixture();
        let lead = fixture.agent("lead");
        let arm = fixture.lead_arm(lead, OCCUPIED_SECS);
        let ask = fixture.ask(&arm, "gate-refusal", LAST_UNIT_SECS, Some(lead));
        let view = fixture
            .reserve(Some(lead), &ask, NOW_MS)
            .expect("claim the last room");
        assert_eq!(view.room_left_secs, Some(0));
        let jobs = UnitJobs::new(None);
        let (key, mut request) = fixture.unit_request(&ask, &view, NOW_MS);
        request.maximum_secs = Some(ask.secs - 1);
        let quote = jobs
            .offer
            .quote_for(view.job, &request, ask.secs, NOW_MS)
            .expect("quote with a smaller maximum");

        let refused = jobs.start(&fixture, lead, &key, &quote, NOW_MS);
        assert!(
            matches!(
                refused,
                Err(GpuJobError::LineManaged(LineStartRefused::ClaimMismatch(_)))
            ),
            "{refused:?}"
        );
        let rows = fixture.claims(&arm, 1);
        let ended = only_claim(&rows);
        assert_eq!(ended.key(), key);
        assert_released(ended, "claim_mismatch", NOW_MS);
        assert_eq!(fixture.allocation_room(ended), ask.secs);
        let repeated = jobs.start(&fixture, lead, &key, &quote, NOW_MS + 1);
        assert!(
            matches!(
                repeated,
                Err(GpuJobError::LineManaged(LineStartRefused::ClaimNotClaimed))
            ),
            "{repeated:?}"
        );
        assert_eq!(fixture.claims(&arm, 1), rows);
        assert_eq!(fixture.allocation_room(ended), ask.secs);
        assert!(
            fixture
                .vault
                .gpu_job(&view.job)
                .expect("read job row")
                .is_none()
        );
        assert_eq!(jobs.creates(), 0);
    }
}

/// T14: retrying the logical attempt cannot start its job a second time.
#[test]
fn a_reserve_retried_after_a_lost_answer_starts_one_job() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let ask = fixture.ask(&arm, "same-started-attempt", 60, Some(lead));
    let view = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("first reserve");
    assert!(!view.replayed);
    let jobs = UnitJobs::new(None);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    let job = jobs
        .start(&fixture, lead, &key, &quote, NOW_MS)
        .expect("first start");
    let stored = fixture
        .vault
        .gpu_job(&view.job)
        .expect("read job row")
        .expect("start writes its job row");
    assert_eq!(stored, job);
    assert_eq!(stored.state, GpuJobState::Running);
    assert_eq!(stored.claim, Some(key));
    assert_eq!(stored.started_by, Some(lead.actor));
    let rows = fixture.claims(&arm, 1);
    let claim = only_claim(&rows);
    assert_eq!(claim.key(), key);
    assert_eq!(claim.id, view.job);
    assert_eq!(claim.state, ClaimState::Started);
    assert_eq!(jobs.creates(), 1);

    let retry = UnitReserveRequest {
        intent_key: "new-intent-after-started-answer-lost".to_owned(),
        ..ask
    };
    let again = fixture
        .reserve(Some(lead), &retry, NOW_MS)
        .expect("same logical attempt replays");
    assert!(again.replayed);
    assert_eq!(again.job, view.job);
    assert_eq!(again.state, "started");
    let repeated = jobs.start(&fixture, lead, &key, &quote, NOW_MS);
    assert!(
        matches!(
            repeated,
            Err(GpuJobError::LineManaged(LineStartRefused::ClaimNotClaimed))
        ),
        "{repeated:?}"
    );
    assert_eq!(fixture.claims(&arm, 1), rows);
    assert_eq!(
        fixture.vault.gpu_jobs().expect("read GPU jobs"),
        vec![stored]
    );
    assert_eq!(jobs.creates(), 1);
}

/// T46: even the owner needs the unit door to start on a line-managed offer.
#[test]
fn a_start_on_a_line_managed_offer_without_a_claim_is_refused() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let jobs = UnitJobs::new(None);
    let request = GpuJobRequest {
        job_type: "fine-tune".to_owned(),
        image: "fixture-image".to_owned(),
        maximum_secs: Some(60),
        inputs: serde_json::Value::Null,
    };
    let quote = jobs
        .offer
        .quote(&request, None, 60, NOW_MS)
        .expect("plain quote");
    let receipts = Arc::new(MemoryReceipts::default());
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: quote.units,
        reserve_units: quote.units,
        unit: quote.unit.clone(),
    })
    .with_connector(OFFER.to_owned());
    let admission = RunAdmission::new(
        GpuJob::admission_ref_of(&quote.job),
        declaration,
        None,
        receipts.clone(),
    );
    let plain = GpuJobStart {
        actor: GpuJobActor::Owner(&fixture.owner_proof),
        offer: &jobs.offer,
        quote: &quote,
        resume: None,
        admission: &admission,
    };
    let refused = fixture
        .vault
        .start_gpu_job(plain, &jobs.permits, &jobs.connector, NOW_MS);
    assert!(
        matches!(
            refused,
            Err(GpuJobError::LineManaged(LineStartRefused::OfferLineManaged))
        ),
        "{refused:?}"
    );
    assert!(
        fixture
            .vault
            .gpu_job(&quote.job)
            .expect("read job row")
            .is_none()
    );
    assert_eq!(jobs.creates(), 0);

    // Make a resume offer in memory: no stored GPU job, provider call, or real stop.
    let mut maximum = JobMaximum::start(
        quote.job.to_hex(),
        DeclaredMaximum {
            units: quote.maximum_secs,
            unit: LeaseUnit::new("seconds").expect("unit"),
        },
        Some(MaximumShown { at_ms: NOW_MS }),
    )
    .expect("shown maximum");
    let _ = maximum.record_usage(quote.maximum_secs);
    assert!(maximum.confirm_warning());
    maximum.checkpoint(CheckpointRef("fixture-checkpoint".to_owned()));
    let resume = maximum.stop_at_maximum().expect("in-memory stop").resume;
    let refused = fixture.vault.start_gpu_job(
        GpuJobStart {
            resume: Some(&resume),
            ..plain
        },
        &jobs.permits,
        &jobs.connector,
        NOW_MS,
    );
    assert!(
        matches!(
            refused,
            Err(GpuJobError::LineManaged(
                LineStartRefused::ResumeLineManaged
            ))
        ),
        "{refused:?}"
    );
    assert!(fixture.vault.gpu_jobs().expect("read GPU jobs").is_empty());
    assert!(fixture.claims(&arm, 1).is_empty());
    assert!(
        receipts.rows().is_empty(),
        "the plain starts never reached paid admission"
    );
    assert_eq!(jobs.creates(), 0);

    let (memory, _) = fixture.caller(Some(lead));
    let denied = memory
        .gpu_job_admits(None, GpuJobVerb::Start)
        .expect_err("the lead has no generic start Grant");
    assert_eq!(denied.code, MEMORY_CODE_FORBIDDEN);
    let ask = fixture.ask(&arm, "start-through-claim", 60, Some(lead));
    let view = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("the lead can reserve its unit");
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    let job = jobs
        .start(&fixture, lead, &key, &quote, NOW_MS)
        .expect("the claim admits the lead's job");
    assert_eq!(job.state, GpuJobState::Running);
    assert_eq!(job.claim, Some(key));
    let rows = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&rows).id, job.id);
    assert_eq!(only_claim(&rows).state, ClaimState::Started);
    assert_eq!(jobs.creates(), 1);
}

/// T47: custody can beat start, but cannot release a job that already started.
#[test]
fn a_released_claim_can_no_longer_start() {
    let after_custody = NOW_MS + BudgetPolicy::default().claim_custody_secs * 1_000 + 1;
    {
        let fixture = fixture();
        let lead = fixture.agent("lead");
        let arm = fixture.lead_arm(lead, 0);
        let ask = fixture.ask(&arm, "custody-wins", 60, Some(lead));
        let view = fixture
            .reserve(Some(lead), &ask, NOW_MS)
            .expect("reserve before custody lapses");
        let jobs = UnitJobs::new(None);
        let (key, quote) = jobs.quote(&fixture, &ask, &view, after_custody);
        let refused = jobs.start(&fixture, lead, &key, &quote, after_custody);
        assert!(
            matches!(
                refused,
                Err(GpuJobError::LineManaged(LineStartRefused::ClaimReleased))
            ),
            "{refused:?}"
        );
        let rows = fixture.claims(&arm, 1);
        let claim = only_claim(&rows);
        assert_eq!(claim.key(), key);
        assert_released(claim, "custody_lapsed", after_custody);
        assert!(
            fixture
                .vault
                .gpu_job(&view.job)
                .expect("read job row")
                .is_none()
        );
        assert_eq!(jobs.creates(), 0);
    }

    {
        let fixture = fixture();
        let lead = fixture.agent("lead");
        let arm = fixture.lead_arm(lead, 0);
        let ask = fixture.ask(&arm, "start-wins", 60, Some(lead));
        let view = fixture
            .reserve(Some(lead), &ask, NOW_MS)
            .expect("first attempt");
        let jobs = UnitJobs::new(None);
        let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
        let job = jobs
            .start(&fixture, lead, &key, &quote, NOW_MS)
            .expect("start before custody lapses");
        assert_eq!(job.state, GpuJobState::Running);
        let started = fixture.claims(&arm, 1);
        assert_eq!(only_claim(&started).state, ClaimState::Started);
        let next = UnitReserveRequest {
            intent_key: "started-attempt-two".to_owned(),
            attempt: 2,
            ..ask
        };
        refused_as(
            fixture.reserve(Some(lead), &next, after_custody),
            MEMORY_CODE_INVALID_STATE,
            "attempt_open:",
        );
        assert_eq!(fixture.claims(&arm, 1), started);
        assert_eq!(jobs.creates(), 1);

        let ask = fixture.ask(&arm, "withdrawn-before-start", 60, Some(lead));
        let view = fixture
            .reserve(Some(lead), &ask, after_custody)
            .expect("reserve another unit");
        let (key, quote) = jobs.quote(&fixture, &ask, &view, after_custody);
        let UnitCancel::Withdrawn(withdrawn) = fixture
            .cancel_outcome(Some(lead), &ask, after_custody)
            .expect("withdraw the unstarted claim")
        else {
            panic!("an unstarted unit must withdraw");
        };
        assert_eq!(withdrawn.job, view.job);
        let rows = fixture.claims(&arm, 1);
        let claim = rows
            .iter()
            .find(|claim| claim.key() == key)
            .expect("withdrawn claim row");
        assert_released(claim, "withdrawn", after_custody);
        let refused = jobs.start(&fixture, lead, &key, &quote, after_custody);
        assert!(
            matches!(
                refused,
                Err(GpuJobError::LineManaged(LineStartRefused::ClaimNotClaimed))
            ),
            "{refused:?}"
        );
        assert_eq!(fixture.claims(&arm, 1), rows);
        assert!(
            fixture
                .vault
                .gpu_job(&view.job)
                .expect("read job row")
                .is_none()
        );
        assert_eq!(jobs.creates(), 1);
    }
}

#[test]
fn a_started_units_cancel_ends_its_job_through_the_unit_door() {
    let fixture = fixture();
    let lead = fixture.lead_with_gpu_cancel();
    let arm = fixture.lead_arm(lead, 0);
    let ask = fixture.ask(&arm, "cancel-started-unit", 60, Some(lead));
    let view = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("reserve unit");
    let reserved_rows = fixture.claims(&arm, 1);
    let room_before_reserve = fixture.allocation_room(only_claim(&reserved_rows)) + ask.secs;
    let jobs = UnitJobs::new(None);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    let live = jobs
        .start(&fixture, lead, &key, &quote, NOW_MS)
        .expect("start unit");
    assert_eq!(live.state, GpuJobState::Running);
    let rows = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&rows).state, ClaimState::Started);

    let (memory, _) = fixture.caller(Some(lead));
    memory
        .gpu_job_admits(None, GpuJobVerb::Cancel)
        .expect("the lead has a generic cancel Grant");
    let agent = memory.gpu_job_agent();
    let refused = fixture.vault.cancel_gpu_job(
        GpuJobActor::Agent(&agent),
        &view.job,
        &jobs.permits,
        &jobs.connector,
        NOW_MS,
    );
    let Err(GpuJobError::Caller(error)) = refused else {
        panic!("generic cancel of a unit's job must be refused: {refused:?}");
    };
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    assert!(error.message.contains(ARMS_UNITS_CANCEL_VERB), "{error:?}");
    assert_eq!(
        fixture
            .vault
            .gpu_job(&view.job)
            .expect("read live job")
            .as_ref(),
        Some(&live)
    );
    assert_eq!(fixture.claims(&arm, 1), rows);
    assert_eq!(jobs.connector.terminations.load(Ordering::Relaxed), 0);

    let UnitCancel::JobStarted(token) = fixture
        .cancel_outcome(Some(lead), &ask, NOW_MS)
        .expect("the scoped unit cancel admits its reserver")
    else {
        panic!("expected a started unit's cancel token");
    };
    assert_eq!(token.job(), view.job);
    assert_eq!(token.view().state, "started");
    let ended = fixture
        .vault
        .cancel_unit_gpu_job(token, &jobs.permits, &jobs.connector, NOW_MS)
        .expect("the unit door ends the job");
    assert_eq!(ended.id, view.job);
    assert_eq!(ended.claim, Some(key));
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );
    assert_eq!(
        fixture
            .vault
            .gpu_job(&view.job)
            .expect("read ended job")
            .as_ref(),
        Some(&ended)
    );
    let rows = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&rows).key(), key);
    assert_eq!(jobs.connector.terminations.load(Ordering::Relaxed), 1);
    assert_eq!(jobs.creates(), 1);
    let claim = only_claim(&rows);
    let terminal = unit_terminal(claim);
    assert_eq!(terminal.end, UnitEnd::Settled);
    assert_eq!(terminal.charged_secs, 0);
    assert_eq!(terminal.node_end.as_deref(), Some("stopped"));
    assert_eq!(fixture.allocation_room(claim), room_before_reserve);
}

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Mutex;

use oneiron::experiment_arm::ArmEvidenceDigest;
use oneiron::gpu_job::GpuJobOutput;
use oneiron::gpu_line::UnitTerminal;
use oneiron::job_dispatch::JobObservation;
use oneiron::test_doors::gpu_job::gate_next_end_commit;

fn unit_terminal(claim: &UnitClaim) -> &UnitTerminal {
    let ClaimState::Ended(terminal) = &claim.state else {
        panic!("expected ended claim: {claim:?}");
    };
    terminal
}

fn unit_job_admission(
    quote: &GpuJobQuote,
    limit_units: u64,
) -> (RunAdmission, Arc<MemoryReceipts>) {
    let receipts = Arc::new(MemoryReceipts::default());
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units,
        reserve_units: limit_units,
        unit: quote.unit.clone(),
    })
    .with_connector(OFFER.to_owned());
    let admission = RunAdmission::new(
        GpuJob::admission_ref_of(&quote.job),
        declaration,
        None,
        receipts.clone(),
    );
    (admission, receipts)
}

/// T38: the claim and the job are both terminal even before the end step returns.
#[test]
fn a_crash_between_the_terminal_row_and_the_settle_settles_once_at_restart() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let room_before_reserve = RUNG_1_SECS + MARKET_SECS;
    let ask = fixture.ask(&arm, "end-at-crash", 60, Some(lead));
    let view = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("reserve unit");
    let jobs = UnitJobs::new(None)
        .with_statuses([GpuResourceStatus::Exited { used_secs: 20 }])
        .with_billed_secs(20);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    let job = jobs
        .start(&fixture, lead, &key, &quote, NOW_MS)
        .expect("start unit");
    assert_eq!(job.state, GpuJobState::Running);
    let job_id = job.id;
    let (admission, _) = unit_job_admission(&quote, quote.units);
    let gate = Arc::new(Barrier::new(2));
    gate_next_end_commit(&jobs.permits, job_id, Arc::clone(&gate));
    let ended = GpuJobState::Ended {
        reason: GpuEndReason::Exited,
    };
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            fixture.vault.gpu_job_step(
                &job_id,
                &jobs.offer,
                &admission,
                &jobs.permits,
                &jobs.connector,
                NOW_MS + 1_000,
            )
        });
        gate.wait();
        // Release the worker even when an assertion in the commit window fails.
        let window = catch_unwind(AssertUnwindSafe(|| {
            let stored = fixture
                .vault
                .gpu_job(&job_id)
                .expect("read committed job")
                .expect("committed job row");
            assert_eq!(stored.state, ended);
            let rows = fixture.claims(&arm, 1);
            let claim = only_claim(&rows);
            let terminal = unit_terminal(claim);
            assert_eq!(terminal.end, UnitEnd::Settled);
            assert_eq!(terminal.charged_secs, 20);
            assert_eq!(terminal.node_end.as_deref(), Some("exited(0)"));
            assert_eq!(fixture.allocation_room(claim), room_before_reserve - 20);

            let restarted_permits = GpuJobPermits::new();
            let (restarted_admission, _) = unit_job_admission(&quote, quote.units);
            let calls = jobs.calls();
            assert_eq!(calls, (1, 1, 1));
            let replay = fixture
                .vault
                .gpu_job_step(
                    &job_id,
                    &jobs.offer,
                    &restarted_admission,
                    &restarted_permits,
                    &jobs.connector,
                    NOW_MS + 2_000,
                )
                .expect("step the ended job after restart");
            assert_eq!(replay.state, ended);
            assert_eq!(jobs.calls(), calls);
            let replayed_rows = fixture.claims(&arm, 1);
            assert_eq!(replayed_rows, rows);
            assert_eq!(
                fixture.allocation_room(only_claim(&replayed_rows)),
                room_before_reserve - 20
            );
            rows
        }));
        gate.wait();
        let step = worker.join().expect("step thread").expect("step exits");
        let rows = window.unwrap_or_else(|panic| resume_unwind(panic));
        assert_eq!(step.state, ended);
        assert_eq!(fixture.claims(&arm, 1), rows);
    });
}

/// T39: a new issuer uses the original hold, not its own (unfunded) admission.
#[test]
fn a_restarted_issuer_takes_up_the_original_hold_and_admits_nothing_new() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let room_before_reserve = RUNG_1_SECS + MARKET_SECS;
    let ask = fixture.ask(&arm, "restart-running-unit", 60, Some(lead));
    let view = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("reserve unit");
    let jobs = UnitJobs::new(None)
        .with_statuses([
            GpuResourceStatus::Running {
                used_secs: 10,
                checkpoint: None,
            },
            GpuResourceStatus::Exited { used_secs: 25 },
        ])
        .with_billed_secs(25);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    let job = jobs
        .start(&fixture, lead, &key, &quote, NOW_MS)
        .expect("start on the first host");
    let permits = GpuJobPermits::new();
    let (admission, receipts) = unit_job_admission(&quote, 0);
    let running = fixture
        .vault
        .gpu_job_step(
            &job.id,
            &jobs.offer,
            &admission,
            &permits,
            &jobs.connector,
            NOW_MS + 1_000,
        )
        .expect("step on the restarted host");
    assert_eq!(running.state, GpuJobState::Running);
    assert_eq!(running.used_secs, 10);
    let stored = fixture
        .vault
        .gpu_job(&job.id)
        .expect("read running job")
        .expect("running job row");
    let chunk = stored.chunk().expect("running chunk");
    assert_eq!(
        chunk.idempotency_key,
        job.chunk().expect("original chunk").idempotency_key
    );
    assert!(!chunk.admission_lost);
    assert!(
        !permits.holds(&job.id),
        "the new host holds no chunk permit"
    );
    assert!(receipts.rows().is_empty(), "no paid admission on restart");
    let rows = fixture.claims(&arm, 1);
    let claim = only_claim(&rows);
    assert_eq!(claim.state, ClaimState::Started);
    assert_eq!(fixture.allocation_room(claim), room_before_reserve - 60);

    let ended = fixture
        .vault
        .gpu_job_step(
            &job.id,
            &jobs.offer,
            &admission,
            &permits,
            &jobs.connector,
            NOW_MS + 2_000,
        )
        .expect("finish on the restarted host");
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Exited
        }
    );
    let rows = fixture.claims(&arm, 1);
    let claim = only_claim(&rows);
    let terminal = unit_terminal(claim);
    assert_eq!(terminal.end, UnitEnd::Settled);
    assert_eq!(terminal.charged_secs, 25);
    assert_eq!(fixture.allocation_room(claim), room_before_reserve - 25);
    assert!(
        receipts.rows().is_empty(),
        "the end needs no paid admission either"
    );
    assert_eq!(jobs.creates(), 1);
}

#[test]
fn a_units_end_carries_its_machines_typed_terminal() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let ask = fixture.ask(&arm, "typed-terminal", 60, Some(lead));
    let view = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("reserve unit");
    let jobs = UnitJobs::new(None)
        .with_statuses([GpuResourceStatus::Exited { used_secs: 61 }])
        .with_billed_secs(60);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    let job = jobs
        .start(&fixture, lead, &key, &quote, NOW_MS)
        .expect("start unit");
    let (admission, _) = unit_job_admission(&quote, quote.units);
    let sha256 = "ab".repeat(32);
    fixture
        .vault
        .put_job_observation(&JobObservation {
            key: job.chunk().expect("job chunk").idempotency_key.clone(),
            machine: fixture.machine,
            device_id: None,
            receipt: Vec::new(),
            epoch: "e1".to_owned(),
            seq: 1,
            last_measured_secs: None,
            observed_at_ms: NOW_MS,
            end_seen: None,
            meter: None,
            terminal: Some(GpuJobTerminal {
                end: GpuJobEnd::TimeLimit,
                measured_secs: Some(61),
                billed_secs: 60,
                meter: MeterVerdict::Bracketed { billed_secs: 60 },
                machine: Some(fixture.machine),
                device_id: Some("GPU-fixture-uuid".to_owned()),
                outputs: vec![GpuJobOutput {
                    name: "metrics.json".to_owned(),
                    sha256: sha256.clone(),
                    bytes: 512,
                }],
            }),
            started: false,
        })
        .expect("store the machine's typed terminal");
    fixture
        .vault
        .gpu_job_step(
            &job.id,
            &jobs.offer,
            &admission,
            &jobs.permits,
            &jobs.connector,
            NOW_MS + 1_000,
        )
        .expect("end the unit's job");
    let rows = fixture.claims(&arm, 1);
    let claim = only_claim(&rows);
    let terminal = unit_terminal(claim);
    assert_eq!(terminal.end, UnitEnd::Settled);
    assert_eq!(terminal.charged_secs, 60);
    assert_eq!(terminal.measured_secs, 61);
    assert_eq!(terminal.machine, Some(fixture.machine));
    assert_eq!(terminal.device_id.as_deref(), Some("GPU-fixture-uuid"));
    assert_eq!(terminal.node_end.as_deref(), Some("time_limit"));
    assert_eq!(
        terminal.outputs,
        vec![ArmEvidenceDigest {
            name: "metrics.json".to_owned(),
            sha256,
            bytes: 512,
            rows: None,
        }]
    );
    let room_before_lost_unit = fixture.allocation_room(claim);

    let ask = fixture.ask(&arm, "lost-terminal", 60, Some(lead));
    let at_ms = NOW_MS + 2_000;
    let view = fixture
        .reserve(Some(lead), &ask, at_ms)
        .expect("reserve a distinct unit's first attempt");
    let jobs = UnitJobs::new(None)
        .with_statuses([
            GpuResourceStatus::Running {
                used_secs: 30,
                checkpoint: None,
            },
            GpuResourceStatus::Gone,
        ])
        .with_checkpoint_signal(50)
        .with_billed_secs(30);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, at_ms);
    let job = jobs
        .start(&fixture, lead, &key, &quote, at_ms)
        .expect("start the second unit");
    let (admission, _) = unit_job_admission(&quote, quote.units);
    let running = fixture
        .vault
        .gpu_job_step(
            &job.id,
            &jobs.offer,
            &admission,
            &jobs.permits,
            &jobs.connector,
            at_ms + 1_000,
        )
        .expect("observe 30 seconds before the machine is lost");
    assert_eq!(running.used_secs, 30);
    let ended = fixture
        .vault
        .gpu_job_step(
            &job.id,
            &jobs.offer,
            &admission,
            &jobs.permits,
            &jobs.connector,
            at_ms + 2_000,
        )
        .expect("end the lost unit's job");
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Gone
        }
    );
    let rows = fixture.claims(&arm, 1);
    let claim = rows
        .iter()
        .find(|claim| claim.key() == key)
        .expect("lost unit claim");
    let terminal = unit_terminal(claim);
    assert_eq!(terminal.end, UnitEnd::BoxLost);
    assert_eq!(terminal.charged_secs, 0);
    assert_eq!(terminal.lost_secs, 30);
    assert_eq!(fixture.allocation_room(claim), room_before_lost_unit);
}

#[test]
fn a_written_off_units_job_ends_its_claim_in_the_same_write() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let ask = fixture.ask(&arm, "written-off-unit", 60, Some(lead));
    let view = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("reserve unit");
    let reserved_rows = fixture.claims(&arm, 1);
    let room_before_reserve = fixture.allocation_room(only_claim(&reserved_rows)) + ask.secs;
    let jobs = UnitJobs::new(None);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    let live = jobs
        .start(&fixture, lead, &key, &quote, NOW_MS)
        .expect("start unit");
    assert_eq!(live.state, GpuJobState::Running);
    assert_eq!(
        only_claim(&fixture.claims(&arm, 1)).state,
        ClaimState::Started
    );

    let written = fixture
        .vault
        .write_off_gpu_job(
            &fixture.owner_proof,
            &view.job,
            &jobs.permits,
            &jobs.connector,
            NOW_MS + 1_000,
        )
        .expect("the owner writes off the unit's job");
    assert_eq!(
        written.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Unconfirmed
        }
    );
    assert_eq!(written.claim, Some(key));
    assert_eq!(jobs.connector.write_offs.load(Ordering::Relaxed), 1);
    assert_eq!(jobs.connector.terminations.load(Ordering::Relaxed), 0);
    let rows = fixture.claims(&arm, 1);
    let claim = only_claim(&rows);
    assert_eq!(claim.key(), key);
    let terminal = unit_terminal(claim);
    assert_eq!(
        terminal.end,
        UnitEnd::WrittenOff {
            by: Some(fixture.owner)
        }
    );
    assert_eq!(terminal.charged_secs, 0);
    assert_eq!(terminal.ended_at_ms, NOW_MS + 1_000);
    assert_eq!(fixture.allocation_room(claim), room_before_reserve);
}

use std::cell::Cell;

use oneiron::experiment_arm::unit_order_as;
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::work_order::{
    AttemptOutcome, AttemptRefused, AttemptToMake, CancelWhy, DecidedBy, EndKind, MachineFacts,
    MachineReach, OrderAttemptRef, OrderCharge, OrderHost, OrderState, Room, SlotDecision,
    SlotName, TemplateFact, WorkOrder, WorkOrderRef, attempt_job_id, work_order_cancel_as,
};

fn h3_line_room(fixture: &Fixture, line: EntityId, period: u32) -> u64 {
    let txn = read_txn(&fixture.vault).expect("read snapshot");
    let stored = stored_period_in_txn(&fixture.vault, &txn, &line, period)
        .expect("read period")
        .expect("period minted");
    allocation_standing_in_txn(
        &fixture.vault,
        &txn,
        &stored.allocation.allocation(gpu_seconds()),
        &[fixture.machine],
    )
    .expect("read allocation standing")
    .room()
}

fn h3_machine_facts(machine: EntityId, now_ms: u64) -> MachineFacts {
    MachineFacts {
        machine,
        reach: MachineReach::Answered { at_ms: now_ms },
        enabled: true,
        refusal: None,
        paused: None,
        drained: None,
        templates: Some(vec![TemplateFact {
            name: "fixture-template".to_owned(),
            digest: "a1".repeat(32),
        }]),
        room: Room::default(),
        devices: None,
        window: None,
        keep_headroom_pct: None,
        roles: Vec::new(),
        warm: Vec::new(),
    }
}

struct H3Host<'a> {
    vault: &'a Vault,
    jobs: &'a UnitJobs,
    now_ms: Cell<u64>,
    calls: Cell<usize>,
    skip_start: Cell<bool>,
}

impl OrderHost for H3Host<'_> {
    fn machine_facts(&self, machines: &[EntityId]) -> Vec<MachineFacts> {
        machines
            .iter()
            .map(|machine| h3_machine_facts(*machine, self.now_ms.get()))
            .collect()
    }

    fn make_attempt(&self, attempt: &AttemptToMake<'_>) -> AttemptOutcome {
        self.calls.set(self.calls.get() + 1);
        let now = self.now_ms.get();
        let reserved = self
            .vault
            .reserve_order_attempt(attempt, now)
            .expect("reserve attempt write");
        match reserved {
            Err(AttemptRefused::OrderChanged) => AttemptOutcome::OrderChanged,
            Err(AttemptRefused::Blocked(blocker)) => AttemptOutcome::Refused(vec![blocker]),
            Ok(_) => {
                if self.skip_start.get() {
                    return AttemptOutcome::Made;
                }
                let key = attempt
                    .order
                    .claim_key(attempt.n)
                    .expect("a line order has a claim key");
                let request = self
                    .vault
                    .unit_job_request(&key, now)
                    .expect("read job request")
                    .expect("the claim stands claimed");
                let quote = self
                    .jobs
                    .offer
                    .quote_for(
                        attempt.job,
                        &request,
                        attempt.order.request.maximum_secs,
                        now,
                    )
                    .expect("quote the claim's job");
                let reference = attempt.reference();
                let _ = self.vault.start_claimed_gpu_job(
                    UnitJobStart {
                        actor: GpuJobActor::Order(&reference),
                        offer: &self.jobs.offer,
                        quote: &quote,
                    },
                    &key,
                    &self.jobs.permits,
                    &self.jobs.connector,
                    now,
                );
                AttemptOutcome::Made
            }
        }
    }

    fn stop_attempt(&self, _order: &WorkOrder, _job: &EntityId) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn a_waiting_unit_holds_no_claim_and_no_seconds_until_its_attempt() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let before_room = h3_line_room(&fixture, arm.line, 0);
    let mut ask = fixture.ask(&arm, "waiting-unit", 60, Some(lead));
    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS).expect("order the waiting unit");
    assert!(!ordered.replayed);
    assert!(matches!(ordered.order.state, OrderState::Open { .. }));
    match &ordered.order.charge {
        OrderCharge::Line {
            arm: charge_arm,
            rung,
            line,
            offer,
            purpose,
        } => {
            assert_eq!(*charge_arm, arm.id);
            assert_eq!(*rung, 1);
            assert_eq!(*line, arm.line);
            assert_eq!(offer, OFFER);
            assert_eq!(*purpose, UnitPurpose::Work);
        }
        other => panic!("a waiting unit is charged to its line: {other:?}"),
    }
    assert_eq!(ordered.order.limits.machines, vec![fixture.machine]);
    assert!(ordered.order.attempts.is_empty());
    assert!(fixture.claims(&arm, 1).is_empty());
    assert_eq!(h3_line_room(&fixture, arm.line, 0), before_room);

    let replayed = unit_order_as(&memory, owner, &ask, NOW_MS).expect("same key and ask replays");
    assert!(replayed.replayed);
    assert_eq!(replayed.order.id, ordered.order.id);
    assert!(fixture.claims(&arm, 1).is_empty());

    let mut reserve_same_key = ask.clone();
    reserve_same_key.wait = WaitRule::No;
    let ordered_key = fixture
        .reserve(Some(lead), &reserve_same_key, NOW_MS)
        .expect_err("an ordered key does not reserve");
    assert_eq!(ordered_key.code, MEMORY_CODE_INVALID_STATE);
    assert!(
        ordered_key.message.starts_with("intent_key_ordered"),
        "unexpected message: {:?}",
        ordered_key.message
    );

    let mut no_wait = ask.clone();
    no_wait.intent_key = "waiting-unit-no-wait".to_owned();
    no_wait.wait = WaitRule::No;
    let no_wait_err = unit_order_as(&memory, owner, &no_wait, NOW_MS)
        .expect_err("wait No is the reserve, not an order");
    assert_eq!(no_wait_err.code, MEMORY_CODE_BAD_REQUEST);

    let second = fixture.ask(&arm, "second-unit", 60, Some(lead));
    fixture
        .reserve(Some(lead), &second, NOW_MS)
        .expect("reserve the second unit at once");
    let mut order_reserved_key = second.clone();
    order_reserved_key.wait = WaitRule::Open;
    let reserved_key = unit_order_as(&memory, owner, &order_reserved_key, NOW_MS)
        .expect_err("a reserved key does not order");
    assert_eq!(reserved_key.code, MEMORY_CODE_INVALID_STATE);
    assert!(
        reserved_key.message.starts_with("intent_key_reserved"),
        "unexpected message: {:?}",
        reserved_key.message
    );
}

#[test]
fn a_line_orders_attempt_reserves_its_claim_and_entry_in_one_write_and_starts_under_it() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let before_room = h3_line_room(&fixture, arm.line, 0);
    let mut ask = fixture.ask(&arm, "line-unit", 60, Some(lead));
    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS).expect("order the line unit");
    let jobs = UnitJobs::new(None);
    let host = H3Host {
        vault: &fixture.vault,
        jobs: &jobs,
        now_ms: Cell::new(NOW_MS),
        calls: Cell::new(0),
        skip_start: Cell::new(false),
    };
    fixture
        .vault
        .work_order_pass(&host, NOW_MS)
        .expect("first pass makes the attempt");
    assert_eq!(host.calls.get(), 1);
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    assert!(matches!(order.state, OrderState::Running { attempt: 1 }));
    assert_eq!(order.attempts.len(), 1);
    let attempt = &order.attempts[0];
    let job_id = attempt_job_id(&order.id, 1).expect("attempt job id");
    assert_eq!(attempt.job, job_id);
    assert_eq!(attempt.machine, Some(fixture.machine));
    let key = order.claim_key(1).expect("line order has a claim key");
    let claims = fixture.claims(&arm, 1);
    let claim = only_claim(&claims);
    assert_eq!(claim.key(), key);
    assert_eq!(claim.id, attempt.job);
    assert_eq!(claim.unit_key, order.id.to_hex());
    assert_eq!(claim.attempt, 1);
    assert_eq!(claim.reserved_by, Some(lead.actor));
    assert_eq!(claim.grant, Some(lead.grant));
    assert_eq!(claim.state, ClaimState::Started);
    let job = fixture
        .vault
        .gpu_job(&attempt.job)
        .expect("read job")
        .expect("job row");
    assert_eq!(job.claim, Some(key));
    assert_eq!(job.started_by, Some(lead.actor));
    assert_eq!(h3_line_room(&fixture, arm.line, 0), before_room - ask.secs);

    host.now_ms.set(NOW_MS + 1_000);
    fixture
        .vault
        .work_order_pass(&host, NOW_MS + 1_000)
        .expect("second pass makes nothing");
    assert_eq!(host.calls.get(), 1);
}

#[test]
fn a_line_order_with_no_room_waits_on_line_room_and_holds_nothing() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let before_room = h3_line_room(&fixture, arm.line, 0);
    let before_refusals = fixture.refusals(&arm, 0).len();
    // The room is made small by asking above the rung cap: the attempt's reserve then refuses
    // `over_rung_cap` (a budget refusal), which the order maps onto `line_room`.
    let mut ask = fixture.ask(&arm, "too-big", RUNG_1_SECS + 1, Some(lead));
    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS).expect("order the oversized unit");
    let jobs = UnitJobs::new(None);
    let host = H3Host {
        vault: &fixture.vault,
        jobs: &jobs,
        now_ms: Cell::new(NOW_MS),
        calls: Cell::new(0),
        skip_start: Cell::new(false),
    };
    fixture
        .vault
        .work_order_pass(&host, NOW_MS)
        .expect("pass refuses the attempt");
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    assert!(order.attempts.is_empty());
    let blocked = match &order.state {
        OrderState::Open { blocked, .. } => blocked,
        other => panic!("the order waits open: {other:?}"),
    };
    assert!(
        blocked.iter().any(|on| on.blocker.code() == "line_room"),
        "the order waits on line room: {blocked:?}"
    );
    assert!(fixture.claims(&arm, 1).is_empty());
    assert_eq!(fixture.refusals(&arm, 0).len(), before_refusals);
    assert_eq!(h3_line_room(&fixture, arm.line, 0), before_room);
}

#[test]
fn a_line_attempt_never_started_ends_after_custody_and_the_next_attempt_reserves() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let before_room = h3_line_room(&fixture, arm.line, 0);
    let mut ask = fixture.ask(&arm, "never-started", 60, Some(lead));
    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS).expect("order the unit");
    let jobs = UnitJobs::new(None);
    let host = H3Host {
        vault: &fixture.vault,
        jobs: &jobs,
        now_ms: Cell::new(NOW_MS),
        calls: Cell::new(0),
        skip_start: Cell::new(true),
    };
    fixture
        .vault
        .work_order_pass(&host, NOW_MS)
        .expect("first pass reserves the claim");
    assert_eq!(host.calls.get(), 1);
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    assert!(matches!(order.state, OrderState::Running { attempt: 1 }));
    assert_eq!(order.attempts.len(), 1);
    let job_id = attempt_job_id(&order.id, 1).expect("attempt job id");
    assert_eq!(order.attempts[0].job, job_id);
    let key_one = order.claim_key(1).expect("claim key");
    let claims = fixture.claims(&arm, 1);
    let claim = only_claim(&claims);
    assert_eq!(claim.key(), key_one);
    assert_eq!(claim.state, ClaimState::Claimed);
    assert!(fixture.vault.gpu_job(&job_id).expect("read job").is_none());

    host.now_ms.set(NOW_MS + 1_000);
    fixture
        .vault
        .work_order_pass(&host, NOW_MS + 1_000)
        .expect("second pass inside custody");
    assert_eq!(host.calls.get(), 1);
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    assert!(matches!(order.state, OrderState::Running { attempt: 1 }));
    let claims = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&claims).state, ClaimState::Claimed);

    let period = fixture
        .vault
        .gpu_line_period(&arm.line, 0)
        .expect("read period")
        .expect("period minted");
    let custody_ms = period.policy.claim_custody_secs * 1_000;
    let lapsed_now = NOW_MS + custody_ms + 1_000;
    host.now_ms.set(lapsed_now);
    fixture
        .vault
        .work_order_pass(&host, lapsed_now)
        .expect("third pass past custody");
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    let first = &order.attempts[0];
    let end = first.end.as_ref().expect("the attempt ended");
    assert_eq!(end.kind, EndKind::NeverStarted);
    let claims = fixture.claims(&arm, 1);
    let claim = claims
        .iter()
        .find(|claim| claim.key() == key_one)
        .expect("the first claim");
    let ClaimState::Ended(terminal) = &claim.state else {
        panic!("the first claim ended: {claim:?}");
    };
    assert_eq!(terminal.end, UnitEnd::Released("custody_lapsed".to_owned()));
    assert_eq!(terminal.charged_secs, 0);
    // The AFTER rule retries a never-started attempt after 30 s, so the same pass that ends it
    // does not make attempt 2 yet: the room is back to what it was before.
    assert_eq!(host.calls.get(), 1);
    assert_eq!(order.attempts.len(), 1);
    assert_eq!(h3_line_room(&fixture, arm.line, 0), before_room);

    // Attempt 2 reserves once the retry's backoff has passed, and its job starts.
    let retry_at = order
        .retry_not_before_ms
        .expect("a never-started attempt retries after a backoff");
    let retry_now = retry_at + 1_000;
    host.skip_start.set(false);
    host.now_ms.set(retry_now);
    fixture
        .vault
        .work_order_pass(&host, retry_now)
        .expect("the retry pass makes attempt 2");
    assert_eq!(host.calls.get(), 2);
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    assert!(
        matches!(order.state, OrderState::Running { attempt: 2 }),
        "attempt 2 runs: {:?}",
        order.state
    );
    assert_eq!(order.attempts.len(), 2);
    let key_two = order.claim_key(2).expect("claim key of attempt 2");
    let job_two = attempt_job_id(&order.id, 2).expect("attempt 2 job id");
    assert_eq!(order.attempts[1].job, job_two);
    let claims = fixture.claims(&arm, 1);
    let second = claims
        .iter()
        .find(|claim| claim.key() == key_two)
        .expect("the second claim");
    assert_eq!(second.id, job_two);
    assert_eq!(second.attempt, 2);
    assert_eq!(second.state, ClaimState::Started);
    let job = fixture
        .vault
        .gpu_job(&job_two)
        .expect("read job")
        .expect("attempt 2's job row");
    assert_eq!(job.claim, Some(key_two));
    assert_eq!(h3_line_room(&fixture, arm.line, 0), before_room - ask.secs);
}

#[test]
fn a_cancel_between_the_reserve_and_the_start_releases_the_claim_and_starts_nothing() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let before_room = h3_line_room(&fixture, arm.line, 0);
    let mut ask = fixture.ask(&arm, "cancel-race", 60, Some(lead));
    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS).expect("order the unit");
    let jobs = UnitJobs::new(None);
    let host = H3Host {
        vault: &fixture.vault,
        jobs: &jobs,
        now_ms: Cell::new(NOW_MS),
        calls: Cell::new(0),
        skip_start: Cell::new(true),
    };
    fixture
        .vault
        .work_order_pass(&host, NOW_MS)
        .expect("pass reserves the claim");
    assert_eq!(host.calls.get(), 1);
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    let key = order.claim_key(1).expect("claim key");
    let job_id = attempt_job_id(&order.id, 1).expect("attempt job id");
    let claims = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&claims).state, ClaimState::Claimed);

    // The lead's Grant names only `vault.arms.units.*`, not `vault.jobs.orders.cancel`, so the
    // owner cancels.
    let cancel_at = NOW_MS + 1_000;
    let (owner_memory, owner_proof) = fixture.caller(None);
    work_order_cancel_as(
        &owner_memory,
        owner_proof,
        &WorkOrderRef {
            order: ordered.order.id,
        },
        cancel_at,
    )
    .expect("the owner cancels the running order");

    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    let last = order.last_attempt().expect("one attempt");
    let reference = OrderAttemptRef {
        order: order.id,
        revision: order.revision,
        n: last.n,
        machine: last.machine,
        ranked: last.ranked.clone(),
        placed: last.placed.clone(),
    };
    let request = fixture
        .vault
        .unit_job_request(&key, cancel_at)
        .expect("read job request")
        .expect("the claim stands claimed");
    let quote = jobs
        .offer
        .quote_for(job_id, &request, ask.secs, cancel_at)
        .expect("quote the claim's job");
    let refused = fixture.vault.start_claimed_gpu_job(
        UnitJobStart {
            actor: GpuJobActor::Order(&reference),
            offer: &jobs.offer,
            quote: &quote,
        },
        &key,
        &jobs.permits,
        &jobs.connector,
        cancel_at,
    );
    assert!(
        matches!(
            refused,
            Err(GpuJobError::Order(AttemptRefused::OrderChanged))
        ),
        "a cancelled order does not start: {refused:?}"
    );
    assert!(fixture.vault.gpu_job(&job_id).expect("read job").is_none());
    let claims = fixture.claims(&arm, 1);
    let claim = only_claim(&claims);
    let ClaimState::Ended(terminal) = &claim.state else {
        panic!("the claim was released: {claim:?}");
    };
    assert_eq!(terminal.end, UnitEnd::Released("order_changed".to_owned()));
    assert_eq!(h3_line_room(&fixture, arm.line, 0), before_room);
    assert_eq!(jobs.creates(), 0);

    host.now_ms.set(cancel_at + 1_000);
    fixture
        .vault
        .work_order_pass(&host, cancel_at + 1_000)
        .expect("pass settles the cancel");
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    assert!(matches!(order.state, OrderState::Cancelled { .. }));
}

#[test]
fn an_order_attempt_never_starts_another_callers_claim() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let first = fixture.ask(&arm, "first-claim", 60, Some(lead));
    let view = fixture
        .reserve(Some(lead), &first, NOW_MS)
        .expect("reserve the first claim");
    let key = ClaimKey::of(first.arm, first.rung, &first.unit_key, first.attempt);
    let claims = fixture.claims(&arm, 1);
    let before = only_claim(&claims).clone();
    assert_eq!(before.key(), key);
    assert_eq!(before.state, ClaimState::Claimed);

    let mut second = fixture.ask(&arm, "second-order", 60, Some(lead));
    second.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &second, NOW_MS).expect("order the second unit");
    let other = OrderAttemptRef {
        order: ordered.order.id,
        revision: ordered.order.revision,
        n: 1,
        machine: Some(fixture.machine),
        ranked: SlotDecision {
            slot: SlotName::Rank,
            options: Vec::new(),
            pick: ordered.order.id.to_hex(),
            by: DecidedBy::Rule {
                name: "test".to_owned(),
            },
            why: String::new(),
        },
        placed: SlotDecision {
            slot: SlotName::Place,
            options: vec![fixture.machine.to_hex()],
            pick: fixture.machine.to_hex(),
            by: DecidedBy::Rule {
                name: "test".to_owned(),
            },
            why: String::new(),
        },
    };
    let jobs = UnitJobs::new(None);
    let (quote_key, quote) = jobs.quote(&fixture, &first, &view, NOW_MS);
    assert_eq!(quote_key, key);
    let refused = fixture.vault.start_claimed_gpu_job(
        UnitJobStart {
            actor: GpuJobActor::Order(&other),
            offer: &jobs.offer,
            quote: &quote,
        },
        &key,
        &jobs.permits,
        &jobs.connector,
        NOW_MS,
    );
    assert!(
        matches!(
            refused,
            Err(GpuJobError::LineManaged(LineStartRefused::ClaimMismatch(_)))
        ),
        "another order does not start this claim: {refused:?}"
    );
    let claims = fixture.claims(&arm, 1);
    let after = only_claim(&claims).clone();
    assert_eq!(after, before);
    assert!(fixture.vault.gpu_jobs().expect("read jobs").is_empty());
}

#[test]
fn a_cancel_of_an_order_whose_claim_is_still_claimed_releases_it_at_the_next_pass() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let before_room = h3_line_room(&fixture, arm.line, 0);
    let mut ask = fixture.ask(&arm, "cancel-claimed", 60, Some(lead));
    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS).expect("order the unit");
    let jobs = UnitJobs::new(None);
    let host = H3Host {
        vault: &fixture.vault,
        jobs: &jobs,
        now_ms: Cell::new(NOW_MS),
        calls: Cell::new(0),
        skip_start: Cell::new(true),
    };
    fixture
        .vault
        .work_order_pass(&host, NOW_MS)
        .expect("pass reserves the claim");
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    let key = order.claim_key(1).expect("claim key");
    let job_id = attempt_job_id(&order.id, 1).expect("attempt job id");
    let claims = fixture.claims(&arm, 1);
    assert_eq!(only_claim(&claims).state, ClaimState::Claimed);

    // The lead's Grant names only `vault.arms.units.*`, so the owner cancels.
    let cancel_at = NOW_MS + 1_000;
    let (owner_memory, owner_proof) = fixture.caller(None);
    work_order_cancel_as(
        &owner_memory,
        owner_proof,
        &WorkOrderRef {
            order: ordered.order.id,
        },
        cancel_at,
    )
    .expect("the owner cancels the running order");

    // No start comes: the next pass releases the claim for the cancel and ends the order.
    let pass_at = cancel_at + 1_000;
    host.now_ms.set(pass_at);
    fixture
        .vault
        .work_order_pass(&host, pass_at)
        .expect("pass settles the cancel");
    let claims = fixture.claims(&arm, 1);
    let claim = only_claim(&claims);
    assert_eq!(claim.key(), key);
    let ClaimState::Ended(terminal) = &claim.state else {
        panic!("the claim was released: {claim:?}");
    };
    assert_eq!(
        terminal.end,
        UnitEnd::Released("order_cancelled".to_owned())
    );
    assert_eq!(terminal.charged_secs, 0);
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    assert!(
        matches!(order.state, OrderState::Cancelled { .. }),
        "the order is cancelled: {:?}",
        order.state
    );
    let end = order.attempts[0].end.as_ref().expect("the attempt ended");
    assert_eq!(end.kind, EndKind::NeverStarted);
    assert_eq!(host.calls.get(), 1);
    assert!(fixture.vault.gpu_job(&job_id).expect("read job").is_none());
    assert_eq!(jobs.creates(), 0);
    assert_eq!(h3_line_room(&fixture, arm.line, 0), before_room);
}

#[test]
fn a_line_order_whose_agent_lost_its_lead_role_is_cancelled_authority_ended() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let before_room = h3_line_room(&fixture, arm.line, 0);
    let mut ask = fixture.ask(&arm, "lost-role", 60, Some(lead));
    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS).expect("order the unit");

    // The owner sets the line again with another lead: the ordering agent's Grant still
    // stands, and it holds no role on the line.
    let other = fixture.agent("other-lead");
    let line = fixture
        .vault
        .gpu_line(&arm.line)
        .expect("read line")
        .expect("line row");
    let (owner_memory, owner_proof) = fixture.caller(None);
    owner_memory
        .set_gpu_line(
            owner_proof,
            &GpuLineSetRequest {
                intent_key: "drop-lead".to_owned(),
                project: arm.line,
                policy: GpuLinePolicy {
                    unit: line.unit.clone(),
                    wallet: line.wallet.clone(),
                    offers: line.offers.clone(),
                    machines: line.machines.clone(),
                    leads: vec![other.grant],
                    reviewers: line.reviewers.clone(),
                    planners: line.planners.clone(),
                    period_secs: line.period_secs,
                    period_anchor_ms: line.period_anchor_ms,
                    budget: line.budget.clone(),
                },
            },
            NOW_MS + 500,
        )
        .expect("the owner sets the line with another lead");

    let jobs = UnitJobs::new(None);
    let host = H3Host {
        vault: &fixture.vault,
        jobs: &jobs,
        now_ms: Cell::new(NOW_MS + 1_000),
        calls: Cell::new(0),
        skip_start: Cell::new(false),
    };
    fixture
        .vault
        .work_order_pass(&host, NOW_MS + 1_000)
        .expect("the pass reads the order's authority");
    assert_eq!(host.calls.get(), 0);
    let order = fixture
        .vault
        .work_order(&ordered.order.id)
        .expect("read order")
        .expect("order row");
    assert_eq!(
        order.state,
        OrderState::Cancelled {
            why: CancelWhy::AuthorityEnded
        }
    );
    assert!(order.attempts.is_empty());
    assert!(fixture.claims(&arm, 1).is_empty());
    assert_eq!(h3_line_room(&fixture, arm.line, 0), before_room);
}

// Row RSI-ARM-RESULT: where a unit's returnable outputs land.

use oneiron::blob_artifact::ArtifactCreateRequest;
use oneiron::gpu_job::{GpuJobResultBinding, GpuJobResultFile};
use oneiron::job_workload::WorkloadStarter;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::work_order::ResultBinding;

/// The text of the task a unit's result binding names.
const RESULT_TASK_TEXT: &str = "Read the arm's verdict";
/// The name of the artifact a unit's result binding names.
const RESULT_ARTIFACT_NAME: &str = "verdict.txt";

/// A task and an artifact the owner makes, as a unit's result binding.
fn owner_result_binding(fixture: &Fixture) -> GpuJobResultBinding {
    let human = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let task = human
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from(RESULT_TASK_TEXT),
            None,
            None,
            None,
        ))
        .expect("the owner creates a task")
        .task_ref
        .expect("a landed task");
    let artifact = human
        .artifacts_create(&ArtifactCreateRequest {
            name: RESULT_ARTIFACT_NAME.to_owned(),
            media_type: "text/plain".to_owned(),
            content_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"no verdict yet",
            ),
            run_ref: None,
            made_by: None,
        })
        .expect("the owner uploads the artifact")
        .expect("the artifact's view")
        .artifact_id;
    GpuJobResultBinding {
        artifact,
        task,
        manifest: None,
    }
}

/// `binding` as a quote's `inputs.result`.
fn result_input(binding: GpuJobResultBinding) -> serde_json::Value {
    serde_json::json!({
        "artifact": binding.artifact.to_hex(),
        "task": binding.task.to_hex(),
    })
}

/// RSI-ARM-RESULT: a unit reserved with a result keeps it on its claim, and its job's quote
/// binds it as `inputs.result`, where the issuer's landing reads it. A quote that binds no
/// result is not the claim's: the start refuses it and gives the claim up.
#[test]
fn a_unit_reserved_with_a_result_quotes_it_and_starts_only_with_it() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let binding = owner_result_binding(&fixture);
    let mut ask = fixture.ask(&arm, "bound-unit", 60, Some(lead));
    ask.result = Some(binding);
    let view = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("reserve with a result");
    assert_eq!(only_claim(&fixture.claims(&arm, 1)).result, Some(binding));
    let jobs = UnitJobs::new(None);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    assert_eq!(quote.inputs["result"], result_input(binding));

    let mut unbound = quote.clone();
    unbound
        .inputs
        .as_object_mut()
        .expect("the quote's inputs")
        .remove("result");
    let refused = jobs.start(&fixture, lead, &key, &unbound, NOW_MS);
    assert!(
        matches!(
            refused,
            Err(GpuJobError::LineManaged(LineStartRefused::ClaimMismatch(_)))
        ),
        "{refused:?}"
    );
    assert_eq!(jobs.creates(), 0);

    let next = UnitReserveRequest {
        intent_key: "bound-unit-attempt-2".to_owned(),
        attempt: 2,
        ..ask.clone()
    };
    let view = fixture
        .reserve(Some(lead), &next, NOW_MS)
        .expect("the next attempt reserves");
    let (key, quote) = jobs.quote(&fixture, &next, &view, NOW_MS);
    let job = jobs
        .start(&fixture, lead, &key, &quote, NOW_MS)
        .expect("the claim's own quote starts");
    assert_eq!(job.chunks.len(), 1);
    assert_eq!(job.chunks[0].quote.inputs["result"], result_input(binding));
    assert_eq!(jobs.creates(), 1);
}

/// RSI-ARM-RESULT: an agent binds a unit's result only to rows its own read lane resolves. The
/// reserve and the waiting door refuse any other binding `result_binding_unreadable` and write
/// nothing: no claim, no order. The refusal names no field of the rows the binding names: no
/// artifact name and no task text.
#[test]
fn a_unit_result_on_a_row_the_agent_cannot_read_is_refused_and_writes_nothing() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let readable = owner_result_binding(&fixture);
    let mut ask = fixture.ask(&arm, "unreadable-unit", 60, Some(lead));
    // No row has this id, so no lane resolves it.
    ask.result = Some(GpuJobResultBinding {
        artifact: EntityId::now(),
        task: readable.task,
        manifest: None,
    });
    let reserved = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect_err("the reserve refuses the binding");
    assert!(fixture.claims(&arm, 1).is_empty());

    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS)
        .expect_err("the waiting door refuses the binding");
    for error in [&reserved, &ordered] {
        assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
        assert!(
            error.message.starts_with("result_binding_unreadable"),
            "{error:?}"
        );
        let shown = format!("{error:?}");
        assert!(
            !shown.contains(RESULT_TASK_TEXT) && !shown.contains(RESULT_ARTIFACT_NAME),
            "the refusal names a field of a bound row: {shown}"
        );
    }
    assert!(
        fixture
            .vault
            .work_orders()
            .expect("read the work orders")
            .is_empty()
    );

    ask.wait = WaitRule::No;
    ask.result = Some(readable);
    fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("a binding the agent reads reserves");
}

/// RSI-ARTIFACT-HANDOFF: a unit's result manifest is an `application/json` artifact. The reserve
/// and the waiting door refuse a manifest that is not `result_manifest_not_json` and write
/// nothing: no claim, no order. A JSON manifest the agent reads reserves.
#[test]
fn a_unit_result_manifest_that_is_not_json_is_refused_and_writes_nothing() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let binding = owner_result_binding(&fixture);
    let human = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let manifest = |media_type: &str| {
        human
            .artifacts_create(&ArtifactCreateRequest {
                name: "handoff".to_owned(),
                media_type: media_type.to_owned(),
                content_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"{}",
                ),
                run_ref: None,
                made_by: None,
            })
            .expect("the owner uploads the manifest artifact")
            .expect("the artifact's view")
            .artifact_id
    };
    let mut ask = fixture.ask(&arm, "manifest-unit", 60, Some(lead));
    ask.result = Some(GpuJobResultBinding {
        manifest: Some(manifest("text/plain")),
        ..binding
    });
    let reserved = fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect_err("the reserve refuses a text manifest");
    assert!(fixture.claims(&arm, 1).is_empty());

    ask.wait = WaitRule::Open;
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS)
        .expect_err("the waiting door refuses a text manifest");
    for error in [&reserved, &ordered] {
        assert_eq!(error.code, MEMORY_CODE_INVALID_STATE, "{error:?}");
        assert!(
            error.message.starts_with("result_manifest_not_json"),
            "{error:?}"
        );
    }
    assert!(
        fixture
            .vault
            .work_orders()
            .expect("read the work orders")
            .is_empty()
    );

    ask.wait = WaitRule::No;
    ask.result = Some(GpuJobResultBinding {
        manifest: Some(manifest("application/json")),
        ..binding
    });
    fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("a JSON manifest the agent reads reserves");
}

/// RSI-ARM-RESULT: a unit asked with no result keeps the ask digest a claim had before units
/// could bind one, so a retry of a claim stored then still replays; a result is part of the ask,
/// so the same attempt asked with one is another ask.
#[test]
fn a_unit_without_a_result_keeps_its_ask_digest_and_a_result_is_part_of_the_ask() {
    #[derive(serde::Serialize)]
    struct AskBeforeResults<'a> {
        line: EntityId,
        arm: EntityId,
        rung: u8,
        unit_key: &'a str,
        attempt: u16,
        purpose: UnitPurpose,
        offer: &'a str,
        workload: &'a str,
        machine: Option<EntityId>,
        code_sha: &'a str,
        contract_sha256: &'a str,
        secs: u64,
    }
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let ask = fixture.ask(&arm, "digest-unit", 60, Some(lead));
    fixture
        .reserve(Some(lead), &ask, NOW_MS)
        .expect("reserve with no result");
    let claims = fixture.claims(&arm, 1);
    let claim = only_claim(&claims);
    assert_eq!(claim.result, None);
    let before = IntentAsk::new(
        lead.actor,
        ARMS_UNITS_RESERVE_VERB,
        &ask.intent_key,
        &AskBeforeResults {
            line: ask.line,
            arm: ask.arm,
            rung: ask.rung,
            unit_key: &ask.unit_key,
            attempt: ask.attempt,
            purpose: ask.purpose,
            offer: &ask.offer,
            workload: &ask.workload,
            machine: ask.machine,
            code_sha: &ask.code_sha,
            contract_sha256: &ask.contract_sha256,
            secs: ask.secs,
        },
    )
    .expect("frame the ask as it was before results");
    assert_eq!(claim.ask_digest, before.ask_digest());

    let bound = UnitReserveRequest {
        intent_key: "digest-unit-bound".to_owned(),
        result: Some(owner_result_binding(&fixture)),
        ..ask.clone()
    };
    refused_as(
        fixture.reserve(Some(lead), &bound, NOW_MS),
        MEMORY_CODE_INVALID_STATE,
        "attempt_conflict",
    );
    let again = UnitReserveRequest {
        intent_key: "digest-unit-again".to_owned(),
        ..ask
    };
    assert!(
        fixture
            .reserve(Some(lead), &again, NOW_MS)
            .expect("the same ask replays")
            .replayed
    );
}

/// RSI-ARM-RESULT on row H3's path: a waiting unit's order keeps the result, and its attempt's
/// reserve writes it onto the attempt's claim, so the claim's job binds it.
#[test]
fn a_waiting_unit_carries_its_result_into_its_claim_and_job() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let binding = owner_result_binding(&fixture);
    let mut ask = fixture.ask(&arm, "bound-line-unit", 60, Some(lead));
    ask.wait = WaitRule::Open;
    ask.result = Some(binding);
    let (memory, owner) = fixture.caller(Some(lead));
    let ordered = unit_order_as(&memory, owner, &ask, NOW_MS).expect("order the bound unit");
    assert_eq!(
        ordered.order.result,
        Some(ResultBinding {
            artifact: binding.artifact,
            task: binding.task,
            manifest: None,
        })
    );
    let jobs = UnitJobs::new(None);
    let host = H3Host {
        vault: &fixture.vault,
        jobs: &jobs,
        now_ms: Cell::new(NOW_MS),
        calls: Cell::new(0),
        skip_start: Cell::new(false),
    };
    fixture
        .vault
        .work_order_pass(&host, NOW_MS)
        .expect("the pass makes the attempt");
    assert_eq!(host.calls.get(), 1);
    let claims = fixture.claims(&arm, 1);
    let claim = only_claim(&claims);
    assert_eq!(claim.result, Some(binding));
    assert_eq!(claim.state, ClaimState::Started);
    let job = fixture
        .vault
        .gpu_job(&claim.id)
        .expect("read the job")
        .expect("the claim's job row");
    assert_eq!(job.chunks[0].quote.inputs["result"], result_input(binding));
}

/// RSI-ARM-RESULT: a unit job's landed result names its unit. The proposal's report carries the
/// arm, the rung, the unit key, the attempt and the contract the arm pinned (the referee digest,
/// pass 32 3.6), read from the claim the job row names.
#[test]
fn a_landed_unit_result_names_its_arm_rung_and_contract() {
    let fixture = fixture();
    let lead = fixture.agent("lead");
    let arm = fixture.lead_arm(lead, 0);
    let binding = owner_result_binding(&fixture);
    let mut ask = fixture.ask(&arm, "landed-unit", 60, None);
    ask.result = Some(binding);
    let view = fixture
        .reserve(None, &ask, NOW_MS)
        .expect("the owner reserves a bound unit");
    let jobs = UnitJobs::new(None);
    let (key, quote) = jobs.quote(&fixture, &ask, &view, NOW_MS);
    let job = fixture
        .vault
        .start_claimed_gpu_job(
            UnitJobStart {
                actor: GpuJobActor::Owner(&fixture.owner_proof),
                offer: &jobs.offer,
                quote: &quote,
            },
            &key,
            &jobs.permits,
            &jobs.connector,
            NOW_MS,
        )
        .expect("the owner starts the claim's job");
    let file = GpuJobResultFile {
        key: job.chunks[0].idempotency_key.clone(),
        name: "verdict.txt".to_owned(),
        sha256: "ab".repeat(32),
        bytes: b"pass".to_vec(),
    };
    let landed = fixture
        .vault
        .propose_gpu_job_result(
            job.id,
            Some(WorkloadStarter::Owner(fixture.owner)),
            &binding,
            &file,
            fixture.machine,
            NOW_MS,
        )
        .expect("land the result")
        .expect("the owner's lane holds it");
    assert_eq!(landed.artifact_id, binding.artifact);
    assert_eq!(
        landed.summary["report"]["unit"],
        serde_json::json!({
            "arm": arm.id.to_hex(),
            "rung": 1,
            "unit_key": "landed-unit",
            "attempt": 1,
            "contract_sha256": arm.contract.sha256,
        })
    );
    assert_eq!(
        landed.summary["report"]["job"],
        serde_json::json!(job.id.to_hex())
    );
}
