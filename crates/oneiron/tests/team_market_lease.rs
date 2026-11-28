//! A market's lease unit ([MARKET-SEAT-LEASE-UNIT]; Engine ANSWER
//! MARKET-SEAT-LEASE-UNIT = A, 28 Nov; ARCH-0079 #market: "Patterns are
//! compared at equal lease"). On the stack below this a market's pool and
//! shares are numbers in no unit, and nothing spends a share: a member on a
//! subscription seat and a member the engine prices meet at no common
//! measure. Now:
//!
//! - a market records its unit, GPU seconds, the one unit the engine meters
//!   with a machine-signed end on every harness; terms without a unit encode
//!   as before, and a market row written before the unit reads with none;
//! - each verdict, screen or sealed, spends the seconds its referee run's
//!   end charged from the submitting member's share, as one Spend line in
//!   the verdict's own write; the bounty does not move, a replay spends
//!   nothing again, and a verdict whose evidence did not hold spends nothing;
//! - a member whose share cannot pay is refused the verdict with nothing
//!   written (the market's own ledger rations it), and other members go on;
//! - two seats on other harnesses, the first tenant's agy seat and its
//!   claude-code fallback, hold equal shares and the same work spends the
//!   same seconds from each; the team's result shows the unit and each
//!   member's lease beside its seat.
//!
//! The fixture is `tests/team_market_seat.rs`'s rooted vault, so a member
//! submits through an owner-paired credential, with the sealed referee
//! contract of `tests/team_market_referee.rs`. Unit claims are put through
//! the arm test door, as their writer is the reserve door and the machine's
//! end.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test team_market_lease`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{HostSlipIssuer, MachineRole, PairingPrincipal, PairingSeat};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::experiment_arm::ArmEvidenceDigest;
use oneiron::federation::{Scope, ScopeAxis, WalletRef};
use oneiron::gpu_line::{
    ClaimState, Draw, DrawSource, UnitClaim, UnitEnd, UnitPurpose, UnitTerminal,
};
use oneiron::llm::run_admission::AllocationRef;
use oneiron::team::run::{
    TeamLeaseUnit, TeamMarketInput, TeamMarketModeInput, TeamMarketOutcome, TeamMarketSeat,
    TeamMarketSeatSource, TeamMarketSpend, TeamMarketSubmitInput, TeamMarketVerdictInput,
    TeamMarketVerdictOutcome, TeamRefereeInput,
};
use oneiron::team::{
    LedgerKind, Market, SelfTeamCall, TeamRecordInput, TeamRunAnswer, TeamStartInput, market,
    team_run_binding,
};
use oneiron::test_doors::experiment_arm_rows::put_claim;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).

/// The lease owner this test claims rows as.
const WORKER: &str = "team-market-lease";

/// The run the leader's root attempt serves; its members join it.
const RUN: &str = "run-team-market-lease";

/// The rule a market here records.
const RULE: &str = "suite:granite-eval@4f2a";

/// The harness revision the contract pins.
const COMMIT: &str = "c0dec0dec0dec0dec0dec0dec0dec0dec0dec0de";

/// The referee run's output that holds its verdict.
const VERDICT_OUTPUT: &str = "verdict.json";

/// The bar: not worse than the comparator by more than this, on this many
/// tasks.
const MARGIN: f64 = 0.01;
const MIN_TASKS: u64 = 50;

/// The pool, in GPU seconds, and the bounty's share of it: half, so the two
/// members' shares are exact (1000 x 0.5 / 2 = 250 each, bounty 500).
const POOL: u64 = 1_000;
const BOUNTY_SHARE: f64 = 0.5;
const SHARE: u64 = 250;
const BOUNTY: u64 = 500;

/// The challenge a paired agent signs to prove its slip.
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:team-market-lease";

/// The first tenant's seat and its fallback, as the Orchestrator records
/// them (Engine ACCEPT PLAN-MARKET-SEAT-MODEL-STAMP, condition 5; ANSWER
/// MARKET-SEAT-LEASE-UNIT: L4 uses #10660's two seat names).
fn neon_seat() -> PairingSeat {
    PairingSeat {
        harness: "agy".to_owned(),
        model: "gemini-4-neon-xhigh".to_owned(),
    }
}

fn fallback_seat() -> PairingSeat {
    PairingSeat {
        harness: "claude-code".to_owned(),
        model: "claude-opus-5-5".to_owned(),
    }
}

fn owner_paired(seat: &PairingSeat) -> TeamMarketSeat {
    TeamMarketSeat {
        harness: seat.harness.clone(),
        model: seat.model.clone(),
        source: TeamMarketSeatSource::OwnerPaired,
    }
}

/// A 64-hex digest of one repeated byte.
fn digest(byte: &str) -> String {
    byte.repeat(32)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The sealed prompt cohort, a screen's development cohort, the comparator,
/// the approved workload, and the candidates.
fn sealed_cohort() -> String {
    digest("5e")
}
fn screen_cohort() -> String {
    digest("de")
}
fn comparator() -> String {
    digest("c0")
}
fn workload() -> String {
    digest("ab")
}
fn candidate(n: u8) -> String {
    digest(&format!("{n}{n}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "market lease fixture",
        "1",
        Some("Submit carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// The contract text the owner seals, naming the screen cohort.
fn contract_text() -> String {
    json!({
        "schema": "oneiron.market_referee_contract.v1",
        "comparator": {"name": "granite-base", "sha256": comparator()},
        "cohortSha256": sealed_cohort(),
        "screens": [screen_cohort()],
        "harness": {"commit": COMMIT, "workload": workload()},
        "verdictOutput": VERDICT_OUTPUT,
        "bar": {"metric": "pass_rate", "margin": MARGIN, "minTasks": MIN_TASKS},
    })
    .to_string()
}

/// A passing referee verdict under `contract` for `candidate` on `cohort`.
fn verdict_text(contract: &str, candidate: &str, cohort: &str) -> String {
    json!({
        "schema": "oneiron.market_referee_verdict.v1",
        "contractSha256": contract,
        "cohortSha256": cohort,
        "candidateSha256": candidate,
        "comparatorSha256": comparator(),
        "tasks": 120,
        "score": 0.7,
        "pairedLow": 0.01,
        "perTask": [],
    })
    .to_string()
}

/// The arm the referee's units run under.
fn arm() -> TestResult<EntityId> {
    Ok(EntityId::from_bytes([0x74; 16])?)
}

/// The one place a test claim is built: unit `unit_key` of the referee's
/// arm, which ran `contract`'s harness to a clean exit, whose machine
/// hashed `verdict` as the verdict output, and whose settled end charged
/// `charged` GPU seconds.
fn lease_claim(
    unit_key: &str,
    contract: &str,
    verdict: &str,
    charged: u64,
) -> TestResult<UnitClaim> {
    let secs = 600;
    Ok(UnitClaim {
        id: EntityId::now(),
        arm: arm()?,
        rung: 1,
        unit_key: unit_key.to_owned(),
        attempt: 1,
        line: EntityId::from_bytes([0x75; 16])?,
        family: EntityId::from_bytes([0x76; 16])?,
        period: 0,
        purpose: UnitPurpose::Work,
        workload: workload(),
        machine: None,
        code_sha: COMMIT.to_owned(),
        contract_sha256: contract.to_owned(),
        reserved_secs: secs,
        draws: vec![Draw {
            source: DrawSource::FirstAllowance,
            units: secs,
        }],
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        allocation: AllocationRef {
            id: "gpu-line-0".to_owned(),
            generation: 1,
        },
        grant: None,
        reserved_by: None,
        reserved_at_ms: 1,
        ask_digest: digest("ad"),
        state: ClaimState::Ended(UnitTerminal {
            end: UnitEnd::Settled,
            charged_secs: charged,
            measured_secs: charged,
            lost_secs: 0,
            machine: None,
            device_id: None,
            node_end: Some("exited(0)".to_owned()),
            outputs: vec![ArmEvidenceDigest {
                name: VERDICT_OUTPUT.to_owned(),
                sha256: sha256_hex(verdict.as_bytes()),
                bytes: verdict.len() as u64,
                rows: None,
            }],
            ended_at_ms: 2,
        }),
        revision: 2,
    })
}

/// A rooted vault this process owns, as a serving start leaves it (the
/// host root, the engine's machines, this install's profile, the embedded
/// owner bound under the root), the leader, one worker definition per
/// member, and the leader's root attempt, leased.
struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    leader: EntityId,
    /// The definition each member runs as, in start order.
    workers: [EntityId; 2],
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A started sealed market: its team reference, contract digest and leased
/// members, in start order.
struct Started {
    team: String,
    contract: String,
    members: Vec<AttemptRecord>,
}

fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let (owner, owner_proof) = embedded_owner(&vault)?;
    let now = vault.now_recorded_at();
    let leader = EntityId::from_bytes([0x71; 16])?;
    let workers = [
        EntityId::from_bytes([0x72; 16])?,
        EntityId::from_bytes([0x73; 16])?,
    ];
    for (id, name) in [
        (leader, "fixture.lease.leader"),
        (workers[0], "fixture.lease.worker.one"),
        (workers[1], "fixture.lease.worker.two"),
    ] {
        vault.create_agent_definition_as(
            &owner_proof,
            &id,
            &definition(name),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(leader),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(RUN.to_owned()),
            now,
        })?
    else {
        panic!("the leader dispatches without running a model")
    };
    let leased = claim(&vault, status.attempt.id)?;
    Ok(Fixture {
        vault,
        issuer,
        owner,
        owner_proof,
        leader,
        workers,
        leased,
        _dir: dir,
    })
}

/// Leases `id` to this test's worker. Rows are claimed oldest first, so a
/// row queued before it is claimed past.
fn claim(vault: &Vault, id: AttemptId) -> TestResult<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(row);
        }
    }
    Err("the attempt is ready to claim".into())
}

fn call(
    host: &HostSelfDispatcher<'_>,
    call: SelfTeamCall,
) -> TestResult<Result<TeamRunAnswer, String>> {
    match host.dispatch(SelfCall::Team(call))? {
        SelfDispatchOutcome::Team(result) => Ok(Ok(result.answer)),
        SelfDispatchOutcome::Failed(failed) => Ok(Err(failed.error)),
        other => Err(format!("expected a team answer or a typed failure, got {other:?}").into()),
    }
}

/// A verdict answer's outcome, spend and replay flag.
fn verdict_of(
    answer: Result<TeamRunAnswer, String>,
) -> TestResult<(TeamMarketVerdictOutcome, Option<TeamMarketSpend>, bool)> {
    match answer {
        Ok(TeamRunAnswer::MarketVerdict {
            outcome,
            spend,
            replay,
            ..
        }) => Ok((outcome, spend, replay)),
        other => Err(format!("expected a verdict answer, got {other:?}").into()),
    }
}

fn recorded_market(answer: Result<TeamRunAnswer, String>) -> TestResult<TeamMarketOutcome> {
    match answer {
        Ok(TeamRunAnswer::Recorded {
            market: Some(market),
            ..
        }) => Ok(market),
        other => Err(format!("expected a market receipt, got {other:?}").into()),
    }
}

fn gpu_seconds(charged: u64, left: u64) -> Option<TeamMarketSpend> {
    Some(TeamMarketSpend {
        unit: TeamLeaseUnit::GpuSeconds,
        charged,
        left,
    })
}

/// The Spend lines `agent` posted, in order.
fn spends(market: &Market, agent: &str) -> Vec<u64> {
    market
        .ledger
        .iter()
        .filter(|line| line.entry == LedgerKind::Spend && line.agent.as_deref() == Some(agent))
        .map(|line| line.units)
        .collect()
}

impl Fixture {
    fn host(&self) -> oneiron::Result<HostSelfDispatcher<'_>> {
        HostSelfDispatcher::for_leased_agent_attempt(
            &self.vault,
            WriteActor::new(self.leader, EdgeActorClass::Agent),
            &self.leased,
        )
    }

    /// The owner's sealed contract NOTE: its id and the SHA-256 of its text.
    fn contract_note(&self) -> TestResult<(EntityId, String)> {
        let owner = || WriteActor::new(self.owner, EdgeActorClass::Human);
        let note = self
            .vault
            .create_note("research", &contract_text(), owner())
            .map_err(|error| format!("FIXTURE: the NOTE is written: {error:?}"))?;
        self.vault
            .seal_note(note, owner())
            .map_err(|error| format!("FIXTURE: the NOTE seals: {error:?}"))?;
        Ok((note, sha256_hex(self.vault.note_text(note)?.as_bytes())))
    }

    /// A bounty market start under `key`, one member per worker, on the
    /// sealed contract `note` whose digest is `contract`, with `unit` as the
    /// guest wrote it.
    fn start_json(&self, key: &str, note: EntityId, contract: &str, unit: Option<&str>) -> Value {
        let members: Vec<Value> = self
            .workers
            .iter()
            .zip(["m1", "m2"])
            .map(|(worker, member)| json!({"agent": worker.to_hex(), "intentKey": member}))
            .collect();
        let mut terms = json!({
            "referee": {
                "kind": "holdout",
                "rule": RULE,
                "digest": contract,
                "contract": note.to_hex(),
            },
            "mode": {"kind": "bounty"},
            "pool": POOL,
            "bountyShare": BOUNTY_SHARE,
        });
        if let Some(unit) = unit {
            terms["unit"] = json!(unit);
        }
        json!({
            "pattern": "market",
            "intentKey": key,
            "members": members,
            "tournament": null,
            "market": terms,
        })
    }

    /// A sealed market under `key`, with `unit` as the guest wrote it, its
    /// members leased in start order.
    fn start(&self, key: &str, unit: Option<&str>) -> TestResult<Started> {
        let (note, contract) = self.contract_note()?;
        let input: TeamStartInput =
            serde_json::from_value(self.start_json(key, note, &contract, unit))?;
        if let Err(code) = call(&self.host()?, SelfTeamCall::Start(input))? {
            return Err(format!("the market start is refused: {code}").into());
        }
        let team = format!("team:{}:{key}", hex(self.leased.id.as_bytes()));
        let queued = team_run_binding(&self.vault, self.leased.id, &team)?
            .ok_or("the start kept its members")?
            .members;
        let members = queued
            .into_iter()
            .map(|id| claim(&self.vault, id))
            .collect::<TestResult<Vec<_>>>()?;
        Ok(Started {
            team,
            contract,
            members,
        })
    }

    /// `holder` paired as class `agent` on the owner's link declaring
    /// `seat`, redeemed with a fresh connection key and proven: the slip's
    /// id.
    fn pair(&self, holder: EntityId, seat: PairingSeat, binding_seed: u8) -> TestResult<[u8; 32]> {
        let holder_ref = holder.to_hex();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        let link = self.vault.issue_owner_pairing_link(
            &self.issuer,
            &self.owner_proof,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder_ref.clone()),
                actor_class: Some("agent".to_owned()),
                seat: Some(seat),
                ..PairingPrincipal::default()
            },
        )?;
        let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
        let binding_key = signing_key.verifying_key().to_bytes();
        let transcript = oneiron::authority::pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder_ref,
            link.pin.as_ref(),
        )?;
        let slip = self.vault.redeem_pairing_link(
            &self.issuer,
            &link.code,
            &holder_ref,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )?;
        let signature = signing_key
            .sign(&slip.binding_transcript(REQUEST_CHALLENGE)?)
            .to_bytes();
        self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &slip,
            REQUEST_CHALLENGE,
            &signature,
        )?;
        Ok(slip.claims.slip_id)
    }

    /// Member `index`'s submission of `candidate`, through the attached
    /// credential `slip` when one is named, else by its host.
    fn submit(
        &self,
        started: &Started,
        index: usize,
        slip: Option<[u8; 32]>,
        submission: &str,
        candidate: &str,
    ) -> TestResult {
        let input: TeamMarketSubmitInput = serde_json::from_value(json!({
            "teamRef": started.team,
            "submissionRef": submission,
            "candidateSha256": candidate,
        }))?;
        let host = HostSelfDispatcher::for_leased_agent_attempt(
            &self.vault,
            WriteActor::new(self.workers[index], EdgeActorClass::Agent),
            &started.members[index],
        )?;
        let host = match slip {
            Some(slip_id) => host.with_live_run_slip(slip_id),
            None => host,
        };
        match call(&host, SelfTeamCall::MarketSubmit(input))? {
            Ok(_) => Ok(()),
            Err(code) => Err(format!("the submission is refused: {code}").into()),
        }
    }

    /// Puts unit `unit_key`, charged `charged` GPU seconds, whose verdict
    /// output is `verdict`, and has the leader relay that verdict for
    /// `submission`.
    fn relay(
        &self,
        started: &Started,
        submission: &str,
        unit_key: &str,
        verdict: &str,
        charged: u64,
    ) -> TestResult<Result<TeamRunAnswer, String>> {
        put_claim(
            &self.vault,
            &lease_claim(unit_key, &started.contract, verdict, charged)?,
        )?;
        self.relay_again(started, submission, unit_key, verdict)
    }

    /// The leader's relay of `verdict` for `submission` from the unit
    /// `unit_key` already put.
    fn relay_again(
        &self,
        started: &Started,
        submission: &str,
        unit_key: &str,
        verdict: &str,
    ) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamMarketVerdictInput = serde_json::from_value(json!({
            "teamRef": started.team,
            "submissionRef": submission,
            "claim": {"arm": arm()?.to_hex(), "rung": 1, "unitKey": unit_key, "attempt": 1},
            "verdict": verdict,
        }))?;
        call(&self.host()?, SelfTeamCall::MarketVerdict(input))
    }

    /// The leader's record of `team`: it closes the market on its referee.
    fn record(&self, team: &str) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamRecordInput = serde_json::from_value(json!({
            "teamRef": team,
            "members": [],
            "axis": "diverge",
            "decidedBy": {"kind": "referee", "rule": RULE, "signedAt": 0},
            "roles": null,
            "coverage": null,
        }))?;
        call(&self.host()?, SelfTeamCall::Record(input))
    }

    fn market(&self, team: &str) -> TestResult<Market> {
        Ok(market(&self.vault, team)?.ok_or("the market is recorded")?)
    }
}

/// `TeamMarketInput` as #10660 encodes it, frozen: the terms every planned
/// ask with a market digested in before `unit` existed.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MainTeamMarketInput {
    referee: TeamRefereeInput,
    mode: TeamMarketModeInput,
    pool: u64,
    bounty_share: Option<f64>,
    protected: Vec<String>,
}

#[test]
fn the_pool_names_its_unit_and_a_market_before_it_states_none() -> TestResult {
    let f = fixture()?;
    let unstated = f.start("unstated", None)?;
    let stated = f.start("stated", Some("gpu_seconds"))?;
    let (note, contract) = f.contract_note()?;
    let other_unit = f.start_json("turns", note, &contract, Some("turns"));

    let kept = f.market(&unstated.team)?;
    assert_eq!(
        kept.unit,
        Some(TeamLeaseUnit::GpuSeconds),
        "terms without a unit open in GPU seconds"
    );
    assert_eq!(
        f.market(&stated.team)?.unit,
        Some(TeamLeaseUnit::GpuSeconds)
    );
    assert!(
        serde_json::from_value::<TeamStartInput>(other_unit).is_err(),
        "GPU seconds is the market's only unit"
    );
    assert_eq!(
        kept.ledger[0].entry,
        LedgerKind::Mint,
        "the pool is minted first"
    );
    assert_eq!(kept.ledger[0].units, POOL);
    assert_eq!(
        kept.participants
            .values()
            .map(|member| member.share)
            .collect::<Vec<_>>(),
        vec![SHARE, SHARE],
        "equal shares of the pool less the bounty"
    );
    assert_eq!(kept.bounty, BOUNTY);

    // A market row written before the unit reads with none.
    let mut row: RmpValue = rmp_serde::from_slice(&rmp_serde::to_vec_named(&kept)?)?;
    let RmpValue::Map(fields) = &mut row else {
        return Err("a market row is a named map".into());
    };
    let before = fields.len();
    fields.retain(|(name, _)| name.as_str() != Some("unit"));
    assert_eq!(fields.len() + 1, before, "the row held its unit");
    let old: Market = rmp_serde::from_slice(&rmp_serde::to_vec_named(&row)?)?;
    assert_eq!(old.unit, None, "an old market states no unit");
    assert_eq!(
        Market {
            unit: kept.unit,
            ..old
        },
        kept,
        "and reads as before otherwise"
    );

    // Terms without a unit encode as before, so a planned ask's digest
    // stays the same.
    let terms: TeamMarketInput =
        serde_json::from_value(f.start_json("bytes", note, &contract, None)["market"].clone())?;
    let frozen = MainTeamMarketInput {
        referee: terms.referee.clone(),
        mode: terms.mode,
        pool: terms.pool,
        bounty_share: terms.bounty_share,
        protected: terms.protected.clone(),
    };
    assert_eq!(
        rmp_serde::to_vec_named(&terms)?,
        rmp_serde::to_vec_named(&frozen)?
    );
    assert_eq!(
        serde_json::to_value(&terms)?,
        serde_json::to_value(&frozen)?
    );
    Ok(())
}

#[test]
fn a_verdict_spends_its_runs_gpu_seconds_and_the_bounty_stays() -> TestResult {
    let f = fixture()?;
    let started = f.start("spends", None)?;
    f.submit(&started, 0, None, "m1-a", &candidate(1))?;
    f.submit(&started, 1, None, "m2-a", &candidate(2))?;
    let screen = verdict_text(&started.contract, &candidate(1), &screen_cohort());
    let sealed = verdict_text(&started.contract, &candidate(1), &sealed_cohort());

    let screened = verdict_of(f.relay(&started, "m1-a", "screen", &screen, 100)?)?;
    let scored = verdict_of(f.relay(&started, "m1-a", "sealed", &sealed, 120)?)?;
    let replayed = verdict_of(f.relay_again(&started, "m1-a", "sealed", &sealed)?)?;

    assert!(matches!(
        screened,
        (TeamMarketVerdictOutcome::Screened { .. }, _, false)
    ));
    assert_eq!(
        screened.1,
        gpu_seconds(100, SHARE - 100),
        "a screen spends its run's seconds"
    );
    assert!(matches!(
        scored,
        (
            TeamMarketVerdictOutcome::Scored { passed: true, .. },
            _,
            false
        )
    ));
    assert_eq!(
        scored.1,
        gpu_seconds(120, SHARE - 220),
        "so does a sealed verdict"
    );
    assert!(replayed.2, "the same verdict again is a replay");
    assert_eq!(replayed.1, None, "and spends nothing again");
    let kept = f.market(&started.team)?;
    assert_eq!(kept.participants["m1"].spent, 220);
    assert_eq!(spends(&kept, "m1"), vec![100, 120], "one Spend line each");
    assert_eq!(
        kept.participants["m2"].spent, 0,
        "another member's share stays"
    );
    assert_eq!(kept.bounty, BOUNTY, "a spend never moves the bounty");

    // A verdict whose evidence does not hold buys nothing and spends nothing.
    let mut other = lease_claim("other-workload", &started.contract, &sealed, 90)?;
    other.workload = digest("ba");
    put_claim(&f.vault, &other)?;
    let m2 = verdict_text(&started.contract, &candidate(2), &sealed_cohort());
    let invalid = verdict_of(f.relay_again(&started, "m2-a", "other-workload", &m2)?)?;
    assert!(matches!(
        invalid.0,
        TeamMarketVerdictOutcome::Invalid { .. }
    ));
    assert_eq!(invalid.1, None);
    assert_eq!(f.market(&started.team)?.participants["m2"].spent, 0);
    Ok(())
}

#[test]
fn a_member_past_its_share_is_refused_the_verdict_with_nothing_written() -> TestResult {
    let f = fixture()?;
    let started = f.start("refused", None)?;
    f.submit(&started, 0, None, "m1-a", &candidate(1))?;
    f.submit(&started, 1, None, "m2-a", &candidate(2))?;
    let screen = verdict_text(&started.contract, &candidate(1), &screen_cohort());
    let sealed = verdict_text(&started.contract, &candidate(1), &sealed_cohort());
    let screened = verdict_of(f.relay(&started, "m1-a", "screen", &screen, 200)?)?;
    assert_eq!(screened.1, gpu_seconds(200, SHARE - 200));
    let before = f.market(&started.team)?;

    let refused = f.relay(&started, "m1-a", "dear", &sealed, SHARE - 200 + 1)?;

    assert_eq!(
        refused,
        Err("team_market_share_spent".to_owned()),
        "a share that cannot pay is refused the verdict"
    );
    assert_eq!(
        f.market(&started.team)?,
        before,
        "nothing is written: no score, no spend, no Spend line"
    );
    let m2 = verdict_text(&started.contract, &candidate(2), &sealed_cohort());
    let other = verdict_of(f.relay(&started, "m2-a", "m2", &m2, SHARE)?)?;
    assert!(
        matches!(
            other.0,
            TeamMarketVerdictOutcome::Scored { passed: true, .. }
        ),
        "another member goes on: {other:?}"
    );
    assert_eq!(
        other.1,
        gpu_seconds(SHARE, 0),
        "a share pays up to its last second"
    );
    Ok(())
}

#[test]
fn two_seats_on_other_harnesses_meet_at_equal_lease() -> TestResult {
    let f = fixture()?;
    let started = f.start("equal", None)?;
    let neon_slip = f.pair(f.workers[0], neon_seat(), 0x41)?;
    let fallback_slip = f.pair(f.workers[1], fallback_seat(), 0x43)?;
    f.submit(&started, 0, Some(neon_slip), "m1-a", &candidate(1))?;
    f.submit(&started, 1, Some(fallback_slip), "m2-a", &candidate(2))?;
    let m1 = verdict_text(&started.contract, &candidate(1), &sealed_cohort());
    let m2 = verdict_text(&started.contract, &candidate(2), &sealed_cohort());

    let neon = verdict_of(f.relay(&started, "m1-a", "neon", &m1, 180)?)?;
    let fallback = verdict_of(f.relay(&started, "m2-a", "fallback", &m2, 180)?)?;
    let closed = recorded_market(f.record(&started.team)?)?;

    assert_eq!(
        neon.1, fallback.1,
        "the same work spends the same units from each seat"
    );
    assert_eq!(neon.1, gpu_seconds(180, SHARE - 180));
    assert_eq!(closed.unit, Some(TeamLeaseUnit::GpuSeconds));
    let seats: Vec<_> = closed
        .submissions
        .iter()
        .map(|view| (view.participant.as_str(), view.seat.clone()))
        .collect();
    assert_eq!(
        seats,
        vec![
            ("m1", Some(owner_paired(&neon_seat()))),
            ("m2", Some(owner_paired(&fallback_seat()))),
        ]
    );
    let lease: Vec<_> = closed
        .lease
        .iter()
        .map(|view| (view.participant.as_str(), view.share, view.spent))
        .collect();
    assert_eq!(
        lease,
        vec![("m1", SHARE, 180), ("m2", SHARE, 180)],
        "both seats held equal shares and spent the same"
    );
    let winner = closed.winner.as_deref().ok_or("a passing submission won")?;
    for view in &closed.lease {
        let earned = if view.participant == winner {
            closed.bounty
        } else {
            0
        };
        assert_eq!(
            view.earned, earned,
            "{}: only the award is earned",
            view.participant
        );
        assert_eq!(view.left, view.share + view.earned - view.spent);
    }
    Ok(())
}
