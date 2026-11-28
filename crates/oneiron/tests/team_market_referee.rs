//! The sealed referee of a market ([RSI-SEALED-EVAL]; ARCH-0079 #market,
//! line 120: "The record names the rule, its digest, who set it and when, and
//! each score must carry that digest ... A CEO who overrides the referee
//! writes a logged entry with its own receipt"; ARCH-0053 §10a: "measure and
//! decide run outside an experiment's write scope").
//!
//! On the stack below this a market's score is any number whose digest
//! string matches the referee's, and nothing closes a market or logs an
//! override. Now:
//!
//! - a start may name the referee's contract, a sealed NOTE whose text
//!   hashes to the referee's digest; it is pinned before any member spawns,
//!   and a NOTE that is not sealed, does not hash, or names a screen cohort
//!   that is the sealed one spawns nothing;
//! - a member submits its candidate's digest under the member key the host
//!   queued it as, one candidate per submission;
//! - a verdict is the referee run's own output, relayed by the leader or the
//!   submitter: it scores only when the arm unit claim it names ran the
//!   contract's harness commit and workload to a clean exit and the bytes are
//!   the output the machine hashed, for the submission's candidate on the
//!   sealed cohort. A screen cohort never scores; evidence that does not
//!   hold is recorded invalid until a valid verdict replaces it; a valid
//!   sealed verdict is final, and one claim scores one submission;
//! - the record closes the market on its referee, and a CEO override is a
//!   ledger line with its own receipt that never moves the award.
//!
//! The leader and members call through the public leased host dispatcher and
//! the real dispatch, queue and lease rows, as `tests/team_market_bind.rs`
//! does; every input is decoded from the guest's JSON. Unit claims are put
//! through the arm test door, as their writer is the reserve door and the
//! machine's end.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test team_market_referee`.

#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::experiment_arm::ArmEvidenceDigest;
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    ClaimState, Draw, DrawSource, UnitClaim, UnitEnd, UnitPurpose, UnitTerminal,
};
use oneiron::llm::run_admission::AllocationRef;
use oneiron::store::GateDecisionId;
use oneiron::team::market::referee::market_override;
use oneiron::team::run::{
    TeamMarketOutcome, TeamMarketSeat, TeamMarketSeatSource, TeamMarketSubmitInput,
    TeamMarketVerdictInput, TeamMarketVerdictOutcome,
};
use oneiron::team::{
    DecidedBy, LedgerKind, Market, SelfTeamCall, TeamRecordInput, TeamRunAnswer, TeamStartInput,
    market, team_receipt, team_run_binding,
};
use oneiron::test_doors::experiment_arm_rows::put_claim;
use oneiron::test_doors::run_seat_receipt::pin_run_seat;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).

/// The lease owner this test claims rows as.
const WORKER: &str = "team-market-referee";

/// The run the leader's root attempt serves; its members join it.
const RUN: &str = "run-team-market-referee";

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

/// A 64-hex digest of one repeated byte.
fn digest(byte: &str) -> String {
    byte.repeat(32)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The sealed prompt cohort, a screen's development cohort, the comparator,
/// the approved workload, and three candidates.
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

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "market referee fixture",
        "1",
        Some("Score carefully.\n".to_owned()),
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

struct Fixture {
    vault: Vault,
    /// The owner, who writes and seals the contract NOTE.
    owner: EntityId,
    /// The leader: an owner-made Base agent at ceiling Proposed.
    leader: EntityId,
    /// The definition every member runs as.
    worker: EntityId,
    /// The leader's root attempt, leased.
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A process-owned device vault, the leader and the worker, and the leader's
/// root attempt, leased.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let now = vault.now_recorded_at();
    let leader = EntityId::from_bytes([0x6A; 16])?;
    let worker = EntityId::from_bytes([0x6B; 16])?;
    for (id, name) in [
        (leader, "fixture.referee.leader"),
        (worker, "fixture.referee.worker"),
    ] {
        vault.create_agent_definition_as(
            &proof,
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
        owner,
        leader,
        worker,
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The contract text the owner seals, naming `screens` as its development
/// cohorts.
fn contract_text(screens: &[String]) -> String {
    json!({
        "schema": "oneiron.market_referee_contract.v1",
        "comparator": {"name": "granite-base", "sha256": comparator()},
        "cohortSha256": sealed_cohort(),
        "screens": screens,
        "harness": {"commit": COMMIT, "workload": workload()},
        "verdictOutput": VERDICT_OUTPUT,
        "bar": {"metric": "pass_rate", "margin": MARGIN, "minTasks": MIN_TASKS},
    })
    .to_string()
}

/// A referee run's verdict output under `contract` for `candidate` on
/// `cohort`.
fn verdict_text(
    contract: &str,
    candidate: &str,
    cohort: &str,
    tasks: u64,
    score: f64,
    low: f64,
) -> String {
    json!({
        "schema": "oneiron.market_referee_verdict.v1",
        "contractSha256": contract,
        "cohortSha256": cohort,
        "candidateSha256": candidate,
        "comparatorSha256": comparator(),
        "tasks": tasks,
        "score": score,
        "pairedLow": low,
        "perTask": [],
    })
    .to_string()
}

/// The arm the referee's units run under.
fn arm() -> TestResult<EntityId> {
    Ok(EntityId::from_bytes([0x6C; 16])?)
}

/// The one place a test claim is built: unit `unit_key` of the referee's
/// arm, which ran `contract`'s harness to a clean exit and whose machine
/// hashed `verdict` as the verdict output. A test changes one field of it.
fn referee_claim(unit_key: &str, contract: &str, verdict: &str) -> TestResult<UnitClaim> {
    let secs = 600;
    Ok(UnitClaim {
        id: EntityId::now(),
        arm: arm()?,
        rung: 1,
        unit_key: unit_key.to_owned(),
        attempt: 1,
        line: EntityId::from_bytes([0x6D; 16])?,
        family: EntityId::from_bytes([0x6E; 16])?,
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
        state: ClaimState::Ended(ended("exited(0)", verdict)),
        revision: 2,
    })
}

/// A claim's end as the machine reported it: `node_end`, with `verdict`
/// hashed as the verdict output.
fn ended(node_end: &str, verdict: &str) -> UnitTerminal {
    UnitTerminal {
        end: UnitEnd::Settled,
        charged_secs: 300,
        measured_secs: 300,
        lost_secs: 0,
        machine: None,
        device_id: None,
        node_end: Some(node_end.to_owned()),
        outputs: vec![ArmEvidenceDigest {
            name: VERDICT_OUTPUT.to_owned(),
            sha256: sha256_hex(verdict.as_bytes()),
            bytes: verdict.len() as u64,
            rows: None,
        }],
        ended_at_ms: 2,
    }
}

/// A started sealed market: its team reference, contract digest and leased
/// members, in start order.
struct Sealed {
    team: String,
    contract: String,
    members: Vec<AttemptRecord>,
}

impl Fixture {
    fn host(&self) -> oneiron::Result<HostSelfDispatcher<'_>> {
        HostSelfDispatcher::for_leased_agent_attempt(
            &self.vault,
            WriteActor::new(self.leader, EdgeActorClass::Agent),
            &self.leased,
        )
    }

    fn member_host<'a>(
        &'a self,
        member: &AttemptRecord,
    ) -> oneiron::Result<HostSelfDispatcher<'a>> {
        HostSelfDispatcher::for_leased_agent_attempt(
            &self.vault,
            WriteActor::new(self.worker, EdgeActorClass::Agent),
            member,
        )
    }

    fn team_ref(&self, key: &str) -> String {
        format!("team:{}:{key}", hex(self.leased.id.as_bytes()))
    }

    /// The owner's NOTE of `text`, sealed when `seal`; its id and the
    /// SHA-256 of the text it keeps.
    fn contract_note(&self, text: &str, seal: bool) -> TestResult<(EntityId, String)> {
        let owner = || WriteActor::new(self.owner, EdgeActorClass::Human);
        let note = self
            .vault
            .create_note("research", text, owner())
            .map_err(|error| format!("FIXTURE: the NOTE is written: {error:?}"))?;
        if seal {
            self.vault
                .seal_note(note, owner())
                .map_err(|error| format!("FIXTURE: the NOTE seals: {error:?}"))?;
        }
        Ok((note, sha256_hex(self.vault.note_text(note)?.as_bytes())))
    }

    /// A bounty market start under `key` of one member per key in
    /// `members`, its referee on `digest` with `contract` as its NOTE.
    fn start_json(
        &self,
        key: &str,
        members: &[&str],
        digest: &str,
        contract: Option<EntityId>,
    ) -> Value {
        let members: Vec<Value> = members
            .iter()
            .map(|member| json!({"agent": self.worker.to_hex(), "intentKey": member}))
            .collect();
        let mut referee = json!({"kind": "holdout", "rule": RULE, "digest": digest});
        if let Some(note) = contract {
            referee["contract"] = json!(note.to_hex());
        }
        json!({
            "pattern": "market",
            "intentKey": key,
            "members": members,
            "tournament": null,
            "market": {"referee": referee, "mode": {"kind": "bounty"}, "pool": 1_000},
        })
    }

    fn start(&self, input: Value) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamStartInput = serde_json::from_value(input)?;
        call(&self.host()?, SelfTeamCall::Start(input))
    }

    /// A sealed bounty market under `key` among `members`, started, with its
    /// members leased in start order.
    fn sealed(&self, key: &str, members: &[&str]) -> TestResult<Sealed> {
        let (note, contract) = self.contract_note(&contract_text(&[screen_cohort()]), true)?;
        let started = self.start(self.start_json(key, members, &contract, Some(note)))?;
        if let Err(code) = started {
            return Err(format!("the sealed start is refused: {code}").into());
        }
        let team = self.team_ref(key);
        let queued = team_run_binding(&self.vault, self.leased.id, &team)?
            .ok_or("the start kept its members")?
            .members;
        let members = queued
            .into_iter()
            .map(|id| claim(&self.vault, id))
            .collect::<TestResult<Vec<_>>>()?;
        Ok(Sealed {
            team,
            contract,
            members,
        })
    }

    fn submit(
        &self,
        member: &AttemptRecord,
        team: &str,
        submission: &str,
        candidate: &str,
    ) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamMarketSubmitInput = serde_json::from_value(json!({
            "teamRef": team,
            "submissionRef": submission,
            "candidateSha256": candidate,
        }))?;
        call(
            &self.member_host(member)?,
            SelfTeamCall::MarketSubmit(input),
        )
    }

    /// `host`'s relay of `verdict` for `submission`, from unit `unit_key`.
    fn relay(
        &self,
        host: &HostSelfDispatcher<'_>,
        team: &str,
        submission: &str,
        unit_key: &str,
        verdict: &str,
    ) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamMarketVerdictInput = serde_json::from_value(json!({
            "teamRef": team,
            "submissionRef": submission,
            "claim": {"arm": arm()?.to_hex(), "rung": 1, "unitKey": unit_key, "attempt": 1},
            "verdict": verdict,
        }))?;
        call(host, SelfTeamCall::MarketVerdict(input))
    }

    /// The leader's record of `team`, with `override` as the guest wrote it.
    fn record(
        &self,
        team: &str,
        referee_override: Option<Value>,
    ) -> TestResult<Result<TeamRunAnswer, String>> {
        let mut input = json!({
            "teamRef": team,
            "members": [],
            "axis": "diverge",
            "decidedBy": {"kind": "referee", "rule": RULE, "signedAt": 0},
            "roles": null,
            "coverage": null,
        });
        if let Some(asked) = referee_override {
            input["override"] = asked;
        }
        let input: TeamRecordInput = serde_json::from_value(input)?;
        call(&self.host()?, SelfTeamCall::Record(input))
    }

    fn market(&self, team: &str) -> TestResult<Market> {
        Ok(market(&self.vault, team)?.ok_or("the market is recorded")?)
    }
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

fn outcome(answer: Result<TeamRunAnswer, String>) -> TestResult<TeamMarketVerdictOutcome> {
    match answer {
        Ok(TeamRunAnswer::MarketVerdict { outcome, .. }) => Ok(outcome),
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

#[test]
fn a_contract_that_is_not_sealed_or_does_not_hash_spawns_no_member() -> TestResult {
    let f = fixture()?;
    let (unsealed, unsealed_digest) = f.contract_note(&contract_text(&[]), false)?;
    let (sealed, _) = f.contract_note(&contract_text(&[]), true)?;
    let (overlapping, overlapping_digest) =
        f.contract_note(&contract_text(&[sealed_cohort()]), true)?;

    for (key, note, rule_digest) in [
        ("unsealed", unsealed, unsealed_digest),
        ("unhashed", sealed, digest("99")),
        ("overlapping", overlapping, overlapping_digest),
    ] {
        let answer = f.start(f.start_json(key, &["m1", "m2"], &rule_digest, Some(note)))?;

        assert_eq!(
            answer.err().as_deref(),
            Some("team_start_market_contract"),
            "{key}"
        );
        let team = f.team_ref(key);
        assert!(
            team_run_binding(&f.vault, f.leased.id, &team)?.is_none(),
            "{key}: no member spawns before its contract is pinned"
        );
        assert!(market(&f.vault, &team)?.is_none(), "{key}: no ledger opens");
    }
    Ok(())
}

#[test]
fn a_sealed_contract_is_pinned_with_the_ledger_before_any_member_spawns() -> TestResult {
    let f = fixture()?;
    let (note, contract) = f.contract_note(&contract_text(&[screen_cohort()]), true)?;

    let answer = f.start(f.start_json("pinned", &["m1", "m2"], &contract, Some(note)))?;

    assert!(
        matches!(answer, Ok(TeamRunAnswer::Started { .. })),
        "{answer:?}"
    );
    let ledger = f.market(&f.team_ref("pinned"))?;
    let pinned = ledger
        .contract
        .ok_or("the contract is pinned on the market")?;
    assert_eq!(pinned.note, note);
    assert_eq!(
        pinned.sha256, contract,
        "the contract is the referee's digest"
    );
    assert_eq!(ledger.referee.digest, contract);
    assert_eq!(pinned.comparator.sha256, comparator());
    assert_eq!(pinned.cohort_sha256, sealed_cohort());
    assert_eq!(pinned.screens, vec![screen_cohort()]);
    assert_eq!(pinned.harness_commit, COMMIT);
    assert_eq!(pinned.harness_workload, workload());
    assert_eq!(pinned.verdict_output, VERDICT_OUTPUT);
    assert_eq!(pinned.bar.min_tasks, MIN_TASKS);
    assert!((pinned.bar.margin - MARGIN).abs() < f64::EPSILON);
    Ok(())
}

#[test]
fn a_member_submits_under_its_host_key_and_one_candidate_is_one_submission() -> TestResult {
    let f = fixture()?;
    let market = f.sealed("submits", &["m1", "m2"])?;
    let before = f.vault.now_recorded_at();

    let first = f.submit(&market.members[0], &market.team, "m1-a", &candidate(1))?;
    let after = f.vault.now_recorded_at();

    match &first {
        Ok(TeamRunAnswer::MarketSubmitted {
            participant,
            at,
            replay: false,
            ..
        }) => {
            assert_eq!(participant, "m1", "the member key the host queued it as");
            assert!((before..=after).contains(at), "the vault's time: {at}");
        }
        other => panic!("expected a submission, got {other:?}"),
    }
    let forged = json!({
        "teamRef": market.team,
        "submissionRef": "m1-b",
        "candidateSha256": candidate(2),
        "participant": "m2",
    });
    assert!(
        serde_json::from_value::<TeamMarketSubmitInput>(forged).is_err(),
        "a guest-named member does not decode"
    );

    let copied = f.submit(&market.members[1], &market.team, "m2-a", &candidate(1))?;
    assert_eq!(
        copied.err().as_deref(),
        Some("team_market_candidate_taken"),
        "a rival's candidate digest is refused"
    );
    let replayed = f.submit(&market.members[0], &market.team, "m1-a", &candidate(1))?;
    assert!(
        matches!(
            replayed,
            Ok(TeamRunAnswer::MarketSubmitted { replay: true, .. })
        ),
        "{replayed:?}"
    );
    let kept = f.market(&market.team)?;
    assert_eq!(kept.submissions.len(), 1, "the refusals wrote nothing");
    assert_eq!(kept.submissions[0].agent, "m1");
    assert_eq!(
        kept.submissions[0].candidate_sha256.as_deref(),
        Some(candidate(1).as_str())
    );
    Ok(())
}

#[test]
fn a_sealed_verdict_scores_by_the_paired_bar_and_is_final() -> TestResult {
    let f = fixture()?;
    let market = f.sealed("scored", &["m1", "m2"])?;
    f.submit(&market.members[0], &market.team, "m1-a", &candidate(1))?
        .map_err(|code| format!("refused: {code}"))?;
    f.submit(&market.members[1], &market.team, "m2-a", &candidate(2))?
        .map_err(|code| format!("refused: {code}"))?;
    let passing = verdict_text(
        &market.contract,
        &candidate(1),
        &sealed_cohort(),
        120,
        0.71,
        -0.004,
    );
    let thin = verdict_text(
        &market.contract,
        &candidate(2),
        &sealed_cohort(),
        12,
        0.93,
        0.2,
    );
    put_claim(
        &f.vault,
        &referee_claim("pass", &market.contract, &passing)?,
    )?;
    put_claim(&f.vault, &referee_claim("thin", &market.contract, &thin)?)?;
    let host = f.host()?;

    let scored = outcome(f.relay(&host, &market.team, "m1-a", "pass", &passing)?)?;
    let unknown = outcome(f.relay(&host, &market.team, "m2-a", "thin", &thin)?)?;

    assert_eq!(
        scored,
        TeamMarketVerdictOutcome::Scored {
            score: 0.71,
            passed: true,
            unknown: false,
            seat: None,
        },
        "the low end of the paired interval stays above minus the margin"
    );
    assert_eq!(
        unknown,
        TeamMarketVerdictOutcome::Scored {
            score: 0.93,
            passed: false,
            unknown: true,
            seat: None,
        },
        "fewer tasks than the bar judges is unknown, not a pass"
    );
    let kept = f.market(&market.team)?;
    let evidence = kept.submissions[0]
        .evidence
        .as_ref()
        .ok_or("the score carries its evidence")?;
    assert_eq!(evidence.workload, workload());
    assert_eq!(evidence.output_sha256, sha256_hex(passing.as_bytes()));

    let replay = f.relay(&host, &market.team, "m1-a", "pass", &passing)?;
    assert!(
        matches!(
            replay,
            Ok(TeamRunAnswer::MarketVerdict { replay: true, .. })
        ),
        "{replay:?}"
    );
    let again = verdict_text(
        &market.contract,
        &candidate(1),
        &sealed_cohort(),
        120,
        0.2,
        -0.5,
    );
    put_claim(&f.vault, &referee_claim("again", &market.contract, &again)?)?;
    let second = f.relay(&host, &market.team, "m1-a", "again", &again)?;
    assert_eq!(
        second.err().as_deref(),
        Some("team_market_verdict_final"),
        "a valid sealed verdict is final"
    );
    Ok(())
}

#[test]
fn evidence_that_does_not_hold_is_invalid_until_a_valid_verdict_replaces_it() -> TestResult {
    let f = fixture()?;
    let market = f.sealed("invalid", &["m1"])?;
    f.submit(&market.members[0], &market.team, "m1-a", &candidate(1))?
        .map_err(|code| format!("refused: {code}"))?;
    let good = verdict_text(
        &market.contract,
        &candidate(1),
        &sealed_cohort(),
        120,
        0.7,
        0.01,
    );
    let other_candidate = verdict_text(
        &market.contract,
        &candidate(3),
        &sealed_cohort(),
        120,
        0.9,
        0.1,
    );
    let base = |key: &str, verdict: &str| referee_claim(key, &market.contract, verdict);
    let cases: Vec<(&str, Option<UnitClaim>, &str, &str)> = vec![
        ("absent", None, good.as_str(), "no_claim"),
        (
            "other-contract",
            Some(UnitClaim {
                contract_sha256: digest("0c"),
                ..base("other-contract", &good)?
            }),
            good.as_str(),
            "other_contract",
        ),
        (
            "other-commit",
            Some(UnitClaim {
                code_sha: "beef".repeat(10),
                ..base("other-commit", &good)?
            }),
            good.as_str(),
            "other_harness",
        ),
        (
            "other-workload",
            Some(UnitClaim {
                workload: digest("ba"),
                ..base("other-workload", &good)?
            }),
            good.as_str(),
            "other_workload",
        ),
        (
            "failed-run",
            Some(UnitClaim {
                state: ClaimState::Ended(ended("exited(1)", &good)),
                ..base("failed-run", &good)?
            }),
            good.as_str(),
            "referee_run_not_clean",
        ),
        (
            "other-bytes",
            Some(base("other-bytes", &other_candidate)?),
            good.as_str(),
            "verdict_output_mismatch",
        ),
        (
            "other-candidate",
            Some(base("other-candidate", &other_candidate)?),
            other_candidate.as_str(),
            "other_candidate",
        ),
    ];
    let host = f.host()?;

    for (key, unit, verdict, why) in cases {
        if let Some(unit) = &unit {
            put_claim(&f.vault, unit)?;
        }
        let answered = outcome(f.relay(&host, &market.team, "m1-a", key, verdict)?)?;

        assert_eq!(
            answered,
            TeamMarketVerdictOutcome::Invalid {
                reason: why.to_owned()
            },
            "{key}"
        );
        let kept = f.market(&market.team)?;
        let submission = &kept.submissions[0];
        assert_eq!(submission.score, None, "{key}: invalid is never a score");
        assert_eq!(submission.passed, None, "{key}: nor a loss");
        assert_eq!(
            submission
                .invalid
                .as_ref()
                .map(|invalid| invalid.reason.as_str()),
            Some(why),
            "{key}"
        );
    }

    put_claim(&f.vault, &base("good", &good)?)?;
    let valid = outcome(f.relay(&host, &market.team, "m1-a", "good", &good)?)?;
    assert!(
        matches!(valid, TeamMarketVerdictOutcome::Scored { passed: true, .. }),
        "{valid:?}"
    );
    let kept = f.market(&market.team)?;
    assert!(
        kept.submissions[0].invalid.is_none(),
        "a valid verdict replaces the invalid one"
    );
    Ok(())
}

#[test]
fn a_screen_never_scores_and_the_close_ignores_it() -> TestResult {
    let f = fixture()?;
    let market = f.sealed("screened", &["m1"])?;
    f.submit(&market.members[0], &market.team, "m1-a", &candidate(1))?
        .map_err(|code| format!("refused: {code}"))?;
    let screen = verdict_text(
        &market.contract,
        &candidate(1),
        &screen_cohort(),
        120,
        0.99,
        0.5,
    );
    put_claim(
        &f.vault,
        &referee_claim("screen", &market.contract, &screen)?,
    )?;

    let screened = outcome(f.relay(&f.host()?, &market.team, "m1-a", "screen", &screen)?)?;

    assert_eq!(screened, TeamMarketVerdictOutcome::Screened { score: 0.99 });
    let kept = f.market(&market.team)?;
    assert_eq!(
        kept.submissions[0].score, None,
        "a screen is never the referee's score"
    );
    assert_eq!(kept.submissions[0].passed, None, "nor a pass");
    let closed = recorded_market(f.record(&market.team, None)?)?;
    assert_eq!(closed.winner, None, "the close reads sealed verdicts only");
    Ok(())
}

#[test]
fn an_unsealed_market_or_a_running_claim_refuses_a_verdict_and_writes_nothing() -> TestResult {
    let f = fixture()?;
    // A referee named with no contract: no verdict scores this market.
    let started = f.start(f.start_json("unsealed", &["m1"], &digest("77"), None))?;
    assert!(started.is_ok(), "{started:?}");
    let team = f.team_ref("unsealed");
    let queued = team_run_binding(&f.vault, f.leased.id, &team)?
        .ok_or("the start kept its member")?
        .members;
    let member = claim(&f.vault, queued[0])?;
    f.submit(&member, &team, "m1-a", &candidate(1))?
        .map_err(|code| format!("refused: {code}"))?;
    let verdict = verdict_text(
        &digest("77"),
        &candidate(1),
        &sealed_cohort(),
        120,
        0.8,
        0.1,
    );
    put_claim(
        &f.vault,
        &referee_claim("unsealed", &digest("77"), &verdict)?,
    )?;
    let host = f.host()?;

    let unsealed = f.relay(&host, &team, "m1-a", "unsealed", &verdict)?;
    assert_eq!(unsealed.err().as_deref(), Some("team_market_unsealed"));

    let market = f.sealed("running", &["m1"])?;
    f.submit(&market.members[0], &market.team, "m1-a", &candidate(2))?
        .map_err(|code| format!("refused: {code}"))?;
    let verdict = verdict_text(
        &market.contract,
        &candidate(2),
        &sealed_cohort(),
        120,
        0.8,
        0.1,
    );
    put_claim(
        &f.vault,
        &UnitClaim {
            state: ClaimState::Started,
            ..referee_claim("running", &market.contract, &verdict)?
        },
    )?;
    let before = f.market(&market.team)?;

    let pending = f.relay(&host, &market.team, "m1-a", "running", &verdict)?;

    assert_eq!(
        pending.err().as_deref(),
        Some("team_market_verdict_pending")
    );
    assert_eq!(f.market(&market.team)?, before, "nothing is written");
    Ok(())
}

#[test]
fn one_claim_scores_one_submission_and_only_the_leader_or_submitter_relays() -> TestResult {
    let f = fixture()?;
    let market = f.sealed("relays", &["m1", "m2"])?;
    f.submit(&market.members[0], &market.team, "m1-a", &candidate(1))?
        .map_err(|code| format!("refused: {code}"))?;
    f.submit(&market.members[1], &market.team, "m2-a", &candidate(2))?
        .map_err(|code| format!("refused: {code}"))?;
    let first = verdict_text(
        &market.contract,
        &candidate(1),
        &sealed_cohort(),
        120,
        0.7,
        0.01,
    );
    put_claim(&f.vault, &referee_claim("first", &market.contract, &first)?)?;
    let rival = f.member_host(&market.members[1])?;
    let own = f.member_host(&market.members[0])?;

    let stranger = f.relay(&rival, &market.team, "m1-a", "first", &first)?;
    assert_eq!(
        stranger.err().as_deref(),
        Some("team_market_verdict_relay"),
        "a rival member relays no other member's verdict"
    );
    let relayed = outcome(f.relay(&own, &market.team, "m1-a", "first", &first)?)?;
    assert!(
        matches!(
            relayed,
            TeamMarketVerdictOutcome::Scored { passed: true, .. }
        ),
        "the submitter relays its own verdict: {relayed:?}"
    );

    let reused = f.relay(&f.host()?, &market.team, "m2-a", "first", &first)?;
    assert_eq!(
        reused.err().as_deref(),
        Some("team_market_claim_used"),
        "one claim's verdict scores one submission"
    );
    assert_eq!(f.market(&market.team)?.submissions[1].score, None);
    Ok(())
}

#[test]
fn the_record_closes_on_the_referee_and_an_override_never_moves_the_award() -> TestResult {
    let f = fixture()?;
    let market = f.sealed("closed", &["m1", "m2"])?;
    f.submit(&market.members[0], &market.team, "m1-a", &candidate(1))?
        .map_err(|code| format!("refused: {code}"))?;
    f.submit(&market.members[1], &market.team, "m2-a", &candidate(2))?
        .map_err(|code| format!("refused: {code}"))?;
    let host = f.host()?;
    for (submission, unit, n, low) in [("m1-a", "one", 1, 0.01), ("m2-a", "two", 2, -0.3)] {
        let verdict = verdict_text(
            &market.contract,
            &candidate(n),
            &sealed_cohort(),
            120,
            0.6,
            low,
        );
        put_claim(&f.vault, &referee_claim(unit, &market.contract, &verdict)?)?;
        outcome(f.relay(&host, &market.team, submission, unit, &verdict)?)?;
    }
    let bounty = f.market(&market.team)?.bounty;

    let closed = recorded_market(f.record(
        &market.team,
        Some(json!({"submissionRef": "m2-a", "reason": "m2's draft reads better"})),
    )?)?;

    assert_eq!(closed.winner.as_deref(), Some("m1"), "the referee's winner");
    assert_eq!(closed.winning_submission.as_deref(), Some("m1-a"));
    assert_eq!(closed.bounty, bounty);
    let shown = closed
        .referee_override
        .as_ref()
        .ok_or("the record shows the override beside the referee's result")?;
    assert_eq!(shown.chosen, "m2-a");
    assert_eq!(shown.by, f.leader.to_hex(), "the CEO's AGENT_DEF");

    let kept = f.market(&market.team)?;
    assert_eq!(
        kept.participants["m1"].earned, bounty,
        "the award follows the referee"
    );
    assert_eq!(
        kept.participants["m2"].earned, 0,
        "an override never moves the award"
    );
    let line = kept.ledger.last().ok_or("the override is on the ledger")?;
    assert_eq!(
        line.entry,
        LedgerKind::Override {
            submission_ref: "m2-a".to_owned(),
            by: f.leader
        }
    );
    assert_eq!(line.units, 0);
    let receipt =
        market_override(&f.vault, &market.team)?.ok_or("the override has its own receipt")?;
    assert_eq!(receipt.referee_winner.as_deref(), Some("m1-a"));
    assert_eq!(receipt.ledger_seq, line.seq);
    let team = team_receipt(&f.vault, &market.team)?.ok_or("the team receipt is written")?;
    assert!(
        matches!(team.decided_by, DecidedBy::Referee { .. }),
        "the team receipt stays the referee's: {:?}",
        team.decided_by
    );

    let read = recorded_market(f.record(&market.team, None)?)?;
    assert_eq!(read, closed, "a read of the result shows both");
    let moved = f.record(
        &market.team,
        Some(json!({"submissionRef": "m1-a", "reason": "changed my mind"})),
    )?;
    assert_eq!(moved.err().as_deref(), Some("team_record_override_moved"));
    Ok(())
}

/// [MARKET-SEAT-MODEL-STAMP]: a member run the engine seated submits under
/// its seat receipt's model, frozen on the submission, and the sealed score
/// carries that seat: in the verdict's answer and in the team result's
/// submissions list. A run the engine did not seat is unknown.
#[test]
fn a_host_seated_member_carries_its_seat_receipt_model_to_its_score() -> TestResult {
    let f = fixture()?;
    let market = f.sealed("seated", &["m1", "m2"])?;
    let model = "provider/host-model@r1";
    pin_run_seat(
        &f.vault,
        EntityId::from_bytes(*market.members[0].id.as_bytes())?,
        model,
    )?;
    let host_seat = TeamMarketSeat {
        harness: "oneiron".to_owned(),
        model: model.to_owned(),
        source: TeamMarketSeatSource::HostSeat,
    };

    let seated = f.submit(&market.members[0], &market.team, "m1-a", &candidate(1))?;
    let unseated = f.submit(&market.members[1], &market.team, "m2-a", &candidate(2))?;
    let passing = verdict_text(
        &market.contract,
        &candidate(1),
        &sealed_cohort(),
        120,
        0.71,
        -0.004,
    );
    put_claim(
        &f.vault,
        &referee_claim("pass", &market.contract, &passing)?,
    )?;
    let scored = outcome(f.relay(&f.host()?, &market.team, "m1-a", "pass", &passing)?)?;
    let closed = recorded_market(f.record(&market.team, None)?)?;

    match &seated {
        Ok(TeamRunAnswer::MarketSubmitted { seat, .. }) => {
            assert_eq!(
                seat.as_ref(),
                Some(&host_seat),
                "the run's own seat receipt"
            );
        }
        other => panic!("expected a submission, got {other:?}"),
    }
    match &unseated {
        Ok(TeamRunAnswer::MarketSubmitted { seat, .. }) => {
            assert_eq!(seat, &None, "a run the engine did not seat is unknown");
        }
        other => panic!("expected a submission, got {other:?}"),
    }
    assert_eq!(
        scored,
        TeamMarketVerdictOutcome::Scored {
            score: 0.71,
            passed: true,
            unknown: false,
            seat: Some(host_seat.clone()),
        },
        "the score carries the seat its submission froze"
    );
    assert_eq!(
        f.market(&market.team)?.submissions[0].seat.as_ref(),
        Some(&host_seat)
    );
    let listed: Vec<_> = closed
        .submissions
        .iter()
        .map(|view| (view.submission_ref.as_str(), view.seat.clone(), view.score))
        .collect();
    assert_eq!(
        listed,
        vec![("m1-a", Some(host_seat), Some(0.71)), ("m2-a", None, None),],
        "the result lists each seat beside its score"
    );
    Ok(())
}
