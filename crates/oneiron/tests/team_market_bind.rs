//! A market binds before the work ([RSI-MARKET-BIND]; ARCH-0079 #market,
//! line 120: "The record names the rule, its digest, who set it and when, and
//! each score must carry that digest ... The CEO judges after the work; a
//! market binds before it").
//!
//! On main a code-mode `self.team.start` under the `market` pattern spawns
//! its members with no referee recorded, and `self.team.record` then takes
//! the rule and time the leader names after the work. Now:
//!
//! - a market start that is not a tournament's names its referee and ledger
//!   terms, and the host records them before the first member spawns: the
//!   setter is the leader's AGENT_DEF, read from its dispatch row, and the
//!   time is the vault's. A start without them, or whose terms open no
//!   ledger, spawns no member; terms on another pattern are refused;
//! - a replay on the same terms keeps the first record, and a start on other
//!   terms is refused with nothing spawned;
//! - a market receipt names the recorded referee, never the leader's late
//!   rule, and a market team whose start recorded none writes no receipt.
//!
//! The leader's calls go through the public leased host dispatcher and the
//! real dispatch, queue and lease rows, as `tests/agent_blast_radius.rs`
//! drives them; each start input is decoded from the guest's JSON.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test team_market_bind`.

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
    TeamRunStamp,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    HostSelfDispatcher, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfCall, SelfDispatchOutcome,
    SelfDispatcher,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::store::GateDecisionId;
use oneiron::team::{
    DecidedBy, Market, RefereeKind, SelfTeamCall, TeamPattern, TeamRecordInput, TeamRunAnswer,
    TeamStartInput, market, team_receipt, team_run_binding,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).

/// The lease owner this test claims rows as.
const WORKER: &str = "team-market-bind";

/// The run the leader's root attempt serves; its members join it.
const RUN: &str = "run-team-market-bind";

/// The rule and digest every market here records.
const RULE: &str = "suite:granite-eval@4f2a";
const DIGEST: &str = "sha256:9c1e5b77d0a4";

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "market bind fixture",
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
    let leader = EntityId::from_bytes([0x5A; 16])?;
    let worker = EntityId::from_bytes([0x5B; 16])?;
    for (id, name) in [
        (leader, "fixture.market.leader"),
        (worker, "fixture.market.worker"),
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

impl Fixture {
    /// The leased host dispatcher of the leader's root attempt.
    fn host(&self) -> oneiron::Result<HostSelfDispatcher<'_>> {
        HostSelfDispatcher::for_leased_agent_attempt(
            &self.vault,
            WriteActor::new(self.leader, EdgeActorClass::Agent),
            &self.leased,
        )
    }

    /// The reference a start under `key` opens: the leader's attempt and the
    /// key.
    fn team_ref(&self, key: &str) -> String {
        format!("team:{}:{key}", hex(self.leased.id.as_bytes()))
    }

    /// A start under `key` and `pattern` of one member per key in
    /// `members`, all running the worker, with `market` as the guest wrote
    /// it (or none).
    fn start_json(
        &self,
        pattern: &str,
        key: &str,
        members: &[&str],
        market: Option<Value>,
    ) -> Value {
        let members: Vec<Value> = members
            .iter()
            .map(|member| json!({"agent": self.worker.to_hex(), "intentKey": member}))
            .collect();
        let mut input = json!({
            "pattern": pattern,
            "intentKey": key,
            "members": members,
            "tournament": null,
        });
        if let Some(market) = market {
            input["market"] = market;
        }
        input
    }

    /// The leader's `self.team.start` of `input`: the answer, or the typed
    /// failure code.
    fn start(&self, input: Value) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamStartInput = serde_json::from_value(input)?;
        self.team_call(SelfTeamCall::Start(input))
    }

    /// The leader's `self.team.record` of `team_ref`, naming `members`
    /// beyond those its start spawned and a referee rule and time of its
    /// own, after the work.
    fn record(
        &self,
        team_ref: &str,
        members: &[String],
        rule: &str,
        signed_at: u64,
    ) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamRecordInput = serde_json::from_value(json!({
            "teamRef": team_ref,
            "members": members,
            "axis": "diverge",
            "decidedBy": {"kind": "referee", "rule": rule, "signedAt": signed_at},
            "roles": null,
            "coverage": null,
        }))?;
        self.team_call(SelfTeamCall::Record(input))
    }

    fn team_call(&self, call: SelfTeamCall) -> TestResult<Result<TeamRunAnswer, String>> {
        match self.host()?.dispatch(SelfCall::Team(call))? {
            SelfDispatchOutcome::Team(result) => Ok(Ok(result.answer)),
            SelfDispatchOutcome::Failed(failed) => Ok(Err(failed.error)),
            other => {
                Err(format!("expected a team answer or a typed failure, got {other:?}").into())
            }
        }
    }

    /// The members the host kept for the start of `team_ref`: none when no
    /// member spawned.
    fn spawned(&self, team_ref: &str) -> TestResult<usize> {
        Ok(team_run_binding(&self.vault, self.leased.id, team_ref)?
            .map_or(0, |binding| binding.members.len()))
    }

    fn market(&self, team_ref: &str) -> TestResult<Option<Market>> {
        Ok(market(&self.vault, team_ref)?)
    }
}

/// A bounty market's terms on `digest`, as the guest writes them.
fn terms(digest: &str) -> Value {
    json!({
        "referee": {"kind": "test_suite", "rule": RULE, "digest": digest},
        "mode": {"kind": "bounty"},
        "pool": 1_000,
    })
}

fn started_members(answer: &TeamRunAnswer) -> Vec<String> {
    match answer {
        TeamRunAnswer::Started { members, .. } => members
            .iter()
            .filter_map(|member| member.attempt_ref.clone())
            .collect(),
        other => panic!("expected a started team, got {other:?}"),
    }
}

#[test]
fn a_market_start_without_a_referee_spawns_no_member() -> TestResult {
    let f = fixture()?;
    let team = f.team_ref("unrefereed");

    let answer = f.start(f.start_json("market", "unrefereed", &["m1", "m2"], None))?;

    assert_eq!(
        answer.err().as_deref(),
        Some("team_start_market_needs_referee"),
        "a market names its referee before the work"
    );
    assert_eq!(
        f.spawned(&team)?,
        0,
        "no member of an unrefereed market spawns"
    );
    assert!(f.market(&team)?.is_none(), "no ledger is opened");
    Ok(())
}

#[test]
fn a_market_start_records_its_referee_before_any_member_spawns() -> TestResult {
    let f = fixture()?;
    let team = f.team_ref("bound");
    let before = f.vault.now_recorded_at();

    let answer = f.start(f.start_json("market", "bound", &["m1", "m2"], Some(terms(DIGEST))))?;
    let after = f.vault.now_recorded_at();

    let members = started_members(&answer.map_err(|code| format!("refused: {code}"))?);
    assert_eq!(
        members.len(),
        2,
        "both members spawn once the referee is recorded"
    );
    let ledger = f
        .market(&team)?
        .ok_or("the start opened the run's ledger")?;
    assert_eq!(ledger.referee.kind, RefereeKind::TestSuite);
    assert_eq!(ledger.referee.rule_ref, RULE);
    assert_eq!(
        ledger.referee.digest, DIGEST,
        "the rule's digest is pinned to the run"
    );
    assert_eq!(
        ledger.referee.signed_by, f.leader,
        "the setter is the leader's AGENT_DEF, the run's CEO"
    );
    assert!(
        (before..=after).contains(&ledger.referee.signed_at),
        "the referee carries the vault's time at the start: {} not in {before}..={after}",
        ledger.referee.signed_at
    );
    assert_eq!(ledger.opened_at, ledger.referee.signed_at);
    assert_eq!(
        ledger.participants.keys().cloned().collect::<Vec<_>>(),
        vec!["m1".to_owned(), "m2".to_owned()],
        "the participants are the members' keys"
    );
    assert_eq!(f.spawned(&team)?, 2);
    Ok(())
}

#[test]
fn a_guest_named_setter_or_time_never_reaches_the_record() -> TestResult {
    let f = fixture()?;
    let team = f.team_ref("self-signed");
    let other = EntityId::from_bytes([0x5C; 16])?;
    let mut forged = terms(DIGEST);
    forged["referee"]["signedBy"] = json!(other.to_hex());
    forged["referee"]["signedAt"] = json!(1);
    let input = f.start_json("market", "self-signed", &["m1"], Some(forged));

    // The wire takes no setter and no time: such a start does not decode.
    assert!(
        serde_json::from_value::<TeamStartInput>(input).is_err(),
        "a start naming the referee's setter or time is refused at the wire"
    );
    assert!(f.market(&team)?.is_none());

    let before = f.vault.now_recorded_at();
    let answer = f.start(f.start_json("market", "self-signed", &["m1"], Some(terms(DIGEST))))?;
    started_members(&answer.map_err(|code| format!("refused: {code}"))?);
    let ledger = f
        .market(&team)?
        .ok_or("the start opened the run's ledger")?;
    assert_eq!(
        ledger.referee.signed_by, f.leader,
        "the leader's AGENT_DEF, not the guest's"
    );
    assert_ne!(ledger.referee.signed_by, other);
    assert!(
        ledger.referee.signed_at >= before && ledger.referee.signed_at != 1,
        "the vault's time, not the guest's"
    );
    Ok(())
}

#[test]
fn a_market_start_whose_ledger_cannot_open_spawns_no_member() -> TestResult {
    let f = fixture()?;
    let team = f.team_ref("bad-terms");
    let mut bad = terms(DIGEST);
    bad["bountyShare"] = json!(1.5);

    let answer = f.start(f.start_json("market", "bad-terms", &["m1", "m2"], Some(bad)))?;

    assert_eq!(answer.err().as_deref(), Some("team_start_market_invalid"));
    assert_eq!(
        f.spawned(&team)?,
        0,
        "no member spawns before its ledger opens"
    );
    assert!(f.market(&team)?.is_none());
    Ok(())
}

#[test]
fn a_replayed_market_start_keeps_the_first_record_and_moved_terms_spawn_nothing() -> TestResult {
    let f = fixture()?;
    let team = f.team_ref("replayed");
    let first = f.start(f.start_json("market", "replayed", &["m1", "m2"], Some(terms(DIGEST))))?;
    let first = started_members(&first.map_err(|code| format!("refused: {code}"))?);
    let recorded = f
        .market(&team)?
        .ok_or("the first start opened the ledger")?;

    let again = f.start(f.start_json("market", "replayed", &["m1", "m2"], Some(terms(DIGEST))))?;
    let again = started_members(&again.map_err(|code| format!("refused: {code}"))?);
    assert_eq!(again, first, "a replay answers the same members");
    assert_eq!(
        f.market(&team)?.as_ref(),
        Some(&recorded),
        "a replay keeps the first record, its setter and its time"
    );

    let moved_digest = f.start(f.start_json(
        "market",
        "replayed",
        &["m1", "m2"],
        Some(terms("sha256:other")),
    ))?;
    assert_eq!(
        moved_digest.err().as_deref(),
        Some("team_start_market_moved")
    );
    let moved_members = f.start(f.start_json(
        "market",
        "replayed",
        &["m1", "m2", "m3"],
        Some(terms(DIGEST)),
    ))?;
    assert_eq!(
        moved_members.err().as_deref(),
        Some("team_start_market_moved")
    );
    assert_eq!(f.spawned(&team)?, 2, "a moved start spawns nothing");
    assert_eq!(
        f.market(&team)?.as_ref(),
        Some(&recorded),
        "the record stays"
    );
    Ok(())
}

#[test]
fn a_market_receipt_names_the_recorded_referee_not_the_leaders_late_rule() -> TestResult {
    let f = fixture()?;
    let team = f.team_ref("receipted");
    let answer =
        f.start(f.start_json("market", "receipted", &["m1", "m2"], Some(terms(DIGEST))))?;
    started_members(&answer.map_err(|code| format!("refused: {code}"))?);
    let ledger = f
        .market(&team)?
        .ok_or("the start opened the run's ledger")?;

    let recorded = f.record(&team, &[], "rule:named-after-the-work", u64::MAX / 2)?;

    assert!(
        matches!(recorded, Ok(TeamRunAnswer::Recorded { replay: false, .. })),
        "the bound market records its receipt: {recorded:?}"
    );
    let receipt = team_receipt(&f.vault, &team)?.ok_or("the receipt is kept")?;
    assert_eq!(
        receipt.decided_by,
        DecidedBy::Referee {
            rule: RULE.to_owned(),
            signed_at: ledger.referee.signed_at,
        },
        "the receipt names the referee recorded before the work"
    );
    Ok(())
}

#[test]
fn a_market_team_with_no_recorded_referee_writes_no_receipt() -> TestResult {
    let f = fixture()?;
    let team = f.team_ref("unbound");
    // A member stamped into the market team by a plain spawn: its start
    // recorded no referee.
    let stamp = TeamRunStamp::new(team.clone(), TeamPattern::Market)?;
    let call = SelfCall::AgentsSpawn(Box::new(SelfAgentSpawnCall {
        target: Some(AgentDispatchTarget::Custom(f.worker)),
        context: AgentSpawnContext::default().with_team(stamp),
        intent_key: "unbound-member".to_owned(),
        ask: None,
    }));
    let member = match f.host()?.dispatch(call)? {
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { attempt_ref, .. }) => {
            hex(attempt_ref.as_bytes())
        }
        other => return Err(format!("expected a queued member, got {other:?}").into()),
    };
    assert!(
        f.market(&team)?.is_none(),
        "FIXTURE: no referee was recorded"
    );

    let recorded = f.record(&team, &[member], RULE, f.vault.now_recorded_at())?;

    assert_eq!(
        recorded.err().as_deref(),
        Some("team_record_market_unbound"),
        "a market team whose start recorded no referee writes no receipt"
    );
    assert!(team_receipt(&f.vault, &team)?.is_none());
    Ok(())
}

#[test]
fn a_referee_outside_a_market_start_is_refused() -> TestResult {
    let f = fixture()?;
    let team = f.team_ref("vote-with-referee");

    let answer = f.start(f.start_json(
        "vote",
        "vote-with-referee",
        &["m1", "m2"],
        Some(terms(DIGEST)),
    ))?;

    assert_eq!(
        answer.err().as_deref(),
        Some("team_start_referee_outside_market")
    );
    assert_eq!(f.spawned(&team)?, 0);
    assert!(f.market(&team)?.is_none());
    Ok(())
}
