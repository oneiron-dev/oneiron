//! A planned market binds before the work ([RSI-MARKET-BIND-PLANNED]; Engine
//! ANSWER RSI-MARKET-BIND-PLANNED = A; ARCH-0079 #market: "The CEO judges
//! after the work; a market binds before it").
//!
//! On main a planned (DOOR-111) market team queues its leader and members in
//! one writer with no referee recorded, so its receipt can only refuse as
//! unbound. Now:
//!
//! - the planned ask, the owner's and a leased agent's, takes the same
//!   `market` terms as `self.team.start`; a market plan without them, them on
//!   any other plan, and terms no ledger opens on are refused when the plan
//!   is frozen, before the pattern runner runs, with nothing queued;
//! - the launch writer records the ledger in the transaction that queues the
//!   group, after the leader and before any member: the setter is the asker
//!   (the owner at the root, the leasing agent's AGENT_DEF under a lease),
//!   the time is the vault's, and the members are its participants;
//! - market terms on a `self.agents.spawn` that launches no planned team are
//!   refused, never dropped;
//! - an ask without terms encodes, and digests, byte for byte as main's.
//!
//! The launches go through the public dispatcher with a planner host of one
//! seat, the shipped team-shape and team-market workflows (seeded through the
//! bootstrap test door) and a counting pattern runner.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test team_market_planned`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    AgentSpawnContext, CallerOrigin, CareLevel, CoordinationPattern, DispatchAgent, PlannerSeat,
    PlannerSkills, SpawnNeed, SpawnOverride, TeamPlan, agent_dispatch_actor,
    decode_agent_dispatch_input, load_team_type_tree,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    AgentSpawnInput, HostSelfDispatcher, SelfAgentSpawnResult, SelfCall, SelfDispatchOutcome,
    SelfDispatcher, SelfSpawnAsk,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_projection::ContextSpec;
use oneiron::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore};
use oneiron::llm::ModelId;
use oneiron::skill::LoadedSkillPack;
use oneiron::store::GateDecisionId;
use oneiron::task_type::TaskTypeRef;
use oneiron::team::doors::SpawnIntentRequest;
use oneiron::team::{
    LeasedSpawnRequest, Market, PatternLaunchRunner, PatternLaunchSpec, PlannedIntentView,
    PlannedSpawnHost, PlannedSpawnRequest, RefereeKind, SpawnPhase, TeamAxis, TeamPattern, market,
    pattern_skill, team_run_binding,
};
use oneiron::test_doors::bootstrap_skills::{bootstrap_skill_id, seed_bootstrap_skills_adding};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_records::agent_dispatch::planner_live::intent::ASK_DIGEST_CONTEXT;
use rmpv::Value as RmpValue;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).

/// The model the one planner seat serves, and the executor the host plans on.
const EXECUTOR: &str = "test/executor@v1";

/// The run the leased parent serves; a group it launches rides it.
const RUN: &str = "run-team-market-planned";

/// The lease owner this test claims rows as.
const WORKER: &str = "team-market-planned";

/// The adapter label the host places and plans under.
const ADAPTER: &str = "fixture.planned-market.v1";

/// The work every planned ask carries, and the briefings the runner writes.
const PROMPT: &str = "Compare two checkable approaches.";
const LEADER: &str = "Collect both approaches and score them.";
const MEMBERS: [&str; 2] = ["Check approach A.", "Check approach B."];

/// The rule and digest every market here records.
const RULE: &str = "suite:granite-eval@4f2a";
const DIGEST: &str = "sha256:9c1e5b77d0a4";

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "planned market fixture",
        "1",
        Some("Compare approaches.\n".to_owned()),
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
    owner: AuthenticatedOwner,
    /// The owner's actor, the setter of an owner's planned market.
    person: EntityId,
    /// The leased parent's AGENT_DEF, the setter of its planned market.
    parent: EntityId,
    /// The one planner seat's AGENT_DEF, which every planned agent runs.
    seat: EntityId,
    /// The shipped team-market workflow, the market plan's pattern skill.
    market_skill: EntityId,
    /// The root tree's root node, asked for so placement keeps it.
    stamp: TaskTypeRef,
    seats: [PlannerSeat; 1],
    skills: PlannerSkills,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A process-owned device vault with the team-shape and team-market
/// workflows seeded, the parent and seat definitions, and one planner seat.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let person = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
    seed_bootstrap_skills_adding(
        &vault,
        &[
            (
                "team-shape",
                include_str!("../../../skills/team-shape/SKILL.md"),
            ),
            (
                "team-market",
                include_str!("../../../skills/team-market/SKILL.md"),
            ),
        ],
    )?;
    let skills = PlannerSkills::seeded(&vault)?;
    assert!(
        vault.get_skill_record(&skills.team_shape)?.is_some(),
        "the team-shape workflow is seeded"
    );
    let market_skill = bootstrap_skill_id("team-market")?;
    assert_eq!(
        pattern_skill(&vault, &market_skill)?.map(|bound| bound.pattern),
        Some(TeamPattern::Market),
        "the team-market workflow is bound as the market pattern"
    );
    let stamp = load_team_type_tree(&vault, Some(vault.root_project()?))?.root_ref();
    let parent = EntityId::from_bytes([0x5A; 16])?;
    let seat = EntityId::from_bytes([0x5B; 16])?;
    let now = vault.now_recorded_at();
    for (id, name) in [
        (parent, "fixture.planned.parent"),
        (seat, "fixture.planned.seat"),
    ] {
        vault.create_agent_definition_as(
            &owner,
            &id,
            &definition(name),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    let seats = [PlannerSeat {
        model: ModelId::new(EXECUTOR)?,
        agent_def: seat,
    }];
    Ok(Fixture {
        vault,
        owner,
        person,
        parent,
        seat,
        market_skill,
        stamp,
        seats,
        skills,
        _dir: dir,
    })
}

/// A pattern runner that counts its runs and briefs the leader and two
/// members, as a team-market start would.
#[derive(Default)]
struct Runner(AtomicUsize);

impl Runner {
    fn runs(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl PatternLaunchRunner for Runner {
    fn run(
        &self,
        _pack: &LoadedSkillPack,
        _asked: &SpawnNeed,
        _prompt: &str,
        _plan: &TeamPlan,
        _payer: &WriteActor,
    ) -> oneiron::Result<PatternLaunchSpec> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(PatternLaunchSpec {
            leader_briefing: LEADER.to_owned(),
            member_briefings: MEMBERS
                .iter()
                .map(|briefing| (*briefing).to_owned())
                .collect(),
            axis: TeamAxis::Converge,
        })
    }
}

impl Fixture {
    fn host(&self) -> PlannedSpawnHost<'_> {
        PlannedSpawnHost {
            caller_origin: CallerOrigin::NativeHost,
            seats: &self.seats,
            skills: &self.skills,
            executor: EXECUTOR,
            placement: None,
            planner: None,
            spend: None,
            placement_adapter: ADAPTER,
            placement_key: None,
        }
    }

    /// The owner's planned spawn of `ask` under `key`, launched at `at`.
    fn launch_as_owner(
        &self,
        key: &str,
        ask: SelfSpawnAsk,
        runner: &Runner,
        at: u64,
    ) -> TestResult<PlannedIntentView> {
        let request = PlannedSpawnRequest {
            intent_key: key.to_owned(),
            ask,
            prompt: PROMPT.to_owned(),
            requested_type: Some(self.stamp.clone()),
        };
        Ok(
            AgentDispatcher::new(&self.vault).launch_reserved_spawn_as_owner(
                &self.owner,
                &request,
                &self.host(),
                Some(runner),
                at,
            )?,
        )
    }

    /// The parent's root attempt on `RUN`, dispatched and leased.
    fn lease_parent(&self) -> TestResult<AttemptRecord> {
        let AgentDispatchOutcome::Dispatched(status) =
            AgentDispatcher::new(&self.vault).dispatch(DispatchAgent {
                target: AgentDispatchTarget::Custom(self.parent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(RUN.to_owned()),
                now: self.vault.now_recorded_at(),
            })?
        else {
            panic!("the parent dispatches without running a model")
        };
        claim(&self.vault, status.attempt.id)
    }

    /// The leased parent's planned spawn of `ask` under `key`, launched at
    /// `at`, as the agent its lease runs.
    fn launch_as_agent(
        &self,
        leased: &AttemptRecord,
        key: &str,
        ask: SelfSpawnAsk,
        runner: &Runner,
        at: u64,
    ) -> TestResult<PlannedIntentView> {
        let status = DreamerRunnerStore::new(&self.vault)
            .status(leased.id)?
            .ok_or("the parent's dispatch row")?;
        let actor = agent_dispatch_actor(&decode_agent_dispatch_input(&status.payload.input)?)?;
        let request = LeasedSpawnRequest {
            intent_key: key.to_owned(),
            ask,
            context: AgentSpawnContext::default()
                .with_type_ref(self.stamp.clone())
                .with_context_spec(ContextSpec::default().with_briefing(PROMPT)),
        };
        Ok(
            AgentDispatcher::new(&self.vault).launch_planned_spawn_for_attempt(
                leased,
                &actor,
                &request,
                &self.host(),
                Some(runner),
                at,
            )?,
        )
    }

    /// The members a launched group queued, each checked: queued, its
    /// dispatch key naming its role, under the leader, stamped into `team`.
    fn queued_members(&self, view: &PlannedIntentView) -> TestResult<Vec<AttemptId>> {
        let leader = view.root_attempt.ok_or("a launched group has its leader")?;
        let team = view
            .team_ref
            .as_deref()
            .ok_or("a launched team has its reference")?;
        let digest = team
            .rsplit_once(':')
            .ok_or("the team reference ends on its digest")?
            .1;
        let binding = team_run_binding(&self.vault, leader, team)?.ok_or("TEAM_RUN")?;
        assert_eq!(binding.stamp.pattern, TeamPattern::Market);
        assert_eq!(binding.members, view.member_attempts);
        let queue = AttemptQueue::new(&self.vault);
        let store = DreamerRunnerStore::new(&self.vault);
        for (ordinal, id) in view.member_attempts.iter().enumerate() {
            let row = queue.get(*id)?.ok_or("the member's queue row")?;
            assert_eq!(row.state, AttemptState::Queued);
            assert_eq!(
                row.dedupe_key,
                Some(format!(
                    "{AGENT_DISPATCH_ATTEMPT_TYPE}:planned:{digest}:member:{ordinal}"
                ))
            );
            let status = store.status(*id)?.ok_or("the member's dispatch row")?;
            assert_eq!(status.payload.parent_attempt, Some(leader));
            let input = decode_agent_dispatch_input(&status.payload.input)?;
            assert_eq!(input.target.agent_definition_ref()?, self.seat);
            assert_eq!(input.team.as_ref(), Some(&binding.stamp));
        }
        Ok(view.member_attempts.clone())
    }

    /// How many attempts the queue holds.
    fn rows(&self) -> TestResult<usize> {
        Ok(AttemptQueue::new(&self.vault).list()?.len())
    }

    fn market(&self, view: &PlannedIntentView) -> TestResult<Option<Market>> {
        let team = view
            .team_ref
            .as_deref()
            .ok_or("a launched team has its reference")?;
        Ok(market(&self.vault, team)?)
    }
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

/// A bounty market's terms on `digest`, as the asker writes them.
fn terms(digest: &str) -> Value {
    json!({
        "referee": {"kind": "test_suite", "rule": RULE, "digest": digest},
        "mode": {"kind": "bounty"},
        "pool": 1_000,
    })
}

/// An ask that pins `pattern` at `width`, with `market` as the asker wrote
/// it (or none).
fn ask(
    pattern: CoordinationPattern,
    width: u32,
    market: Option<Value>,
) -> TestResult<SelfSpawnAsk> {
    Ok(SelfSpawnAsk {
        need: "Compare two checkable approaches.".to_owned(),
        care: None,
        notes: None,
        model: None,
        width: Some(SpawnOverride::Pin { value: width }),
        pattern: Some(SpawnOverride::Pin { value: pattern }),
        budget_cap_units: None,
        balance_free_prompt: false,
        market: market.map(serde_json::from_value).transpose()?,
    })
}

/// A view that planned and launched nothing, with the refusal it kept.
fn refused(view: &PlannedIntentView) -> String {
    assert_eq!(view.phase, SpawnPhase::Refused, "{view:?}");
    assert!(view.root_attempt.is_none(), "no leader is queued");
    assert!(view.member_attempts.is_empty(), "no member is queued");
    assert!(view.team_ref.is_none(), "no team is bound");
    view.refusal.clone().unwrap_or_default()
}

/// The ledger a launch recorded: its referee set by `setter` at the vault's
/// time, between `before` and `after`, on the rule and digest, its members
/// the participants.
fn assert_bound(ledger: &Market, setter: EntityId, before: u64, after: u64) {
    assert_eq!(ledger.referee.kind, RefereeKind::TestSuite);
    assert_eq!(ledger.referee.rule_ref, RULE);
    assert_eq!(
        ledger.referee.digest, DIGEST,
        "the digest is pinned to the run"
    );
    assert_eq!(
        ledger.referee.signed_by, setter,
        "the asker set the referee"
    );
    assert!(
        (before..=after).contains(&ledger.referee.signed_at),
        "the referee's time is the vault's: {} not in {before}..={after}",
        ledger.referee.signed_at
    );
    assert_eq!(ledger.opened_at, ledger.referee.signed_at);
    assert_eq!(ledger.pool, 1_000);
    assert_eq!(
        ledger.participants.keys().cloned().collect::<Vec<_>>(),
        vec!["member:0".to_owned(), "member:1".to_owned()],
        "the members, in launch order, are the market's participants"
    );
}

#[test]
fn a_planned_market_ask_without_terms_queues_nothing() -> TestResult {
    let f = fixture()?;
    let runner = Runner::default();
    let at = f.vault.now_recorded_at();
    let rows = f.rows()?;

    let view = f.launch_as_owner(
        "owner-unbound",
        ask(CoordinationPattern::Market, 3, None)?,
        &runner,
        at,
    )?;
    let refusal = refused(&view);
    assert!(
        refusal.contains("names its referee and ledger terms"),
        "the owner is told what to name: {refusal}"
    );
    assert_eq!(f.rows()?, rows, "nothing is queued");

    let leased = f.lease_parent()?;
    let rows = f.rows()?;
    let view = f.launch_as_agent(
        &leased,
        "leased-unbound",
        ask(CoordinationPattern::Market, 3, None)?,
        &runner,
        at,
    )?;
    let refusal = refused(&view);
    assert!(
        refusal.contains("names its referee and ledger terms"),
        "{refusal}"
    );
    assert_eq!(f.rows()?, rows, "nothing is queued under the lease");

    assert_eq!(
        runner.runs(),
        0,
        "a market plan without terms is refused before its pattern runs"
    );
    Ok(())
}

#[test]
fn an_owner_planned_market_records_its_referee_with_the_group() -> TestResult {
    let f = fixture()?;
    let runner = Runner::default();
    let before = f.vault.now_recorded_at();
    // The launching call's own time is not the referee's.
    let at = before + 3_600;

    let view = f.launch_as_owner(
        "owner-market",
        ask(CoordinationPattern::Market, 3, Some(terms(DIGEST)))?,
        &runner,
        at,
    )?;
    let after = f.vault.now_recorded_at();

    assert_eq!(view.phase, SpawnPhase::Launched, "{:?}", view.refusal);
    let members = f.queued_members(&view)?;
    assert_eq!(members.len(), 2, "the leader and two members are queued");
    let Some(ledger) = f.market(&view)? else {
        panic!("the launch recorded no ledger in the writer that queued its members")
    };
    assert_bound(&ledger, f.person, before, after);
    assert!(
        ledger.referee.signed_at < at,
        "the vault's time, not the call's"
    );

    // A replay answers what launched, and records nothing again.
    let replay = f.launch_as_owner(
        "owner-market",
        ask(CoordinationPattern::Market, 3, Some(terms(DIGEST)))?,
        &runner,
        at,
    )?;
    assert_eq!(replay, view);
    assert_eq!(f.market(&view)?, Some(ledger), "the first record stands");
    assert_eq!(runner.runs(), 1, "the pattern ran once");
    Ok(())
}

#[test]
fn a_leased_planned_market_names_the_leasing_agent() -> TestResult {
    let f = fixture()?;
    let runner = Runner::default();
    let leased = f.lease_parent()?;
    let before = f.vault.now_recorded_at();

    let view = f.launch_as_agent(
        &leased,
        "leased-market",
        ask(CoordinationPattern::Market, 3, Some(terms(DIGEST)))?,
        &runner,
        before,
    )?;
    let after = f.vault.now_recorded_at();

    assert_eq!(view.phase, SpawnPhase::Launched, "{:?}", view.refusal);
    let leader = view.root_attempt.ok_or("a launched group has its leader")?;
    let leader_row = AttemptQueue::new(&f.vault)
        .get(leader)?
        .ok_or("the leader's row")?;
    assert_eq!(
        leader_row.run_id.as_deref(),
        Some(RUN),
        "the group rides the parent's run"
    );
    assert_eq!(f.queued_members(&view)?.len(), 2);
    let Some(ledger) = f.market(&view)? else {
        panic!("the launch recorded no ledger in the writer that queued its members")
    };
    assert_bound(&ledger, f.parent, before, after);
    Ok(())
}

#[test]
fn planned_market_terms_on_a_plan_that_is_no_market_are_refused() -> TestResult {
    let f = fixture()?;
    let runner = Runner::default();
    let at = f.vault.now_recorded_at();
    let rows = f.rows()?;

    let view = f.launch_as_owner(
        "solo-terms",
        ask(CoordinationPattern::Solo, 1, Some(terms(DIGEST)))?,
        &runner,
        at,
    )?;

    let refusal = refused(&view);
    assert!(refusal.contains("bind a market plan only"), "{refusal}");
    assert_eq!(f.rows()?, rows, "nothing is queued");
    Ok(())
}

#[test]
fn planned_market_terms_that_open_no_ledger_are_refused_before_the_pattern_runs() -> TestResult {
    let f = fixture()?;
    let runner = Runner::default();
    let at = f.vault.now_recorded_at();
    let mut stranger = terms(DIGEST);
    stranger["protected"] = json!(["member:5"]);
    let mut whole_pool = terms(DIGEST);
    whole_pool["bountyShare"] = json!(1.0);
    let rows = f.rows()?;

    for (key, terms, why) in [
        (
            "protects-a-stranger",
            stranger,
            "protects only its own members",
        ),
        (
            "bounty-takes-the-pool",
            whole_pool,
            "a bounty share lies in [0, 1)",
        ),
    ] {
        let view = f.launch_as_owner(
            key,
            ask(CoordinationPattern::Market, 3, Some(terms))?,
            &runner,
            at,
        )?;
        let refusal = refused(&view);
        assert!(refusal.contains(why), "{key}: {refusal}");
    }
    assert_eq!(
        runner.runs(),
        0,
        "no pattern runs for terms no ledger opens on"
    );
    assert_eq!(f.rows()?, rows, "nothing is queued");
    Ok(())
}

#[test]
fn market_terms_on_a_spawn_that_launches_no_planned_team_are_refused() -> TestResult {
    let f = fixture()?;
    let leased = f.lease_parent()?;
    // This leased host binds no planner, so its spawns name their target.
    let host = HostSelfDispatcher::for_leased_agent_attempt(
        &f.vault,
        WriteActor::new(f.parent, EdgeActorClass::Agent),
        &leased,
    )?;
    let spawn =
        |key: &str, market: Option<Value>| -> TestResult<oneiron::Result<SelfDispatchOutcome>> {
            let mut input = json!({
                "need": "score the granite suite",
                "prompt": PROMPT,
                "intent_key": key,
                "agent": f.seat.to_hex(),
            });
            if let Some(market) = market {
                input["market"] = market;
            }
            let input: AgentSpawnInput = serde_json::from_value(input)?;
            Ok(host.dispatch(SelfCall::AgentsSpawn(Box::new(input.into_call()?))))
        };

    let queue = AttemptQueue::new(&f.vault);
    let rows = queue.list()?.len();
    let Err(error) = spawn("direct-market", Some(terms(DIGEST)))? else {
        panic!("a direct spawn carrying market terms is refused, not run")
    };
    assert!(
        error
            .to_string()
            .contains("market terms bind a team this host launches"),
        "{error}"
    );
    assert_eq!(
        queue.list()?.len(),
        rows,
        "the refused spawn queued no child"
    );

    // The same spawn without terms runs its target.
    let outcome = spawn("direct-plain", None)??;
    assert!(
        matches!(
            outcome,
            SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { .. })
        ),
        "{outcome:?}"
    );
    assert_eq!(
        queue.list()?.len(),
        rows + 1,
        "the plain spawn queued its child"
    );
    Ok(())
}

/// main's `SelfSpawnAsk` at c4cef1fccb0 (crates/oneiron/src/code_run/types/request.rs:329-353),
/// frozen: the shape every stored intent's ask, and its digest, was written in before
/// `market` existed (Engine ACCEPT 12:10, condition 1).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainSelfSpawnAsk {
    need: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    care: Option<CareLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<SpawnOverride<ModelId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    width: Option<SpawnOverride<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pattern: Option<SpawnOverride<CoordinationPattern>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_cap_units: Option<SpawnOverride<u64>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    balance_free_prompt: bool,
}

/// The owner's ask digest as `ask_digest` (planner_live/intent.rs) takes it:
/// BLAKE3 under its context over the ask, the prompt and the requested type,
/// rmp named.
fn owner_ask_digest(ask: &impl Serialize, prompt: &str) -> TestResult<[u8; 32]> {
    let requested_type: Option<TaskTypeRef> = None;
    let bytes = rmp_serde::to_vec_named(&(ask, prompt, &requested_type))?;
    let mut hasher = blake3::Hasher::new_derive_key(ASK_DIGEST_CONTEXT);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

#[test]
fn an_ask_without_terms_encodes_and_digests_as_mains() -> TestResult {
    let model = || ModelId::new("local/fixture-model@1");
    let ask = SelfSpawnAsk {
        need: "score the granite suite".to_owned(),
        care: Some(CareLevel::High),
        notes: Some("one model family".to_owned()),
        model: Some(SpawnOverride::Seed {
            value: model()?,
            weight_runs: 2.0,
        }),
        width: Some(SpawnOverride::Pin { value: 3 }),
        pattern: Some(SpawnOverride::Pin {
            value: CoordinationPattern::Market,
        }),
        budget_cap_units: Some(SpawnOverride::Seed {
            value: 900,
            weight_runs: 1.0,
        }),
        balance_free_prompt: true,
        market: None,
    };
    let main = MainSelfSpawnAsk {
        need: ask.need.clone(),
        care: Some(CareLevel::High),
        notes: ask.notes.clone(),
        model: Some(SpawnOverride::Seed {
            value: model()?,
            weight_runs: 2.0,
        }),
        width: Some(SpawnOverride::Pin { value: 3 }),
        pattern: Some(SpawnOverride::Pin {
            value: CoordinationPattern::Market,
        }),
        budget_cap_units: Some(SpawnOverride::Seed {
            value: 900,
            weight_runs: 1.0,
        }),
        balance_free_prompt: true,
    };
    assert_eq!(
        rmp_serde::to_vec_named(&ask)?,
        rmp_serde::to_vec_named(&main)?,
        "an ask without terms encodes byte for byte as main's"
    );
    assert_eq!(
        owner_ask_digest(&ask, PROMPT)?,
        owner_ask_digest(&main, PROMPT)?,
        "so every stored intent keeps its ask digest"
    );
    let bare = SelfSpawnAsk {
        need: "a bare need".to_owned(),
        care: None,
        notes: None,
        model: None,
        width: None,
        pattern: None,
        budget_cap_units: None,
        balance_free_prompt: false,
        market: None,
    };
    let bare_main: MainSelfSpawnAsk = serde_json::from_value(json!({"need": "a bare need"}))?;
    assert_eq!(
        rmp_serde::to_vec_named(&bare)?,
        rmp_serde::to_vec_named(&bare_main)?
    );
    // Terms are part of the ask: the same key with other terms names another ask.
    let termed = SelfSpawnAsk {
        market: Some(serde_json::from_value(terms(DIGEST))?),
        ..ask
    };
    assert_ne!(
        owner_ask_digest(&termed, PROMPT)?,
        owner_ask_digest(&main, PROMPT)?
    );
    Ok(())
}

#[test]
fn a_guest_named_setter_or_time_in_planned_terms_does_not_decode() -> TestResult {
    let owner = |market: Value| -> Result<SpawnIntentRequest, serde_json::Error> {
        serde_json::from_value(json!({
            "intent_key": "owner-market",
            "prompt": PROMPT,
            "need": "score the granite suite",
            "market": market,
        }))
    };
    let leased = |market: Value| -> Result<AgentSpawnInput, serde_json::Error> {
        serde_json::from_value(json!({
            "need": "score the granite suite",
            "prompt": PROMPT,
            "intent_key": "leased-market",
            "market": market,
        }))
    };
    assert!(
        owner(terms(DIGEST))?.market.is_some(),
        "the owner's ask takes the terms"
    );
    assert!(
        leased(terms(DIGEST))?.market.is_some(),
        "a leased ask takes the same terms"
    );
    let mut setter = terms(DIGEST);
    setter["referee"]["setter"] = json!(EntityId::from_bytes([0x5C; 16])?.to_hex());
    let mut signed_at = terms(DIGEST);
    signed_at["signedAt"] = json!(1);
    for named in [setter, signed_at] {
        assert!(
            owner(named.clone()).is_err(),
            "the owner door names no setter or time"
        );
        assert!(leased(named).is_err(), "nor does a leased spawn");
    }
    Ok(())
}

/// [RSI-SEALED-EVAL]: a planned market's referee contract is pinned in the
/// writer that queues the group, so a NOTE that is not sealed drops the whole
/// group.
#[test]
fn a_planned_market_whose_contract_is_not_sealed_queues_nothing() -> TestResult {
    let f = fixture()?;
    let runner = Runner::default();
    let at = f.vault.now_recorded_at();
    let note = f
        .vault
        .create_note(
            "research",
            "the referee contract, not sealed",
            WriteActor::new(f.person, EdgeActorClass::Human),
        )
        .map_err(|error| format!("FIXTURE: the NOTE is written: {error:?}"))?;
    let mut unsealed = terms(DIGEST);
    unsealed["referee"]["contract"] = json!(note.to_hex());
    let rows = f.rows()?;

    let view = f.launch_as_owner(
        "unsealed-contract",
        ask(CoordinationPattern::Market, 3, Some(unsealed))?,
        &runner,
        at,
    )?;

    let refusal = refused(&view);
    assert!(refusal.contains("is not sealed"), "{refusal}");
    assert_eq!(f.rows()?, rows, "nothing is queued");
    Ok(())
}
