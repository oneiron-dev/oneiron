//! DESIGN 15-setting-primitive, stage 0.2: the Schedule primitive through its public verbs and
//! its one runner.
//! - an interval runs when due; one that comes late runs once, then goes on from now;
//! - a deadline fires once, late; a job that lapses drops a late occurrence unrun;
//! - a failing job backs off from a minute, doubling; a paged job runs to its end in one pass;
//! - an agent arms an actor job under its own Grant, re-arms and disarms only its own arming,
//!   and never an engine job, which only the engine arms;
//! - "run now" makes a job due at once; the housekeeping pass runs due jobs, and a stopped
//!   vault's wake time reads the first due job that wakes its host;
//! - a wall-clock job is due at its next occurrence in its zone; an unknown zone is refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test schedule_primitive`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::Memory;
use oneiron::schedule::{JobOutcome, Trigger};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::schedule::{arm_as_engine, runs};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const LIST: &str = "vault.schedules.list";
const ARM: &str = "vault.schedules.arm";
const DISARM: &str = "vault.schedules.disarm";
const RUN: &str = "vault.schedules.run";
const T0: u64 = 1_790_000_000;
const HOUR: u64 = 3_600;
const DAY: u64 = 24 * HOUR;

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("open vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            clock,
            _dir: dir,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn as_agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }

    /// An enabled, active agent definition the owner creates, with the owner's live Grant
    /// naming `read` and `verbs`.
    fn agent(&self, verbs: &[&str]) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("schedule-agent-{}", id.to_hex()),
                    "desc": "schedule primitive fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent: id,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the Grant");
        id
    }

    fn at(&self, now: u64) {
        self.clock.set(now);
    }

    /// One runner pass; the outcomes of the runs it made.
    fn run_due(&self) -> Vec<JobOutcome> {
        self.vault
            .run_due(HousekeepingBudget::unbounded())
            .expect("the runner")
            .runs
            .into_iter()
            .map(|run| run.outcome)
            .collect()
    }

    /// The owner's view of `job` about `subject`, if armed.
    fn view(&self, job: &str, subject: EntityId) -> Option<Value> {
        let listed = call(
            &self.as_owner(),
            LIST,
            json!({ "job": job, "subject": subject.to_hex() }),
        );
        listed["schedules"]
            .as_array()
            .expect("schedules")
            .first()
            .cloned()
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) {
    invoke(memory, verb, input).expect_err("the call is refused");
}

fn arm(job: &str, subject: EntityId, trigger: Value) -> Value {
    json!({ "job": job, "subject": subject.to_hex(), "trigger": trigger })
}

fn every(secs: u64) -> Value {
    json!({ "kind": "every", "secs": secs })
}

#[test]
fn an_interval_runs_when_due_and_a_late_one_runs_once_then_goes_on_from_now() {
    let fx = Fixture::rooted();
    let subject = EntityId::now();
    let armed = call(&fx.as_owner(), ARM, arm("test.count", subject, every(HOUR)));
    assert_eq!(armed["due_at"], json!(T0), "{armed}");

    assert_eq!(fx.run_due(), vec![JobOutcome::Done]);
    assert_eq!(runs("test.count", Some(subject)), 1);
    assert_eq!(
        fx.view("test.count", subject).expect("armed")["due_at"],
        json!(T0 + HOUR)
    );
    assert!(fx.run_due().is_empty(), "nothing is due before its time");

    fx.at(T0 + 5 * HOUR + 10);
    assert_eq!(fx.run_due(), vec![JobOutcome::Done]);
    assert_eq!(
        runs("test.count", Some(subject)),
        2,
        "five missed hours run once"
    );
    assert_eq!(
        fx.view("test.count", subject).expect("armed")["due_at"],
        json!(T0 + 6 * HOUR),
        "then it goes on from now"
    );
}

#[test]
fn a_deadline_fires_once_late_and_a_lapsing_job_drops_a_late_occurrence() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let deadline = EntityId::now();
    call(
        &me,
        ARM,
        arm(
            "test.count",
            deadline,
            json!({ "kind": "at", "at": T0 + 100 }),
        ),
    );
    fx.at(T0 + 1_000);
    assert_eq!(fx.run_due(), vec![JobOutcome::Done]);
    assert_eq!(
        runs("test.count", Some(deadline)),
        1,
        "the passed deadline fired, late"
    );
    assert!(
        fx.view("test.count", deadline).is_none(),
        "a deadline is done once it ran"
    );

    let lapsing = EntityId::now();
    call(
        &me,
        ARM,
        arm(
            "test.lapse",
            lapsing,
            json!({ "kind": "at", "at": T0 + 1_100 }),
        ),
    );
    fx.at(T0 + 5_000);
    assert_eq!(fx.run_due(), vec![JobOutcome::Lapsed]);
    assert_eq!(
        runs("test.lapse", Some(lapsing)),
        0,
        "a lapsed occurrence never runs"
    );
    assert!(fx.view("test.lapse", lapsing).is_none());
}

#[test]
fn a_failing_job_backs_off_and_a_paged_job_runs_to_its_end() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let failing = EntityId::now();
    call(&me, ARM, arm("test.fail", failing, every(DAY)));
    assert!(matches!(fx.run_due()[..], [JobOutcome::Failed { .. }]));
    let backing_off = fx.view("test.fail", failing).expect("armed");
    assert_eq!(backing_off["failures"], json!(1));
    assert_eq!(
        backing_off["due_at"],
        json!(T0 + 60),
        "a minute after the first failure"
    );
    fx.at(T0 + 60);
    assert!(matches!(fx.run_due()[..], [JobOutcome::Failed { .. }]));
    let doubled = fx.view("test.fail", failing).expect("armed");
    assert_eq!(doubled["failures"], json!(2));
    assert_eq!(doubled["due_at"], json!(T0 + 60 + 120), "then two minutes");

    let paged = EntityId::now();
    call(&me, ARM, arm("test.paged", paged, every(DAY)));
    assert_eq!(
        fx.run_due(),
        vec![JobOutcome::More, JobOutcome::More, JobOutcome::Done],
        "a run that stopped at its budget is due again at once and keeps its cursor"
    );
    assert_eq!(runs("test.paged", Some(paged)), 3);
    let done = fx.view("test.paged", paged).expect("armed");
    assert_eq!(done["due_at"], json!(T0 + 60 + DAY));
    assert_eq!(done["failures"], json!(0));
}

#[test]
fn an_agent_arms_under_its_grant_and_only_the_engine_arms_an_engine_job() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let agent = fx.agent(&[ARM, LIST, DISARM, RUN]);
    let them = fx.as_agent(agent);
    let own = EntityId::now();

    let armed = call(&them, ARM, arm("test.count", own, every(DAY)));
    assert_eq!(armed["armed_by"], json!(agent.to_hex()), "{armed}");
    let listed = call(&them, LIST, json!({}));
    assert_eq!(listed["schedules"].as_array().expect("schedules").len(), 1);

    refused(&them, ARM, arm("test.engine", own, every(DAY)));
    refused(&me, ARM, arm("test.engine", own, every(DAY)));
    let engine = EntityId::now();
    arm_as_engine(
        &fx.vault,
        "test.engine",
        Some(engine),
        Trigger::Every {
            secs: DAY,
            first_at: None,
        },
    )
    .expect("the engine arms its own job");
    assert!(fx.view("test.engine", engine).is_some());
    refused(
        &them,
        DISARM,
        json!({ "job": "test.engine", "subject": engine.to_hex() }),
    );
    refused(
        &me,
        DISARM,
        json!({ "job": "test.engine", "subject": engine.to_hex() }),
    );

    let owners = EntityId::now();
    call(&me, ARM, arm("test.count", owners, every(DAY)));
    refused(&them, ARM, arm("test.count", owners, every(HOUR)));
    refused(
        &them,
        DISARM,
        json!({ "job": "test.count", "subject": owners.to_hex() }),
    );
    refused(
        &them,
        RUN,
        json!({ "job": "test.count", "subject": owners.to_hex() }),
    );

    let ungranted = fx.agent(&[LIST]);
    refused(
        &fx.as_agent(ungranted),
        ARM,
        arm("test.count", EntityId::now(), every(DAY)),
    );

    let disarmed = call(
        &them,
        DISARM,
        json!({ "job": "test.count", "subject": own.to_hex() }),
    );
    assert_eq!(disarmed, json!({ "disarmed": true }));
    assert!(fx.view("test.count", own).is_none());
}

#[test]
fn run_now_makes_a_job_due_and_the_housekeeping_pass_runs_it() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let subject = EntityId::now();
    call(
        &me,
        ARM,
        arm(
            "test.count",
            subject,
            json!({ "kind": "every", "secs": DAY, "first_at": T0 + DAY }),
        ),
    );
    let wake = fx
        .vault
        .housekeeping_wake_at()
        .expect("wake time")
        .expect("a job that wakes its host is armed");
    assert!(wake <= T0 + DAY, "{wake}");
    assert!(fx.run_due().is_empty(), "due tomorrow");

    let asked = call(
        &me,
        RUN,
        json!({ "job": "test.count", "subject": subject.to_hex() }),
    );
    assert_eq!(asked["due_at"], json!(T0), "{asked}");
    fx.vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("the pass");
    assert_eq!(
        runs("test.count", Some(subject)),
        1,
        "the pass ran the due job"
    );
    assert_eq!(
        fx.view("test.count", subject).expect("armed")["due_at"],
        json!(T0 + DAY)
    );
}

#[test]
fn a_wall_clock_job_is_due_at_its_next_occurrence_in_its_zone() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let subject = EntityId::now();
    let armed = call(
        &me,
        ARM,
        arm(
            "test.count",
            subject,
            json!({ "kind": "civil", "hour": 9, "minute": 0, "zone": "Asia/Tokyo" }),
        ),
    );
    // 09:00 in Tokyo is 00:00 UTC: the next midnight after T0.
    assert_eq!(armed["due_at"], json!(T0.div_ceil(DAY) * DAY), "{armed}");
    refused(
        &me,
        ARM,
        arm(
            "test.count",
            subject,
            json!({ "kind": "civil", "hour": 9, "minute": 0, "zone": "Mars/Olympus" }),
        ),
    );
}
