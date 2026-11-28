#![cfg(oneiron_test_support)]
//! [RSI-PROJECT-WORKFLOW]: an admitted callable SKILL armed as one run of a
//! project, through `vault.turn_programs.arm` with an expected pin and a
//! bound project, on a timer that advances it.
//!
//! - T1 `an_armed_workflow_pins_the_exact_admitted_revision`: a matching
//!   expected pin arms; a wrong hash or another version refuses; an active
//!   callable whose approval does not stand refuses (VISIBLE: before, any
//!   active callable armed); a standing arming whose approval is withdrawn
//!   is refused at its next wake.
//! - T2 `arm_refuses_args_off_the_contract`: arguments off the call contract
//!   refuse, as before.
//! - T3 `an_armed_workflow_is_one_project_run`: a project the arming actor
//!   does not lead, sit on the board of or hold a seat in refuses, so does a
//!   fork another project lists and a turn trigger; the run of an armed
//!   occurrence sends in the stated project.
//! - T3b `a_projectless_program_reads_no_project_row`: the same recipe armed
//!   with no project sends in none (never a wider read).
//! - T4 `the_same_definition_returns_the_standing_registration`: project and
//!   pin are in the definition.
//! - T6 `the_next_target_reuses_the_package`: new arguments arm a new
//!   registration on the same pin; a project fork arms only once admitted,
//!   at its own pin.
//! - The timer ends (every_secs = 120, the recipe's poll: a pending GPU stage
//!   is read at most once every two minutes): a finished entry that answers
//!   no pending stage disarms the program in its settle writer, a refused
//!   write disarms it in the commit that keeps the refusal, and no later due
//!   time wakes it; a pending answer keeps it waking; a program armed for no
//!   project keeps waking as before.
//!
//! On the base `ArmTurnProgram` has no `expected` or `project`, so this
//! file does not build there; each red is a revert pin of one fix on the
//! head.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test turn_program_workflow`.

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    ArmTurnProgram, ExpectedSkillRevision, ProgramTrigger, TurnProgramDrain,
    TurnProgramRegistration,
};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::schedule::JobOutcome;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::project_run::{
    any_program_armed, entry_run_project, lease_program_entry, settle_program_entry,
    settle_refused_program_write,
};
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// A due time well past any clock the vault records in a test.
const T0: u64 = 4_000_000_000;
/// The recipe's timer: a pending GPU stage is polled at most once every two
/// minutes, well under a unit's run time and above the one-a-minute bar.
const EVERY_SECS: u64 = 120;
/// The job an actor's timer programs arm (stage 5b-3).
const TIMER_JOB: &str = "dreamer_runner.program_timer";

/// A rooted vault on a clock the test moves, with its embedded owner bound
/// to the host, the owner's proof and the host's slip issuer.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let clock = ManualClock::new(T0 - 60);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let dir = tempfile::tempdir().expect("temporary vault directory");
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

/// A callable SKILL record at version `version`, approval `approval`, with
/// its content hash; answers the record and the hash's hex.
fn callable_record(version: &str, approval: ClaimApprovalStatus) -> (SkillRecord, String) {
    let files: [(&str, &[u8]); 2] = [
        (
            "SKILL.md",
            b"---\nname: fixture.workflow\ndescription: Advance one project workflow\nversion: 1\nrole: callable\ncall:\n  reference: scripts/run.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"pending\":\"boolean\"}\n---\nA workflow fixture.\n",
        ),
        (
            "scripts/run.js",
            b"finish(JSON.stringify({pending:false}));",
        ),
    ];
    let hash = canonical_skill_tree_hash(files).expect("hash the fixture tree");
    let hex = hash.to_hex();
    let record = SkillRecord::new(
        "fixture.workflow",
        "Advance one project workflow",
        version,
        approval,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: "scripts/run.js".into(),
            arguments: serde_json::json!({"value": "integer"}),
            returns: serde_json::json!({"pending": "boolean"}),
        }),
    )
    .with_content_hash(hash);
    (record, hex)
}

impl Fixture {
    /// An active callable at `approval`; answers its id and content hash.
    fn skill(&self, approval: ClaimApprovalStatus) -> (EntityId, String) {
        let id = EntityId::now();
        let (mut record, hash) = callable_record("1", approval);
        self.vault
            .put_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)
            .expect("put the callable candidate");
        record.lifecycle_status = SkillLifecycle::Active;
        self.vault
            .update_skill_record(&id, &record, TimeRange { start: 2, end: 2 }, 2)
            .expect("activate the callable");
        (id, hash)
    }

    /// A callable left a candidate (not admitted).
    fn candidate(&self) -> EntityId {
        let id = EntityId::now();
        let (record, _) = callable_record("1", ClaimApprovalStatus::Proposed);
        self.vault
            .put_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)
            .expect("put the candidate fork");
        id
    }

    /// Admits the candidate `id`: active and approved.
    fn admit(&self, id: EntityId) {
        let (mut record, _) = callable_record("1", ClaimApprovalStatus::Approved);
        record.lifecycle_status = SkillLifecycle::Active;
        self.vault
            .update_skill_record(&id, &record, TimeRange { start: 3, end: 3 }, 3)
            .expect("admit the fork");
    }

    /// Withdraws the approval of the active skill `id`.
    fn withdraw_approval(&self, id: EntityId) {
        let (mut record, _) = callable_record("1", ClaimApprovalStatus::Proposed);
        record.lifecycle_status = SkillLifecycle::Active;
        self.vault
            .update_skill_record(&id, &record, TimeRange { start: 4, end: 4 }, 4)
            .expect("withdraw the approval");
    }

    /// An owner-born project under the root, led by `leader`, listing
    /// `forks` among its skill forks.
    fn project(&self, leader: EntityId, forks: &[EntityId]) -> EntityId {
        let id = EntityId::now();
        let root = self.vault.root_project().expect("root project");
        let mut record = ProjectRecord::new(id, Some(root), root, leader).expect("project record");
        record.skill_forks = forks.iter().map(EntityId::to_hex).collect();
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

    fn arm(&self, input: &ArmTurnProgram) -> Result<TurnProgramRegistration, String> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .arm_turn_program(input)
            .map_err(|error| format!("{error:?}"))
    }

    /// Runs the vault's due jobs at `now`, as the host's tick does; answers
    /// how many timer runs ended done (with one program armed, the wakes
    /// its release recorded).
    fn release_timers_at(&self, now: u64) -> usize {
        self.clock.set(now);
        self.vault
            .run_due(HousekeepingBudget::unbounded())
            .expect("run the due jobs")
            .runs
            .iter()
            .filter(|run| run.job == TIMER_JOB && run.outcome == JobOutcome::Done)
            .count()
    }

    fn drain(&self, now: u64) -> TurnProgramDrain {
        self.vault.wake_turn_programs(now).expect("drain")
    }

    fn armed(&self) -> bool {
        any_program_armed(&self.vault, self.owner).expect("read the armings")
    }
}

fn input(skill: EntityId, trigger: ProgramTrigger) -> ArmTurnProgram {
    ArmTurnProgram {
        skill,
        executor: "fixture.executor@1".into(),
        args: serde_json::json!({"value": 41}),
        conversation: None,
        trigger,
        expected: None,
        project: None,
    }
}

const fn timer(every_secs: u64) -> ProgramTrigger {
    ProgramTrigger::Timer {
        first_at: T0,
        every_secs,
    }
}

/// T1: the exact admitted revision.
#[test]
fn an_armed_workflow_pins_the_exact_admitted_revision() {
    let f = fixture();
    let (skill, hash) = f.skill(ClaimApprovalStatus::Approved);
    let mut pinned = input(skill, timer(0));
    pinned.expected = Some(ExpectedSkillRevision {
        version: "1".into(),
        content_hash: hash.clone(),
    });
    let armed = f
        .arm(&pinned)
        .unwrap_or_else(|error| panic!("the expected revision arms: {error}"));
    assert_eq!(
        (
            armed.definition.version.as_str(),
            armed.definition.content_hash.as_str()
        ),
        ("1", hash.as_str()),
        "{armed:?}"
    );

    let mut wrong_hash = input(skill, timer(EVERY_SECS));
    wrong_hash.expected = Some(ExpectedSkillRevision {
        version: "1".into(),
        content_hash: "0".repeat(64),
    });
    assert!(f.arm(&wrong_hash).is_err(), "a wrong content hash refuses");
    let mut moved = input(skill, timer(EVERY_SECS));
    moved.expected = Some(ExpectedSkillRevision {
        version: "2".into(),
        content_hash: hash,
    });
    assert!(f.arm(&moved).is_err(), "another version refuses");

    // VISIBLE: an active callable whose approval does not stand no longer arms.
    let (proposed, _) = f.skill(ClaimApprovalStatus::Proposed);
    let refused = f.arm(&input(proposed, timer(0)));
    assert!(
        refused.is_err(),
        "an unapproved active callable refuses; seen {refused:?}"
    );

    // A standing arming whose approval is withdrawn is refused at its next wake.
    f.withdraw_approval(skill);
    assert_eq!(f.release_timers_at(T0), 1, "the due time releases");
    let judged = f.drain(T0);
    assert_eq!(
        (judged.admitted, judged.refused),
        (0, 1),
        "the wake of an arming whose approval was withdrawn is refused: {judged:?}"
    );
}

/// T2: the call contract still decides the arguments.
#[test]
fn arm_refuses_args_off_the_contract() {
    let f = fixture();
    let (skill, _) = f.skill(ClaimApprovalStatus::Approved);
    let mut off = input(skill, timer(0));
    off.args = serde_json::json!({"value": "forty-one"});
    assert!(f.arm(&off).is_err(), "arguments off the contract refuse");
}

/// T3: one project run.
#[test]
fn an_armed_workflow_is_one_project_run() {
    let f = fixture();
    let (shared, _) = f.skill(ClaimApprovalStatus::Approved);
    let (foreign_fork, _) = f.skill(ClaimApprovalStatus::Approved);
    let led = f.project(f.owner, &[]);
    let elsewhere = f.project(f.owner, &[foreign_fork]);
    let not_reached = f.project(EntityId::now(), &[]);

    let mut outside = input(shared, timer(EVERY_SECS));
    outside.project = Some(not_reached);
    assert!(
        f.arm(&outside).is_err(),
        "a project the actor neither leads, sits on the board of nor holds a seat in refuses"
    );
    let mut fork_of_another = input(foreign_fork, timer(EVERY_SECS));
    fork_of_another.project = Some(led);
    assert!(
        f.arm(&fork_of_another).is_err(),
        "a fork another project lists refuses"
    );
    let mut own_fork = input(foreign_fork, timer(0));
    own_fork.project = Some(elsewhere);
    assert!(
        f.arm(&own_fork).is_ok(),
        "the project that lists the fork arms it"
    );
    let mut on_turns = input(shared, ProgramTrigger::Turn);
    on_turns.project = Some(led);
    assert!(f.arm(&on_turns).is_err(), "a turn trigger names no project");

    let mut run = input(shared, timer(EVERY_SECS));
    run.project = Some(led);
    let armed = f
        .arm(&run)
        .unwrap_or_else(|error| panic!("the led project arms the shared skill: {error}"));
    assert_eq!(armed.definition.project, Some(led), "{armed:?}");
    f.release_timers_at(T0);
    let admitted = f.drain(T0);
    assert!(admitted.admitted >= 1, "{admitted:?}");
    let mut sent = Vec::new();
    while let Some(entry) = lease_program_entry(&f.vault, T0).expect("lease") {
        sent.push(entry_run_project(&f.vault, &entry).expect("read the run's project"));
    }
    assert!(
        sent.contains(&Some(led)),
        "the armed run sends in the stated project: {sent:?}"
    );
}

/// T3b: no project, no project read.
#[test]
fn a_projectless_program_reads_no_project_row() {
    let f = fixture();
    let (skill, _) = f.skill(ClaimApprovalStatus::Approved);
    let _led = f.project(f.owner, &[]);
    f.arm(&input(skill, timer(0)))
        .unwrap_or_else(|error| panic!("the recipe arms with no project: {error}"));
    assert_eq!(f.release_timers_at(T0), 1);
    let admitted = f.drain(T0);
    assert_eq!(admitted.admitted, 1, "{admitted:?}");
    let entry = lease_program_entry(&f.vault, T0)
        .expect("lease")
        .expect("the admitted try");
    assert_eq!(
        entry_run_project(&f.vault, &entry).expect("read the run's project"),
        None,
        "a program armed for no project sends in none"
    );
}

/// T4: project and pin are the definition.
#[test]
fn the_same_definition_returns_the_standing_registration() {
    let f = fixture();
    let (skill, hash) = f.skill(ClaimApprovalStatus::Approved);
    let first_project = f.project(f.owner, &[]);
    let second_project = f.project(f.owner, &[]);
    let mut run = input(skill, timer(EVERY_SECS));
    run.project = Some(first_project);
    run.expected = Some(ExpectedSkillRevision {
        version: "1".into(),
        content_hash: hash,
    });
    let first = f.arm(&run).expect("arm");
    let again = f.arm(&run).expect("arm again");
    assert!(
        first.newly_armed && !again.newly_armed,
        "{first:?} {again:?}"
    );
    assert_eq!(first.registration, again.registration);
    run.project = Some(second_project);
    let other = f.arm(&run).expect("arm for another project");
    assert!(other.newly_armed, "{other:?}");
    assert_ne!(other.registration, first.registration);
    assert_ne!(
        other.revision, first.revision,
        "the project is in the definition"
    );
}

/// T6: the next target reuses the package; a fork arms once admitted.
#[test]
fn the_next_target_reuses_the_package() {
    let f = fixture();
    let (skill, _) = f.skill(ClaimApprovalStatus::Approved);
    let fork = f.candidate();
    let project = f.project(f.owner, &[fork]);
    let mut first = input(skill, timer(EVERY_SECS));
    first.project = Some(project);
    let first = f.arm(&first).expect("arm the first target");
    let mut next = input(skill, timer(EVERY_SECS));
    next.project = Some(project);
    next.args = serde_json::json!({"value": 42});
    let next = f.arm(&next).expect("arm the next target");
    assert_ne!(next.registration, first.registration);
    assert_eq!(
        (
            &next.definition.skill,
            &next.definition.version,
            &next.definition.content_hash
        ),
        (
            &first.definition.skill,
            &first.definition.version,
            &first.definition.content_hash
        ),
        "the same package at the same pin"
    );

    let mut forked = input(fork, timer(EVERY_SECS));
    forked.project = Some(project);
    assert!(f.arm(&forked).is_err(), "a fork not yet admitted refuses");
    f.admit(fork);
    let armed = f.arm(&forked).expect("the admitted fork arms");
    assert_eq!(armed.definition.skill, fork, "at its own pin: {armed:?}");
}

/// The timer ends at a finished entry that answers no pending stage.
#[test]
fn a_finished_project_run_stops_waking() {
    let f = fixture();
    let (skill, _) = f.skill(ClaimApprovalStatus::Approved);
    let project = f.project(f.owner, &[]);
    let mut run = input(skill, timer(EVERY_SECS));
    run.project = Some(project);
    f.arm(&run).expect("arm");
    assert_eq!(f.release_timers_at(T0), 1);
    assert_eq!(f.drain(T0).admitted, 1);
    let entry = lease_program_entry(&f.vault, T0)
        .expect("lease")
        .expect("the admitted try");
    settle_program_entry(&f.vault, &entry, false, T0).expect("settle the entry");
    assert!(!f.armed(), "the settle writer disarmed the finished run");
    assert_eq!(
        f.release_timers_at(T0 + EVERY_SECS),
        0,
        "no later due time wakes it"
    );
}

/// A pending answer keeps the run waking at its next due time.
#[test]
fn a_pending_project_run_keeps_waking() {
    let f = fixture();
    let (skill, _) = f.skill(ClaimApprovalStatus::Approved);
    let project = f.project(f.owner, &[]);
    let mut run = input(skill, timer(EVERY_SECS));
    run.project = Some(project);
    f.arm(&run).expect("arm");
    assert_eq!(f.release_timers_at(T0), 1);
    assert_eq!(f.drain(T0).admitted, 1);
    let entry = lease_program_entry(&f.vault, T0)
        .expect("lease")
        .expect("the admitted try");
    settle_program_entry(&f.vault, &entry, true, T0).expect("settle the entry");
    assert!(f.armed(), "a pending stage keeps the program armed");
    assert_eq!(
        f.release_timers_at(T0 + EVERY_SECS),
        1,
        "the next due time wakes it"
    );
}

/// A refused stage disarms the run in the commit that keeps the refusal,
/// and no further wake runs the entry.
#[test]
fn a_refused_stage_stops_the_run() {
    let f = fixture();
    let (skill, _) = f.skill(ClaimApprovalStatus::Approved);
    let project = f.project(f.owner, &[]);
    let mut run = input(skill, timer(EVERY_SECS));
    run.project = Some(project);
    f.arm(&run).expect("arm");
    assert_eq!(f.release_timers_at(T0), 1);
    assert_eq!(f.drain(T0).admitted, 1);
    let entry = lease_program_entry(&f.vault, T0)
        .expect("lease")
        .expect("the admitted try");
    settle_refused_program_write(&f.vault, &entry, T0).expect("settle the refused write");
    assert!(!f.armed(), "the refused stage's commit disarmed the run");
    assert_eq!(
        f.release_timers_at(T0 + EVERY_SECS),
        0,
        "no further wake runs the entry"
    );
    let later = f.drain(T0 + EVERY_SECS);
    assert_eq!(later.admitted, 0, "{later:?}");
}

/// A program armed for no project keeps waking after a finished entry, as
/// before.
#[test]
fn a_projectless_program_keeps_waking_after_its_entry() {
    let f = fixture();
    let (skill, _) = f.skill(ClaimApprovalStatus::Approved);
    f.arm(&input(skill, timer(EVERY_SECS))).expect("arm");
    assert_eq!(f.release_timers_at(T0), 1);
    assert_eq!(f.drain(T0).admitted, 1);
    let entry = lease_program_entry(&f.vault, T0)
        .expect("lease")
        .expect("the admitted try");
    settle_program_entry(&f.vault, &entry, false, T0).expect("settle the entry");
    assert!(f.armed(), "a program armed for no project stays armed");
    assert_eq!(f.release_timers_at(T0 + EVERY_SECS), 1);
}
