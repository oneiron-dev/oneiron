//! Row RESTORED-UNJOINED-STARTS-NO-WORK, part 2 (Setting DESIGN pass 15e "Joined"; RULING
//! RESTORED-UNJOINED-OWNER-DIRECT-WORK = A: "gate queued agent turns, scheduled jobs, and every
//! send"): a copy restored into an empty place on a vault a root roots, which has not joined,
//! starts none of the image's scheduled work or hooks.
//! - A job whose run starts the image's work inline (an actor's timer turn programs, here) waits:
//!   a "run now" runs none of its rows, the runner's pass runs none, the row stays due as it was
//!   armed, and it wakes no stopped copy. The first pass after the owner's join runs it.
//! - The fact-hook runner runs no hook: a fact that lands on the copy waits at the hook's cursor,
//!   and the first pass after the join runs the hook on it. Its report names the unjoined copy
//!   with hooks off as with hooks on.
//! - A vault no restore made runs both as before.
//!
//! On the base (#10257's head 93377510b705) the unjoined copy runs its timer row and its hook as
//! the source does: the tests fail at the "run now runs nothing" and "no hook runs" asserts. On
//! part 2's first head (e87e437ce7dc) a pass with hooks off reports no unjoined copy: the
//! hooks-off test fails at its "names the unjoined copy" assert.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_unjoined_runners`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::{
    FactHookRunner, HookBodyRun, HookBodyRuntime, HookPassReport, HookRunContext,
};
use oneiron::schedule::{JobOutcome, ScheduleRunReport, Trigger};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::schedule::{arm_as_engine, due_at, run_job_now};
use oneiron::test_support::test_host_issuer;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};

/// The job an actor's timer turn programs arm: one whose run starts the image's work inline.
const TIMER_JOB: &str = "dreamer_runner.program_timer";
/// The actor the timer row is about; it holds no timer arming, so a run of the row is done.
const TIMER_ACTOR_SEED: u8 = 0x71;
/// The fact hook the host's agent binds, and the predicate of the facts it watches.
const HOOK: &str = "unjoined-watch";
const PREDICATE: &str = "example.unjoined.input";
/// Facts one hook pass reads at most.
const PASS_ENTRIES: usize = 256;

/// The vault's first install: rooted, with its owner bound, its own unanswered serving profile,
/// the vault's root held as its owner key, and an agent's fact hook bound. It never restored, so
/// it is joined.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    vault_id: [u8; 32],
}

fn timer_actor() -> EntityId {
    EntityId::from_bytes([TIMER_ACTOR_SEED; 16]).expect("FIXTURE: the timer actor's id")
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    let agent = vault
        .ensure_agent_principal("restored-unjoined-hook-agent")
        .expect("FIXTURE: the hook's agent");
    bind_fact_hook(&vault, agent);
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        vault_id,
    }
}

/// The agent's own put of its `local` pack with one fact hook on [`PREDICATE`] claims.
fn bind_fact_hook(vault: &Vault, agent: EntityId) {
    let pack_md = format!(
        "---\nname: local\ndescription: Agent local pack for restored copy hook tests.\nversion: 1\nkind: capability\nhooks: [\"{HOOK}\"]\n---\nLocal pack.\n"
    );
    let hook_md = format!(
        "---\nname: {HOOK}\nversion: 1.0.0\nverbs: [\"claim.landed:{PREDICATE}\"]\nphase: fact\noutcomes: [\"nothing\"]\n---\n{HOOK} watches its input.\n"
    );
    let files = vec![
        HubFile::new("PACK.md", pack_md),
        HubFile::new(format!("hooks/{HOOK}/HOOK.md"), hook_md),
        HubFile::new(
            format!("hooks/{HOOK}/intent.md"),
            format!("Watch {PREDICATE} claims and do nothing."),
        ),
        HubFile::new(
            format!("hooks/{HOOK}/body.js"),
            "return {kind: \"nothing\"};",
        ),
    ];
    let writer = vault
        .observed_write_actor(WriteActor::new(agent, EdgeActorClass::Agent))
        .expect("FIXTURE: the agent writer");
    match vault
        .put_local_pack_as_agent(&writer, files)
        .expect("FIXTURE: the agent puts its local pack")
    {
        PackInstallDisposition::Installed(_) => {}
        other => panic!("FIXTURE: the agent's put installs local: {other:?}"),
    }
    let bound = vault
        .pack_hook_bindings()
        .expect("FIXTURE: the hook bindings")
        .into_iter()
        .any(|(_, row)| row.pack == "local" && row.hook == HOOK && row.enabled);
    assert!(bound, "FIXTURE: the agent's fact hook binds, enabled");
}

/// A copy restored beside a host from its checkpoint image, with its own keystore and owner
/// proof: born of a restore, and no machine of the vault yet.
struct Copy {
    vault: Vault,
    proof: AuthenticatedOwner,
}

/// The copy of `host` restored from an image taken now into an empty place under `backups`.
fn restored_copy(host: &Host, backups: &Path) -> Copy {
    let image = backups.join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("FIXTURE: the beside restore source");
    let (vault, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &backups.join("copy"),
        VaultConfig::device(),
        &origin,
        200,
    )
    .expect("FIXTURE: a copy of the image");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: an owner proof on the copy");
    let encryption = vault
        .machine_encryption_key(host.vault_id)
        .expect("FIXTURE: the copy's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, encryption)
        .expect("FIXTURE: the copy's enrolment request");
    assert!(
        vault
            .authority_fold()
            .expect("FIXTURE: the copy's fold")
            .machine(request.machine)
            .is_none(),
        "FIXTURE: the copy is no machine of the vault yet"
    );
    Copy { vault, proof }
}

/// The owner's word that no other machine is left joins `copy` (`Vault::join_restored_install`),
/// with the vault's root held on it as the owner's key.
fn owner_joins(host: &Host, copy: &Copy) {
    copy.vault
        .hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    copy.vault
        .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered)
        .expect("the owner's word joins the copy");
}

/// The timer row about [`timer_actor`], armed due now on `vault`: its due time.
fn arm_timer_row(vault: &Vault) -> u64 {
    let at = vault.now_recorded_at();
    arm_as_engine(vault, TIMER_JOB, Some(timer_actor()), Trigger::At { at })
        .expect("FIXTURE: the timer row is armed");
    at
}

fn timer_row_due(vault: &Vault) -> Option<u64> {
    due_at(vault, TIMER_JOB, Some(timer_actor())).expect("the schedule reads")
}

/// One pass of the schedule's runner on `vault`.
fn run_due(vault: &Vault) -> ScheduleRunReport {
    vault
        .run_due(HousekeepingBudget::unbounded())
        .expect("the runner's pass answers")
}

/// What became of the timer row in `report`, if the pass ran it.
fn timer_run(report: &ScheduleRunReport) -> Option<JobOutcome> {
    let actor = timer_actor().to_hex();
    report
        .runs
        .iter()
        .find(|run| run.job == TIMER_JOB && run.subject.as_deref() == Some(actor.as_str()))
        .map(|run| run.outcome.clone())
}

#[test]
fn an_unjoined_copy_runs_no_timer_row_until_its_join() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    let at = arm_timer_row(&copy.vault);

    assert_eq!(
        run_job_now(&copy.vault, TIMER_JOB, Some(timer_actor())).expect("a run now answers"),
        None,
        "a run now of the timer row runs nothing on the unjoined copy"
    );
    let report = run_due(&copy.vault);
    assert_eq!(
        timer_run(&report),
        None,
        "the runner's pass runs no timer row on the unjoined copy: {report:?}"
    );
    assert_eq!(
        timer_row_due(&copy.vault),
        Some(at),
        "the held row stays due as it was armed"
    );
    assert_ne!(
        copy.vault
            .housekeeping_wake_at()
            .expect("the copy's wake reads"),
        Some(at),
        "the held row wakes no stopped copy"
    );

    owner_joins(&host, &copy);
    let report = run_due(&copy.vault);
    assert_eq!(
        timer_run(&report),
        Some(JobOutcome::Done),
        "the first pass after the join runs the held row: {report:?}"
    );
    assert_eq!(
        timer_row_due(&copy.vault),
        None,
        "the row ran: an actor with no timer left keeps no row"
    );
}

#[test]
fn a_vault_no_restore_made_runs_its_timer_row_as_before() {
    let host = rooted_host();
    arm_timer_row(&host.vault);
    let report = run_due(&host.vault);
    assert_eq!(
        timer_run(&report),
        Some(JobOutcome::Done),
        "a vault no restore made runs its due timer row: {report:?}"
    );
}

/// A hook sandbox that always emits `nothing`, whatever body it runs.
struct AlwaysNothingRuntime;

impl HookBodyRuntime for AlwaysNothingRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        Ok(HookBodyRun {
            outcome_json: r#"{"kind":"nothing"}"#.to_owned(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// One landed claim with [`PREDICATE`] about a fresh person on `vault`.
fn land_fact(vault: &Vault) {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"hook subject",
        )
        .expect("FIXTURE: the claim's subject");
    let body = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(subject),
        rmpv::Value::from("fixture input"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: the claim body");
    vault
        .put_claim(&EntityId::now(), &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("FIXTURE: the fact lands");
}

/// The report of one fact-hook pass on `vault`.
fn hook_pass(vault: &Vault) -> HookPassReport {
    FactHookRunner::new()
        .run_pass(vault, &AlwaysNothingRuntime, PASS_ENTRIES)
        .expect("the hook pass answers")
}

/// How many hook runs one fact-hook pass on `vault` made.
fn hook_runs(vault: &Vault) -> usize {
    hook_pass(vault).runs
}

#[test]
fn an_unjoined_copy_runs_no_fact_hook_until_its_join() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    land_fact(&copy.vault);

    assert_eq!(
        hook_runs(&copy.vault),
        0,
        "the unjoined copy runs no hook on the fact"
    );
    assert_eq!(
        hook_runs(&copy.vault),
        0,
        "a second pass runs none either: the fact waits"
    );

    owner_joins(&host, &copy);
    assert_eq!(
        hook_runs(&copy.vault),
        1,
        "the first pass after the join runs the hook on the fact that waited"
    );
}

#[test]
fn a_hook_pass_names_an_unjoined_copy_with_hooks_off() {
    let host = rooted_host();
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    copy.vault
        .set_hooks_enabled(&copy.proof, false)
        .expect("the owner turns hooks off on the copy");

    let report = hook_pass(&copy.vault);
    assert!(report.disabled, "hooks are off on the copy: {report:?}");
    assert!(
        report.unjoined,
        "the pass names the unjoined copy with hooks off as with hooks on: {report:?}"
    );

    owner_joins(&host, &copy);
    let report = hook_pass(&copy.vault);
    assert!(
        report.disabled && !report.unjoined,
        "the joined copy's pass with hooks off names no unjoined copy: {report:?}"
    );
}

#[test]
fn a_vault_no_restore_made_runs_its_fact_hook_as_before() {
    let host = rooted_host();
    land_fact(&host.vault);
    assert_eq!(
        hook_runs(&host.vault),
        1,
        "a vault no restore made runs its hook on the fact"
    );
}
