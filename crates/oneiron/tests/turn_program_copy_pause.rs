//! A vault copy made beside its source starts with its timer, feed and idle turn programs
//! paused (FIX TURNPROGRAM-OCCURRENCE-ARMINGS-LIVE-ON-A-VAULT-COPY, lead ruling 21 Nov): the
//! copy holds the source's armings, both would release every occurrence, and nothing dedupes one
//! between two stores. A restore that takes its source's place pauses nothing.
//!
//! One test per restore door. Each arms, for the vault's owner, a timer that is due, a feed
//! program whose subscription shows its lane an entry, and an idle program whose quiet time has
//! passed, takes a checkpoint before any release, and goes through its door:
//!
//! - D1 `Vault::restore_checkpoint_beside`: paused.
//! - D2 `Vault::restore_checkpoint_beside_within`, the door a backup rehearsal uses: paused.
//! - D3 `Vault::restore_checkpoint_keeping_authority`, the historical restore beside: paused,
//!   a timer armed after the checkpoint included.
//! - D4 `Vault::activate_archived`, the store a replacing restore set aside: paused.
//! - D5 `Vault::restore_checkpoint_replacing` with `Vault::swap_in_replacement`: running.
//! - D6 `Vault::restore_checkpoint`: running.
//!
//! A pass is what a host's tick does for these programs: the vault's due jobs, then the feed
//! release and the idle release. The tests stop at the wake a release records; they admit none
//! on a vault that runs, so they ask nothing of the admission's receipts.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_copy_pause`.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::dreamer_runner::{ArmTurnProgram, ProgramTrigger};
use oneiron::dreamer_wake::WakeIdleState;
use oneiron::feeds::{FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::recovery::checkpoint::{CheckpointKey, RecoveryWriteBudget, RestoreReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::schedule::JobOutcome;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::test_doors::steward::open_owner_carrier_vault;
use oneiron::test_doors::turn_programs as doors;
use oneiron::test_support::{restore_tempdir, test_host_issuer};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// The job an actor's timer programs arm.
const TIMER_JOB: &str = "dreamer_runner.program_timer";

/// The fixture timer's due time: past on any clock a test host keeps, so the vault's due jobs
/// find it due on the recording clock with no clock of the test's own.
const TIMER_DUE: u64 = 1_000;

/// The due time of the timer D3 arms after its checkpoint.
const LATER_TIMER_DUE: u64 = 2_000;

/// The `created_at` every checkpoint below is taken with.
const SNAPSHOT_AT: u64 = 100;

/// The `restored_at` every restore below passes: a copy the restore pauses names it.
const RESTORED_AT: u64 = 200;

/// The idle program's quiet time.
const QUIET_SECS: u64 = 600;

/// The host's last inbound message in the idle check the tests pass, well past any clock a
/// vault records in a test.
const LAST_INBOUND_AT: u64 = 4_000_000_000;

/// The time the feed and idle releases are asked at: the quiet time has passed.
const NOW: u64 = LAST_INBOUND_AT + QUIET_SECS;

/// An active callable SKILL, enough to arm: arming pins the record and never loads its source.
fn active_callable_skill(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let files: [(&str, &[u8]); 2] = [
        (
            "SKILL.md",
            b"---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\nrole: callable\ncall:\n  reference: scripts/call.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\nAn executable fixture.\n",
        ),
        (
            "scripts/call.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));",
        ),
    ];
    let hash = canonical_skill_tree_hash(files).expect("hash the fixture tree");
    let mut record = SkillRecord::new(
        "fixture.callable",
        "Increment a number",
        "1",
        ClaimApprovalStatus::Approved,
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
            reference: "scripts/call.js".into(),
            arguments: serde_json::json!({"value": "integer"}),
            returns: serde_json::json!({"result": "integer"}),
        }),
    )
    .with_content_hash(hash);
    vault
        .put_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)
        .expect("put the callable candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &record, TimeRange { start: 2, end: 2 }, 2)
        .expect("activate the callable");
    id
}

/// An owner vault a checkpoint can be taken of: rooted under the test host, with its data key
/// minted.
fn open_live(path: &Path) -> Vault {
    let vault = open_owner_carrier_vault(path).expect("an owner vault");
    vault.ensure_vault_key().expect("mint the vault data key");
    vault
}

/// The vault's owner and the callable its programs pin.
struct Armer {
    owner: EntityId,
    skill: EntityId,
}

impl Armer {
    /// The embedded owner of `vault` and a fresh active callable there.
    fn new(vault: &Vault) -> Self {
        Self {
            owner: vault.ensure_embedded_owner_actor().expect("the owner"),
            skill: active_callable_skill(vault),
        }
    }

    /// Arms the owner's program on `trigger` through the public door, as the in-process host's
    /// own caller; answers its registration.
    fn arm(&self, vault: &Vault, trigger: ProgramTrigger) -> EntityId {
        vault
            .memory(self.owner, EdgeActorClass::Human)
            .arm_turn_program(&ArmTurnProgram {
                skill: self.skill,
                executor: "fixture.executor@1".into(),
                args: serde_json::json!({"value": 41}),
                conversation: None,
                trigger,
                expected: None,
                project: None,
            })
            .expect("arm the program")
            .registration
    }

    /// Arms a timer that wakes once, at `due`.
    fn arm_timer(&self, vault: &Vault, due: u64) -> EntityId {
        self.arm(
            vault,
            ProgramTrigger::Timer {
                first_at: due,
                every_secs: 0,
            },
        )
    }
}

/// The programs one vault's owner holds in a test: each by a name for the failure texts, and
/// each timer with the due time it was armed at.
struct Programs {
    owner: EntityId,
    armed: Vec<(&'static str, EntityId)>,
    timers: Vec<(EntityId, u64)>,
}

/// Arms the three programs on `vault`: a timer due at [`TIMER_DUE`], a feed program on a
/// change subscription of the owner's own taken at the head, and an idle program that waits
/// [`QUIET_SECS`]. Then writes a PERSON, an entry past the subscription's cursor that the
/// owner's lane is shown, so a feed release has an occurrence to record.
fn seed_programs(vault: &Vault, armer: &Armer) -> Programs {
    let lane = vault.scoped_read(
        ScopedReadActorKey::with_actor_class(armer.owner.to_hex(), "human")
            .expect("the owner's lane key"),
    );
    let subscription = vault
        .feed_subscribe(
            &lane,
            &FeedSubscribeRequest {
                selector: FeedSelector {
                    sources: vec![FeedSource::Changes],
                    kinds: Vec::new(),
                    entity_types: Vec::new(),
                    predicates: Vec::new(),
                },
                start: FeedStart::Head,
            },
        )
        .expect("subscribe to the change feed")
        .subscription;
    let timer = armer.arm_timer(vault, TIMER_DUE);
    let feed = armer.arm(vault, ProgramTrigger::Feed { subscription });
    let idle = armer.arm(
        vault,
        ProgramTrigger::Idle {
            quiet_secs: QUIET_SECS,
        },
    );
    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("the feed's entry");
    Programs {
        owner: armer.owner,
        armed: vec![
            ("timer", timer),
            ("feed program", feed),
            ("idle program", idle),
        ],
        timers: vec![(timer, TIMER_DUE)],
    }
}

/// Takes `live`'s checkpoint at `image`, with the programs armed and none released; answers
/// the key the image opens with.
fn snapshot_live(live: &Vault, image: &Path) -> CheckpointKey {
    let key = live.checkpoint_key().expect("derive the checkpoint key");
    live.snapshot_checkpoint(image, SNAPSHOT_AT)
        .expect("the checkpoint, with the programs armed");
    key
}

/// Gives a restored or reopened vault what a serving host holds: a device keystore and the
/// test host's root, as `restored_machine_join_guards.rs` gives its copies.
fn serve(vault: &Vault) {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
}

/// The arming row `registration` holds in `vault`, as the test door encodes it:
/// `{"armed": <row>}`. A field the row does not name is absent.
fn arming(vault: &Vault, programs: &Programs, registration: EntityId) -> serde_json::Value {
    let bytes = doors::arming_row_bytes(vault, programs.owner, registration)
        .expect("the vault holds the arming");
    let row: serde_json::Value = serde_json::from_slice(&bytes).expect("the row is JSON");
    row["armed"].clone()
}

/// The time the row says it was paused at, when it names one.
fn paused_at(arming: &serde_json::Value) -> Option<u64> {
    arming.get("paused_at")?.as_u64()
}

/// The row's next due time, when it names one.
fn next_due(arming: &serde_json::Value) -> Option<u64> {
    arming.get("next_due")?.as_u64()
}

/// The occurrence of the wake `vault` owes `registration`, when it owes one.
fn owed_occurrence(vault: &Vault, programs: &Programs, registration: EntityId) -> Option<EntityId> {
    match doors::admitted_row_bytes(vault, programs.owner, registration) {
        Ok((occurrence, _, _)) => Some(occurrence),
        Err(oneiron::Error::EntityNotFound) => None,
        Err(error) => panic!("read the owed wake: {error:?}"),
    }
}

/// What one pass released.
struct Pass {
    /// Every run of the timer job, whatever its outcome.
    timer_runs: usize,
    /// The runs of the timer job that ended done.
    timer_runs_done: usize,
    /// The wakes the feed release recorded.
    feed: usize,
    /// The wakes the idle release recorded.
    idle: usize,
}

/// One pass on `vault`, as its host's tick takes it: the due jobs (an actor's due timers are
/// one run of the timer job), then the feed release, then the idle release on an idle host
/// whose quiet time has passed.
fn pass(vault: &Vault) -> Pass {
    let report = vault
        .run_due(HousekeepingBudget::unbounded())
        .expect("run the due jobs");
    let timer_runs = report.runs.iter().filter(|run| run.job == TIMER_JOB);
    Pass {
        timer_runs: timer_runs.clone().count(),
        timer_runs_done: timer_runs
            .filter(|run| run.outcome == JobOutcome::Done)
            .count(),
        feed: vault
            .release_feed_program_wakes(NOW)
            .expect("the feed release"),
        idle: vault
            .release_idle_program_wakes(
                WakeIdleState {
                    running_turns: false,
                    live_background_work: false,
                    compute_available: true,
                    last_inbound_at: LAST_INBOUND_AT,
                },
                NOW,
            )
            .expect("the idle release"),
    }
}

/// `vault` runs its programs: no arming names a pause, and a pass releases each one. The
/// timer job runs once and each timer, which wakes once, has no due time left; the feed and
/// the idle release record a wake each; the vault owes every program a wake. Answers each
/// owed wake's occurrence with its registration. `who` names the vault in a failure.
fn assert_runs_its_programs(
    vault: &Vault,
    programs: &Programs,
    who: &str,
) -> Vec<(EntityId, EntityId)> {
    for (name, registration) in &programs.armed {
        let row = arming(vault, programs, *registration);
        assert_eq!(
            paused_at(&row),
            None,
            "{who}: the {name} names no pause: {row}"
        );
    }
    for (timer, due) in &programs.timers {
        assert_eq!(
            next_due(&arming(vault, programs, *timer)),
            Some(*due),
            "{who}: a timer holds its due time before the pass"
        );
    }

    let released = pass(vault);
    assert_eq!(
        (released.timer_runs_done, released.feed, released.idle),
        (1, 1, 1),
        "{who}: the pass runs the timer job once and records the feed's and the idle wake"
    );
    for (timer, _) in &programs.timers {
        assert_eq!(
            next_due(&arming(vault, programs, *timer)),
            None,
            "{who}: a timer that wakes once was released: it has no due time left"
        );
    }
    programs
        .armed
        .iter()
        .map(|(name, registration)| {
            let occurrence = owed_occurrence(vault, programs, *registration)
                .unwrap_or_else(|| panic!("{who}: the vault owes the {name} a wake"));
            (occurrence, *registration)
        })
        .collect()
}

/// What a door that makes `copy` beside `source` leaves, in this order:
///
/// 1. every arming is paused in the copy, at `paused` when the door names the time, and each
///    timer holds the due time it had;
/// 2. a pass on the copy releases nothing: the timer job does not run, the feed and the idle
///    release record no wake, the copy owes no program a wake and admits none, and no arming
///    row changed, so no due time moved and no pause lifted;
/// 3. the source names no pause and releases each program in its own pass
///    ([`assert_runs_its_programs`]), so the copy's silence is the pause's doing; and the
///    copy holds neither a wake nor a decision of any occurrence the source released.
fn assert_copy_is_paused(copy: &Vault, source: &Vault, programs: &Programs, paused: Option<u64>) {
    let mut rows = Vec::new();
    for (name, registration) in &programs.armed {
        let row = arming(copy, programs, *registration);
        match paused {
            Some(at) => assert_eq!(
                paused_at(&row),
                Some(at),
                "the copy's {name} is paused at the restore's time: {row}"
            ),
            None => assert!(
                paused_at(&row).is_some(),
                "the copy's {name} is paused: {row}"
            ),
        }
        rows.push(row);
    }
    for (timer, due) in &programs.timers {
        assert_eq!(
            next_due(&arming(copy, programs, *timer)),
            Some(*due),
            "a paused timer holds the due time it had"
        );
    }

    let released = pass(copy);
    assert_eq!(
        (released.timer_runs, released.feed, released.idle),
        (0, 0, 0),
        "the copy's pass runs no timer job and records no feed or idle wake"
    );
    for (name, registration) in &programs.armed {
        assert_eq!(
            owed_occurrence(copy, programs, *registration),
            None,
            "the copy owes the {name} no wake"
        );
    }
    let drained = copy.wake_turn_programs(NOW).expect("the copy's drain");
    assert_eq!(
        (drained.admitted, drained.refused, drained.held),
        (0, 0, 0),
        "the copy admits nothing: {drained:?}"
    );
    for ((name, registration), before) in programs.armed.iter().zip(&rows) {
        assert_eq!(
            &arming(copy, programs, *registration),
            before,
            "the copy's pass leaves the {name}'s row as it was"
        );
    }

    for (occurrence, registration) in assert_runs_its_programs(source, programs, "the source") {
        assert!(
            !doors::wake_owed_here(copy, occurrence, registration).expect("the copy's wakes"),
            "the copy owes no wake the source released"
        );
        assert_eq!(
            doors::wake_decisions_here(copy, occurrence, registration)
                .expect("the copy's decisions"),
            0,
            "the copy decided no wake the source released"
        );
    }
}

/// D1: a checkpoint restored beside its source starts with its timer, its feed program and
/// its idle program paused at the restore's time; the source goes on releasing its own.
#[test]
fn a_restore_beside_its_source_pauses_the_copys_timer_feed_and_idle_programs() {
    let dir = restore_tempdir();
    let live = open_live(&dir.path().join("vault"));
    let programs = seed_programs(&live, &Armer::new(&live));
    let image = dir.path().join("image");
    let key = snapshot_live(&live, &image);
    let (copy, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &dir.path().join("copy"),
        VaultConfig::device(),
        &live.side_restore_source().expect("the restore's source"),
        RESTORED_AT,
    )
    .expect("restore the checkpoint beside its source");
    serve(&copy);

    assert_copy_is_paused(&copy, &live, &programs, Some(RESTORED_AT));
}

/// A budget that keeps no floor, as the engine's own default for a restore beside: the
/// rehearsal's door takes the host's.
struct NoFloor;

impl RecoveryWriteBudget for NoFloor {
    fn hold(&self, _bytes: u64) -> bool {
        true
    }

    fn floored(&self) -> bool {
        false
    }
}

/// D2: the door a backup rehearsal restores through, a restore beside under the host's write
/// budget, pauses the copy's programs as D1 does, so a rehearsal copy that is kept and served
/// releases none of them.
#[test]
fn a_restore_beside_within_a_write_budget_pauses_the_copys_programs() {
    let dir = restore_tempdir();
    let live = open_live(&dir.path().join("vault"));
    let programs = seed_programs(&live, &Armer::new(&live));
    let image = dir.path().join("image");
    let key = snapshot_live(&live, &image);
    let (copy, _) = Vault::restore_checkpoint_beside_within(
        &image,
        &key,
        &dir.path().join("copy"),
        VaultConfig::device(),
        &live.side_restore_source().expect("the restore's source"),
        RESTORED_AT,
        &NoFloor,
    )
    .expect("restore the checkpoint beside its source, within the budget");
    serve(&copy);

    assert_copy_is_paused(&copy, &live, &programs, Some(RESTORED_AT));
}

/// D3: a historical restore beside the live vault carries the armings the live vault holds
/// now, not the checkpoint's, and pauses each of them: a timer armed after the checkpoint was
/// taken is in the copy, and paused.
#[test]
fn a_historical_restore_pauses_the_armings_the_live_vault_holds_now() {
    let dir = restore_tempdir();
    let live = open_live(&dir.path().join("vault"));
    let armer = Armer::new(&live);
    let mut programs = seed_programs(&live, &armer);
    let image = dir.path().join("image");
    let key = snapshot_live(&live, &image);
    let later = armer.arm_timer(&live, LATER_TIMER_DUE);
    programs
        .armed
        .push(("timer armed after the checkpoint", later));
    programs.timers.push((later, LATER_TIMER_DUE));
    let (copy, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &dir.path().join("copy"),
        VaultConfig::device(),
        &live,
        RESTORED_AT,
    )
    .expect("restore the checkpoint beside the live vault, keeping its authority");
    serve(&copy);

    assert_copy_is_paused(&copy, &live, &programs, Some(RESTORED_AT));
}

/// D6: a checkpoint restored into an empty place takes its source's place, so nothing is
/// paused and the restored vault releases each program.
#[test]
fn a_restore_into_an_empty_place_keeps_its_programs_running() {
    let dir = restore_tempdir();
    let live = open_live(&dir.path().join("vault"));
    let programs = seed_programs(&live, &Armer::new(&live));
    let image = dir.path().join("image");
    let key = snapshot_live(&live, &image);
    let (restored, _) = Vault::restore_checkpoint(
        &image,
        &key,
        &dir.path().join("restored"),
        VaultConfig::device(),
        RestoreReason::Restore,
        RESTORED_AT,
    )
    .expect("restore the checkpoint");
    serve(&restored);

    assert_runs_its_programs(&restored, &programs, "the restored vault");
}

/// A vault a restore replaced: the replacement, open at the vault's path, and the path of the
/// store the swap set aside. `_dir` keeps both on disk.
#[cfg(unix)]
struct Replaced {
    _dir: tempfile::TempDir,
    replacement: Vault,
    previous: std::path::PathBuf,
    programs: Programs,
}

/// Arms the programs on a vault, takes its checkpoint, restores a replacement for its place
/// and swaps it in, as `oneiron restore` over a vault does; then parks the displaced store at
/// `previous` and opens the replacement at the vault's path.
#[cfg(unix)]
fn replace_and_swap() -> Replaced {
    let dir = restore_tempdir();
    let (vault_path, staged) = (dir.path().join("vault"), dir.path().join("staged"));
    let previous = dir.path().join("previous");
    let live = open_live(&vault_path);
    let programs = seed_programs(&live, &Armer::new(&live));
    let image = dir.path().join("image");
    let key = snapshot_live(&live, &image);
    let (replacement, _) = Vault::restore_checkpoint_replacing(
        &image,
        &key,
        &staged,
        VaultConfig::device(),
        &live,
        RESTORED_AT,
    )
    .expect("restore the replacement");
    live.swap_in_replacement(&replacement, oneiron::store::exchange_held)
        .expect("swap the replacement in");
    drop((live, replacement));
    std::fs::rename(&staged, &previous).expect("park the displaced store");
    let replacement =
        Vault::open(&vault_path, VaultConfig::device()).expect("open the replacement");
    serve(&replacement);
    Replaced {
        _dir: dir,
        replacement,
        previous,
        programs,
    }
}

/// D5: the replacement a restore swaps into the vault's place is the live vault, so nothing
/// is paused and it releases each program.
#[cfg(unix)]
#[test]
fn a_replacement_swapped_into_the_vaults_place_keeps_its_programs_running() {
    let replaced = replace_and_swap();

    assert_runs_its_programs(&replaced.replacement, &replaced.programs, "the replacement");
}

/// D4: the store a replacing restore set aside, activated as a side vault, is a copy beside
/// its replacement from then on: the activation pauses its programs (at the store's own
/// clock, so the test asks only that each names a pause), and the replacement goes on
/// releasing its own.
#[cfg(unix)]
#[test]
fn an_archived_vault_activated_beside_its_replacement_starts_paused() {
    let replaced = replace_and_swap();
    Vault::activate_archived(
        &replaced.previous,
        VaultConfig::device(),
        &replaced
            .replacement
            .side_restore_source()
            .expect("the activation's source"),
    )
    .expect("activate the displaced store");
    let copy =
        Vault::open(&replaced.previous, VaultConfig::device()).expect("open the activated store");
    serve(&copy);

    assert_copy_is_paused(&copy, &replaced.replacement, &replaced.programs, None);
}
