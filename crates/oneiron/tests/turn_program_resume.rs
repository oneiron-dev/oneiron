//! The owner resumes only the named paused turn programs on a copy beside its source.
//! The confirm binds the chosen rows and which timers are due. A pass checks that resuming
//! a timer arms its job again, without releasing any program left paused. The sheet shows a
//! pinned SKILL only where it reads on the calling handle's lane, as the paused list does.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::dreamer_runner::{
    ArmTurnProgram, PausedTurnProgramsRequest, PausedTurnProgramsView, ProgramTrigger,
    ResumePausedTurnProgramsPreview, ResumePausedTurnProgramsRequest, ResumedTurnPrograms,
    paused_turn_programs,
};
use oneiron::dreamer_wake::WakeIdleState;
use oneiron::feeds::{FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::{Memory, MemoryError};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::schedule::JobOutcome;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::{
    OwnerConfirmPreviewRequest, TURN_PROGRAMS_RESUME_VERB, invoke, preview_owner_confirm,
    resume_paused_turn_programs, resume_paused_turn_programs_as,
};
use oneiron::test_doors::turn_programs as doors;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, restore_tempdir};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const TIMER_JOB: &str = "dreamer_runner.program_timer";
const RESTORED_AT: u64 = 1_800_000_000;
const SNAPSHOT_AT: u64 = RESTORED_AT - 120;
const A_DUE: u64 = RESTORED_AT - 60;
const B_DUE: u64 = RESTORED_AT + 60;
const REPEAT_SECS: u64 = 60;
const QUIET_SECS: u64 = 600;

/// An active callable SKILL, enough to pin an arming without running code.
fn active_callable_skill(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let files: [(&str, &[u8]); 2] = [
        (
            "SKILL.md",
            concat!(
                "---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\n",
                "role: callable\ncall:\n  reference: scripts/call.js\n",
                "  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n",
                "---\nAn executable fixture.\n",
            )
            .as_bytes(),
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
            arguments: json!({"value": "integer"}),
            returns: json!({"result": "integer"}),
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

/// Arms a program through the actor's public door and returns its registration.
fn arm(memory: &Memory<'_>, skill: EntityId, trigger: ProgramTrigger) -> EntityId {
    memory
        .arm_turn_program(&ArmTurnProgram {
            skill,
            executor: "fixture.executor@1".into(),
            args: json!({"value": 41}),
            conversation: None,
            trigger,
            expected: None,
            project: None,
        })
        .expect("arm the program")
        .registration
}

/// Writes a live PERSON, also a visible change when made after the owner's feed subscription.
fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("write a person");
    id
}

/// A copy with four paused armings, a TURN arming that is not paused, and a movable clock.
struct Fixture {
    copy: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    second_person: EntityId,
    agent: EntityId,
    a: EntityId,
    b: EntityId,
    feed: EntityId,
    idle: EntityId,
    turn: EntityId,
    _dir: tempfile::TempDir,
}

/// Cuts the checkpoint before either timer is due and lands it on an owner-held copy where
/// only A is due; the feed can see a PERSON change and the idle quiet time can pass.
fn fixture() -> Fixture {
    let dir = restore_tempdir();
    let clock = ManualClock::new(SNAPSHOT_AT);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let source = Vault::open_owned(dir.path().join("source"), config.clone())
        .expect("open the source under its writer lease");
    let issuer = Arc::new(provision_engine_machines(&source));
    source.install_device_keystore(Arc::new(MemoryKeystore::default()));
    source
        .prepare_install_signing()
        .expect("source install signing");
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    bind_host_owner(&source, &issuer, owner).expect("the owner's binding");
    source
        .ensure_serving_install_profile(&issuer, oneiron::authority::MachineRole::Unanswered)
        .expect("the source's serving profile");
    source.hold_checkpoint_root_signer(issuer.clone());
    source.ensure_vault_key().expect("mint the vault data key");

    let memory = source.memory(owner, EdgeActorClass::Human);
    let skill = active_callable_skill(&source);
    let lane = source.scoped_read(
        ScopedReadActorKey::with_actor_class(owner.to_hex(), "human").expect("owner lane key"),
    );
    let subscription = source
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
        .expect("subscribe at the feed head")
        .subscription;
    let a = arm(
        &memory,
        skill,
        ProgramTrigger::Timer {
            first_at: A_DUE,
            every_secs: 0,
        },
    );
    let b = arm(
        &memory,
        skill,
        ProgramTrigger::Timer {
            first_at: B_DUE,
            every_secs: REPEAT_SECS,
        },
    );
    let feed = arm(&memory, skill, ProgramTrigger::Feed { subscription });
    let idle = arm(
        &memory,
        skill,
        ProgramTrigger::Idle {
            quiet_secs: QUIET_SECS,
        },
    );
    let turn = arm(&memory, skill, ProgramTrigger::Turn);
    let second_person = person(&source);
    let agent = person(&source);

    let image = dir.path().join("image");
    let key = source.checkpoint_key().expect("derive the checkpoint key");
    source
        .snapshot_checkpoint(&image, SNAPSHOT_AT)
        .expect("take the checkpoint");
    clock.set(RESTORED_AT);
    let (copy, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &dir.path().join("copy"),
        config,
        &source.side_restore_source().expect("the restore's source"),
        RESTORED_AT,
    )
    .expect("restore beside the source");
    copy.install_device_keystore(Arc::new(MemoryKeystore::default()));
    copy.hold_checkpoint_root_signer(issuer.clone());
    copy.prepare_install_signing()
        .expect("copy install signing");
    copy.provision_engine_machine_identities(&issuer)
        .expect("copy engine machine signers");

    Fixture {
        copy,
        clock,
        owner,
        second_person,
        agent,
        a,
        b,
        feed,
        idle,
        turn,
        _dir: dir,
    }
}

impl Fixture {
    /// Returns the embedded human owner's handle on the copy, not on its source.
    fn owner(&self) -> Memory<'_> {
        self.copy.memory(self.owner, EdgeActorClass::Human)
    }

    /// Names the four armings the side restore pauses.
    fn paused_registrations(&self) -> [EntityId; 4] {
        [self.a, self.b, self.feed, self.idle]
    }

    /// Reads the owner's whole paused list for comparison with the confirm sheet.
    fn paused_list(&self) -> PausedTurnProgramsView {
        paused_turn_programs(&self.owner(), &PausedTurnProgramsRequest::default())
            .expect("read the owner's paused programs")
    }

    /// Reads the exact arming, preserving the difference between absent and present fields.
    fn arming(&self, registration: EntityId) -> Value {
        let bytes = doors::arming_row_bytes(&self.copy, self.owner, registration)
            .expect("the copy holds the arming");
        let row: Value = serde_json::from_slice(&bytes).expect("the arming row is JSON");
        row["armed"].clone()
    }

    /// Captures the requested arming rows so a refusal or a pass can prove they did not move.
    fn rows(&self, registrations: &[EntityId]) -> Vec<Value> {
        registrations.iter().map(|&id| self.arming(id)).collect()
    }

    /// Reads a recorded wake before admission, or proves the program is not owed one.
    fn owed_occurrence(&self, registration: EntityId) -> Option<EntityId> {
        match doors::admitted_row_bytes(&self.copy, self.owner, registration) {
            Ok((occurrence, _, _)) => Some(occurrence),
            Err(oneiron::Error::EntityNotFound) => None,
            Err(error) => panic!("read the owed wake: {error:?}"),
        }
    }

    /// Previews through the embedded verb table, returning the confirm and its typed sheet.
    fn preview(&self, registrations: &[EntityId]) -> (String, ResumePausedTurnProgramsPreview) {
        let value = invoke(
            &self.owner(),
            "vault.owner_confirm.preview",
            json!({
                "verb": TURN_PROGRAMS_RESUME_VERB,
                "input": {"registrations": registrations},
            }),
        )
        .expect("preview the selected paused programs");
        let confirm = value["confirm"]
            .as_str()
            .expect("the preview's confirm")
            .to_owned();
        let sheet = serde_json::from_value(value["takes"].clone()).expect("the resume sheet");
        (confirm, sheet)
    }

    /// Calls resume as the embedded owner, with the confirm supplied by the test.
    fn resume(
        &self,
        registrations: &[EntityId],
        confirm: Option<String>,
    ) -> Result<ResumedTurnPrograms, MemoryError> {
        resume_paused_turn_programs(
            &self.owner(),
            &ResumePausedTurnProgramsRequest {
                registrations: registrations.to_vec(),
                confirm,
            },
        )
    }
}

/// Checks the exact missing-registration refusal, rather than a generic stale-confirm error.
fn assert_not_paused(error: &MemoryError, registration: EntityId) {
    assert_eq!(error.code, "NOT_FOUND");
    assert_eq!(
        error.message,
        format!(
            "registration {} is no paused program of this vault",
            registration.to_hex()
        ),
    );
}

/// Counts timer runs, successful timer runs, feed wakes and idle wakes in one host pass.
fn pass(vault: &Vault) -> (usize, usize, usize, usize) {
    let report = vault
        .run_due(HousekeepingBudget::unbounded())
        .expect("run due jobs");
    let timer_runs = report.runs.iter().filter(|run| run.job == TIMER_JOB);
    let now = vault.now_recorded_at();
    (
        timer_runs.clone().count(),
        timer_runs
            .filter(|run| run.outcome == JobOutcome::Done)
            .count(),
        vault
            .release_feed_program_wakes(now)
            .expect("release feed wakes"),
        vault
            .release_idle_program_wakes(
                WakeIdleState {
                    running_turns: false,
                    live_background_work: false,
                    compute_available: true,
                    last_inbound_at: RESTORED_AT - QUIET_SECS,
                },
                now,
            )
            .expect("release idle wakes"),
    )
}

/// Without a confirm, no arming moves and all four occurrence programs stay paused.
#[test]
fn resume_without_a_confirm_leaves_every_program_paused() {
    let f = fixture();
    let ids = f.paused_registrations();
    let before = f.rows(&ids);

    let error = f.resume(&[f.a, f.feed], None).expect_err("no confirm");
    assert_eq!(error.code, "OWNER_CONFIRM_REQUIRED");
    let after = f.rows(&ids);
    for row in &after {
        assert_eq!(row["paused_at"].as_u64(), Some(RESTORED_AT));
    }
    assert_eq!(after, before);
    assert_eq!(f.copy.paused_turn_program_count().expect("paused count"), 4);
}

/// The sheet uses paused-list rows in key order and marks only overdue timers.
#[test]
fn preview_lists_selected_programs_in_key_order_and_marks_due_timers() {
    let f = fixture();
    let list = f.paused_list();
    for (ids, overdue) in [([f.a, f.b], Some(f.a)), ([f.feed, f.idle], None)] {
        let mut order = ids;
        order.sort_unstable();
        let (_, sheet) = f.preview(&[order[1], order[0]]);
        assert_eq!(sheet.programs.len(), 2);
        for (item, id) in sheet.programs.iter().zip(order) {
            let row = list
                .programs
                .iter()
                .find(|row| row.registration == id)
                .expect("list row");
            assert_eq!(
                (item.program.actor, item.program.registration),
                (f.owner, id)
            );
            assert_eq!(&item.program, row);
            assert_eq!(item.fires_at_once, overdue == Some(id));
        }
    }
}

/// A confirmed selection lifts just those pauses and agrees with the remaining list and count.
#[test]
fn a_confirmed_resume_lifts_only_the_named_pauses() {
    let f = fixture();
    let ids = [f.a, f.feed];
    let (confirm, sheet) = f.preview(&ids);
    let answer = f
        .resume(&ids, Some(confirm))
        .expect("resume the chosen pair");

    assert_eq!(answer.resumed, sheet.programs);
    assert_eq!(answer.still_paused, 2);
    for id in ids {
        assert!(f.arming(id).get("paused_at").is_none());
    }
    for id in [f.b, f.idle] {
        assert_eq!(f.arming(id)["paused_at"].as_u64(), Some(RESTORED_AT));
    }
    let mut remaining = [f.b, f.idle];
    remaining.sort_unstable();
    let list = f.paused_list();
    let listed: Vec<_> = list.programs.iter().map(|row| row.registration).collect();
    assert_eq!(listed.as_slice(), remaining.as_slice());
    assert_eq!(list.paused, 2);
    assert_eq!(f.copy.paused_turn_program_count().expect("paused count"), 2);
}

/// Resuming A and the feed releases each once; even when B and idle qualify, their pauses hold.
#[test]
fn a_resumed_overdue_timer_wakes_once_and_paused_programs_do_not_wake() {
    let f = fixture();
    let ids = [f.a, f.feed];
    let (confirm, _) = f.preview(&ids);
    f.resume(&ids, Some(confirm))
        .expect("resume A and the feed");
    let left = [f.b, f.idle];
    let before = f.rows(&left);
    f.clock.set(B_DUE + 1);

    assert_eq!(pass(&f.copy), (1, 1, 1, 0));
    assert!(f.arming(f.a).get("next_due").is_none());
    let a_wake = f.owed_occurrence(f.a).expect("A's overdue wake");
    assert!(f.owed_occurrence(f.feed).is_some());
    for id in left {
        assert_eq!(f.owed_occurrence(id), None);
    }
    assert_eq!(f.rows(&left), before);

    let (timer_runs, _, _, _) = pass(&f.copy);
    assert_eq!(timer_runs, 0);
    assert_eq!(f.owed_occurrence(f.a), Some(a_wake));
}

/// Disarming a previewed registration makes it absent from the sheet and the old confirm lands
/// nothing else.
#[test]
fn a_confirm_of_a_disarmed_program_is_refused() {
    let f = fixture();
    let (confirm, _) = f.preview(&[f.a]);
    assert!(f.owner().disarm_turn_program(f.a).expect("disarm A"));
    let left = [f.b, f.feed, f.idle];
    let before = f.rows(&left);

    let error = f.resume(&[f.a], Some(confirm)).expect_err("A was disarmed");
    assert_not_paused(&error, f.a);
    assert!(matches!(
        doors::arming_row_bytes(&f.copy, f.owner, f.a),
        Err(oneiron::Error::EntityNotFound),
    ));
    assert_eq!(f.rows(&left), before);
    assert_eq!(f.copy.paused_turn_program_count().expect("paused count"), 3);
}

/// A confirm for two programs cannot partially land after one was already resumed.
#[test]
fn a_confirm_of_a_pair_cannot_resume_the_remaining_one() {
    let f = fixture();
    let pair = [f.a, f.b];
    let (stale, _) = f.preview(&pair);
    let (confirm, _) = f.preview(&[f.a]);
    f.resume(&[f.a], Some(confirm)).expect("resume A alone");
    let ids = f.paused_registrations();
    let before = f.rows(&ids);

    let error = f
        .resume(&pair, Some(stale))
        .expect_err("A is no longer paused");
    assert_not_paused(&error, f.a);
    assert_eq!(f.arming(f.b)["paused_at"].as_u64(), Some(RESTORED_AT));
    assert_eq!(f.rows(&ids), before);
    assert_eq!(f.copy.paused_turn_program_count().expect("paused count"), 3);
}

/// When the repeating timer becomes due, its old sheet no longer confirms it, but the new one
/// does.
#[test]
fn a_timer_that_became_due_needs_a_new_confirm() {
    let f = fixture();
    let ids = [f.b];
    let (stale, sheet) = f.preview(&ids);
    assert!(!sheet.programs[0].fires_at_once);
    let before = f.rows(&f.paused_registrations());
    f.clock.set(B_DUE + 1);

    let error = f.resume(&ids, Some(stale)).expect_err("B is now overdue");
    assert_eq!(error.code, "OWNER_CONFIRM_REQUIRED");
    assert_eq!(f.arming(f.b)["paused_at"].as_u64(), Some(RESTORED_AT));
    assert_eq!(f.rows(&f.paused_registrations()), before);
    assert_eq!(f.copy.paused_turn_program_count().expect("paused count"), 4);

    let (confirm, sheet) = f.preview(&ids);
    assert!(sheet.programs[0].fires_at_once);
    let answer = f
        .resume(&ids, Some(confirm))
        .expect("confirm the overdue B");
    assert_eq!(answer.resumed, sheet.programs);
    assert_eq!(answer.still_paused, 3);
    assert!(f.arming(f.b).get("paused_at").is_none());
}

/// Empty, duplicate, missing, TURN and oversized selections fail on the sheet, not the digest;
/// neither a paused arming nor the standing TURN arming changes.
#[test]
fn invalid_selections_are_refused_without_changing_armings() {
    let f = fixture();
    let missing = EntityId::now();
    let too_many: Vec<_> = (0..65).map(|_| EntityId::now()).collect();
    let [a, b, feed, idle] = f.paused_registrations();
    let ids = [a, b, feed, idle, f.turn];
    let before = f.rows(&ids);
    assert!(before[4].get("paused_at").is_none());

    let cases = [
        (
            vec![],
            "BAD_REQUEST",
            "registrations names at least one paused program".into(),
        ),
        (
            vec![f.a, f.a],
            "BAD_REQUEST",
            "registrations names a program twice".into(),
        ),
        (
            vec![missing],
            "NOT_FOUND",
            format!(
                "registration {} is no paused program of this vault",
                missing.to_hex()
            ),
        ),
        (
            vec![f.turn],
            "NOT_FOUND",
            format!(
                "registration {} is no paused program of this vault",
                f.turn.to_hex()
            ),
        ),
        (
            too_many,
            "BAD_REQUEST",
            "registrations names at most 64 paused programs".into(),
        ),
    ];
    for (registrations, code, message) in cases {
        let error = f
            .resume(&registrations, Some("00".repeat(32)))
            .expect_err("the sheet must refuse this selection");
        assert_eq!(error.code, code);
        assert_eq!(error.message, message);
        assert_eq!(f.rows(&ids), before);
        assert_eq!(f.copy.paused_turn_program_count().expect("paused count"), 4);
    }
}

/// Even the owner's live confirm cannot make an agent or a second person the embedded owner.
#[test]
fn an_agent_and_a_second_person_cannot_take_the_embedded_owner_door() {
    let f = fixture();
    let (confirm, _) = f.preview(&[f.a]);
    let input = ResumePausedTurnProgramsRequest {
        registrations: vec![f.a],
        confirm: Some(confirm),
    };
    let ids = f.paused_registrations();
    let before = f.rows(&ids);

    for (actor, class) in [
        (f.agent, EdgeActorClass::Agent),
        (f.second_person, EdgeActorClass::Human),
    ] {
        let error = resume_paused_turn_programs(&f.copy.memory(actor, class), &input)
            .expect_err("not the embedded owner");
        assert_eq!(error.code, "FORBIDDEN");
        assert_eq!(
            error.message,
            "vault.turn_programs.resume is the vault owner's"
        );
        assert_eq!(f.rows(&ids), before);
        assert_eq!(f.copy.paused_turn_program_count().expect("paused count"), 4);
    }
}

/// The sheet reads each pinned SKILL on the calling handle's own lane, as the paused list does:
/// a handle whose lane does not read the SKILL is shown the program with its pin, name and
/// description withheld, and the confirm of that sheet resumes the program through the same
/// handle. The owner's own handle is shown the SKILL.
#[test]
fn the_sheet_withholds_a_skill_its_handle_does_not_read() {
    let f = fixture();
    let (_, own) = f.preview(&[f.a]);
    assert!(own.programs[0].program.definition.is_some());
    assert!(own.programs[0].program.withheld.is_empty());

    let proof = f
        .copy
        .authenticate_owner(f.owner, &f.owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof on the copy");
    let handle = f.copy.memory(f.agent, EdgeActorClass::Agent);
    let preview = preview_owner_confirm(
        &handle,
        &proof,
        OwnerConfirmPreviewRequest {
            verb: TURN_PROGRAMS_RESUME_VERB.to_owned(),
            input: json!({"registrations": [f.a]}),
        },
    )
    .expect("preview on a lane that does not read the SKILL");
    let sheet: ResumePausedTurnProgramsPreview =
        serde_json::from_value(preview.takes.expect("the resume sheet")).expect("a typed sheet");
    assert_eq!(sheet.programs.len(), 1);
    let row = &sheet.programs[0].program;
    assert_eq!((row.actor, row.registration), (f.owner, f.a));
    assert!(row.definition.is_none());
    assert!(row.skill_name.is_none());
    assert!(row.skill_description.is_none());
    assert_eq!(
        row.withheld,
        ["definition", "skill_name", "skill_description"]
    );
    assert!(sheet.programs[0].fires_at_once);

    let answer = resume_paused_turn_programs_as(
        &handle,
        &proof,
        &ResumePausedTurnProgramsRequest {
            registrations: vec![f.a],
            confirm: Some(preview.confirm),
        },
    )
    .expect("the confirm of the withheld sheet resumes A");
    assert_eq!(answer.resumed, sheet.programs);
    assert_eq!(answer.still_paused, 3);
    assert!(f.arming(f.a).get("paused_at").is_none());
}
