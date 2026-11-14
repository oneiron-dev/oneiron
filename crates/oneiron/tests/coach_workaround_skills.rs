//! The Coach's workaround skills (CLIF-STEALS 2, ARCH-0053 #outside-app-evidence; Engine
//! RULING L2-15-SHAPE = A). The owner captures AG-UI files through the real import door. The
//! skills job (`coach.skill_distill`, leased through the Coach host queue) groups each linked
//! failure, repair and outcome by project, app, failure name and repair name. When a group's
//! links fall in three distinct app runs, it files one born-Proposed Candidate skill. The
//! skill's files name only the registered names and the trigger. It also files one Proposed
//! finding, stamped like the captures, that lists the supporting runs and the counterexamples
//! (the same failure, repaired another way). Two runs file nothing. A link that does not join
//! (a missing repair, a repair in another run) counts for nothing. An app run seen in two
//! captures counts once. A second pass over the same evidence files no second skill and no
//! second finding.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test coach_workaround_skills`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::maintenance::workaround_skills::{
    COACH_WORKAROUND_SKILLS_PREDICATE, WORKAROUND_MIN_RUNS, WORKAROUND_SKILL_ID_PREFIX,
};
use oneiron::ingest::{AgUiCustomMapping, AgUiFileImport, AgUiObservationKind};
use oneiron::skill::SkillLifecycle;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::workaround_skills::{
    StoredFinding, admit_skill_distill_attempt, findings_under, skill_files, skills_with_id_prefix,
};
use oneiron::{ClaimApprovalStatus, ClaimSource, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

/// The vault clock's fixed time: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

/// The app the owner names at capture.
const APP: &str = "notes-app";
/// The registered CUSTOM names.
const FAILED: &str = "agent_draft_failed";
const FIXED: &str = "person_fixed_draft";
const RETYPED: &str = "person_retyped_draft";
const OUTCOME: &str = "draft_outcome";

/// Text that rides inside every repair payload. A skill file must never carry it: an imported
/// event is evidence, never an instruction.
const PAYLOAD_MARKER: &str = "payload-text-marker-7";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    project: EntityId,
}

/// A rooted vault with its install enrolled, its embedded owner and proof, and its root
/// project, where every capture lands.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
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
    let project = vault.root_project().expect("root project");
    Fixture {
        vault,
        _dir: dir,
        owner_proof,
        project,
    }
}

/// One registered CUSTOM name: its kind and where its ids sit in the event.
fn mapping(name: &str, kind: AgUiObservationKind) -> AgUiCustomMapping {
    let pointer = |field: &str| Some(format!("/value/{field}"));
    AgUiCustomMapping {
        name: name.to_owned(),
        kind,
        id: pointer("id"),
        thread_id: pointer("thread"),
        run_id: pointer("run"),
        tool_call_id: None,
        failure_id: matches!(kind, AgUiObservationKind::Repair).then(|| "/value/failure".into()),
        repair_id: matches!(kind, AgUiObservationKind::Outcome).then(|| "/value/repair".into()),
        outcome: matches!(kind, AgUiObservationKind::Outcome).then(|| "/value/result".into()),
    }
}

fn mappings() -> Vec<AgUiCustomMapping> {
    vec![
        mapping(FAILED, AgUiObservationKind::Failure),
        mapping(FIXED, AgUiObservationKind::Repair),
        mapping(RETYPED, AgUiObservationKind::Repair),
        mapping(OUTCOME, AgUiObservationKind::Outcome),
    ]
}

/// How one app run's events end.
#[derive(Clone, Copy)]
enum RunEnd {
    /// Failure, the person's repair, and the outcome naming that repair: a `Linked` link.
    Repaired(&'static str),
    /// The outcome names a repair id no event of the run carries: `MissingLink`.
    MissingRepair,
    /// The repair sits in another run of the thread: `NamespaceMismatch`.
    RepairInAnotherRun,
}

fn custom(name: &str, value: Value) -> Value {
    json!({"type": "CUSTOM", "name": name, "value": value})
}

/// One app run's AG-UI events, as the app reports them.
fn run_events(thread: &str, run: &str, end: RunEnd) -> Vec<Value> {
    let mut events = vec![
        json!({"type": "RUN_STARTED", "threadId": thread, "runId": run}),
        custom(
            FAILED,
            json!({"id": "f", "thread": thread, "run": run, "reason": "draft rejected"}),
        ),
    ];
    match end {
        RunEnd::Repaired(repair) => {
            events.push(custom(
                repair,
                json!({"id": "p", "thread": thread, "run": run, "failure": "f",
                       "text": PAYLOAD_MARKER}),
            ));
            events.push(custom(
                OUTCOME,
                json!({"id": "o", "thread": thread, "run": run, "repair": "p", "result": "sent"}),
            ));
        }
        RunEnd::MissingRepair => events.push(custom(
            OUTCOME,
            json!({"id": "o", "thread": thread, "run": run, "repair": "absent", "result": "sent"}),
        )),
        RunEnd::RepairInAnotherRun => {
            let other = format!("{run}-side");
            events.push(custom(
                FIXED,
                json!({"id": "q", "thread": thread, "run": other, "failure": "f",
                       "text": PAYLOAD_MARKER}),
            ));
            events.push(custom(
                OUTCOME,
                json!({"id": "o", "thread": thread, "run": run, "repair": "q", "result": "sent"}),
            ));
        }
    }
    events.push(json!({"type": "RUN_FINISHED", "threadId": thread, "runId": run}));
    events
}

/// Captures the runs as one file through the owner's import door; answers the capture claim.
fn capture(fixture: &Fixture, runs: &[(&str, &str, RunEnd)]) -> EntityId {
    let jsonl = runs
        .iter()
        .flat_map(|(thread, run, end)| run_events(thread, run, *end))
        .map(|event| event.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let receipt = fixture
        .vault
        .ingest_ag_ui_file(
            &fixture.owner_proof,
            &AgUiFileImport {
                claim_ref: None,
                project_ref: fixture.project.to_hex(),
                app_id: APP.to_owned(),
                custom_mappings: mappings(),
                jsonl,
            },
        )
        .expect("the owner captures the file");
    EntityId::from_hex(&receipt.claim_ref).expect("capture claim id")
}

/// The pass's findings.
fn findings(vault: &Vault) -> oneiron::Result<Vec<StoredFinding>> {
    findings_under(vault, COACH_WORKAROUND_SKILLS_PREDICATE)
}

/// The pass's skills.
fn skills(vault: &Vault) -> oneiron::Result<Vec<EntityId>> {
    skills_with_id_prefix(vault, WORKAROUND_SKILL_ID_PREFIX)
}

/// The run ids of a finding's anchor list, in its order.
fn run_ids(anchors: &Value) -> Vec<String> {
    anchors
        .as_array()
        .expect("an anchor list")
        .iter()
        .map(|anchor| anchor["run_id"].as_str().expect("a run id").to_owned())
        .collect()
}

#[test]
fn three_runs_repaired_the_same_way_file_one_candidate_skill_and_a_finding() {
    let fixture = fixture();
    let first = capture(
        &fixture,
        &[
            ("t1", "r1", RunEnd::Repaired(FIXED)),
            ("t1", "r2", RunEnd::Repaired(FIXED)),
        ],
    );
    let second = capture(
        &fixture,
        &[
            ("t2", "r3", RunEnd::Repaired(FIXED)),
            ("t2", "r4", RunEnd::Repaired(RETYPED)),
        ],
    );
    let attempt = admit_skill_distill_attempt(&fixture.vault, T0).expect("the skills job");
    let report = fixture
        .vault
        .run_coach_workaround_skills(&attempt, T0)
        .expect("the workaround pass");
    assert!(
        report.errors.is_empty(),
        "no write rolled back: {:?}",
        report.errors
    );
    assert_eq!(report.captures, 2, "both captures read");
    assert_eq!(report.groups, 2, "one failure, two repairs");
    assert_eq!(report.nominations, 1, "only the three-run repair nominates");
    assert_eq!(report.skills_created, 1);

    let findings = findings(&fixture.vault).expect("findings");
    assert_eq!(findings.len(), 1, "one finding");
    let finding = &findings[0];
    assert_eq!(
        finding.approval,
        ClaimApprovalStatus::Proposed,
        "it waits in the run tray"
    );
    let value = &finding.value;
    assert_eq!(value["kind"], "workaround_skill");
    assert_eq!(value["app"], APP);
    assert_eq!(value["failure"], FAILED);
    assert_eq!(value["repair"], FIXED);
    assert_eq!(value["min_runs"], WORKAROUND_MIN_RUNS);
    assert_eq!(run_ids(&value["supporting_runs"]), ["r1", "r2", "r3"]);
    assert_eq!(
        run_ids(&value["counterexamples"]),
        ["r4"],
        "r4 fixed it another way"
    );
    assert_eq!(value["counterexamples"][0]["repair"], RETYPED);
    let supporting = &value["supporting_runs"][0];
    assert_eq!(
        supporting["capture"],
        first.to_hex(),
        "r1's anchor is in its capture"
    );
    assert!(
        supporting["source_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    assert_eq!(supporting["thread_id"], "t1");
    for key in ["failure_ordinal", "repair_ordinal", "outcome_ordinal"] {
        assert!(supporting[key].is_u64(), "{key} is an event ordinal");
    }
    let mut captures: Vec<String> = value["captures"]
        .as_array()
        .expect("captures")
        .iter()
        .map(|id| id.as_str().expect("capture hex").to_owned())
        .collect();
    captures.sort();
    let mut expected = vec![first.to_hex(), second.to_hex()];
    expected.sort();
    assert_eq!(captures, expected, "the finding cites both captures");
    let capture_body = fixture
        .vault
        .get_claim(&first)
        .expect("capture read")
        .expect("the capture");
    assert_eq!(
        finding.stamps,
        (capture_body.scope_facet, capture_body.scope_project),
        "the finding stands where the captures stand"
    );

    let skills = skills(&fixture.vault).expect("skills");
    assert_eq!(skills.len(), 1, "one skill");
    let skill = skills[0];
    assert_eq!(
        value["skill"],
        skill.to_hex(),
        "the finding names the skill"
    );
    let record = fixture
        .vault
        .get_skill_record(&skill)
        .expect("skill read")
        .expect("the skill record");
    assert!(record.skill_id.starts_with(WORKAROUND_SKILL_ID_PREFIX));
    assert_eq!(value["skill_id"], record.skill_id.as_str());
    assert_eq!(record.lifecycle_status, SkillLifecycle::Candidate, "inert");
    assert_eq!(record.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(record.source, ClaimSource::Generated);
    assert_eq!(record.forked_from, None, "a new skill, no parent");

    let files = skill_files(&fixture.vault, &skill).expect("skill files");
    let paths: Vec<&str> = files.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(paths, ["SKILL.md", "workaround.json"]);
    let skill_md = String::from_utf8(files[0].1.clone()).expect("utf-8 SKILL.md");
    assert!(skill_md.contains(&format!("name: {}", record.skill_id)));
    assert!(skill_md.contains(&format!("App: {APP}")));
    assert!(skill_md.contains(&format!("`{FAILED}`")));
    assert!(skill_md.contains(&format!("`{FIXED}`")));
    for (path, bytes) in &files {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(PAYLOAD_MARKER),
            "{path} carries no imported payload text"
        );
        assert!(
            !text.contains("draft rejected"),
            "{path} carries no failure payload text"
        );
        assert!(
            !text.contains("r1") && !text.contains("t1"),
            "{path} names no app run"
        );
        assert!(!text.contains(RETYPED), "{path} names only its own repair");
    }
}

#[test]
fn two_runs_file_nothing() {
    let fixture = fixture();
    capture(
        &fixture,
        &[
            ("t1", "r1", RunEnd::Repaired(FIXED)),
            ("t1", "r2", RunEnd::Repaired(FIXED)),
        ],
    );
    let attempt = admit_skill_distill_attempt(&fixture.vault, T0).expect("the skills job");
    let report = fixture
        .vault
        .run_coach_workaround_skills(&attempt, T0)
        .expect("the workaround pass");
    assert_eq!(report.groups, 1);
    assert_eq!(report.nominations, 0, "two runs nominate nothing");
    assert!(findings(&fixture.vault).expect("findings").is_empty());
    assert!(skills(&fixture.vault).expect("skills").is_empty());
}

#[test]
fn a_link_that_does_not_join_counts_for_nothing() {
    let fixture = fixture();
    capture(
        &fixture,
        &[
            ("t1", "r1", RunEnd::Repaired(FIXED)),
            ("t1", "r2", RunEnd::Repaired(FIXED)),
            ("t1", "r3", RunEnd::MissingRepair),
            ("t1", "r4", RunEnd::RepairInAnotherRun),
        ],
    );
    let attempt = admit_skill_distill_attempt(&fixture.vault, T0).expect("the skills job");
    let report = fixture
        .vault
        .run_coach_workaround_skills(&attempt, T0)
        .expect("the workaround pass");
    assert_eq!(report.groups, 1, "only the two linked runs group");
    assert_eq!(report.nominations, 0, "an unjoined link is not a third run");
    assert!(findings(&fixture.vault).expect("findings").is_empty());
    assert!(skills(&fixture.vault).expect("skills").is_empty());

    // A third linked run nominates; the unjoined runs are neither support nor counterexample.
    capture(&fixture, &[("t1", "r5", RunEnd::Repaired(FIXED))]);
    let report = fixture
        .vault
        .run_coach_workaround_skills(&attempt, T0)
        .expect("the workaround pass");
    assert_eq!(report.skills_created, 1);
    let findings = findings(&fixture.vault).expect("findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(
        run_ids(&findings[0].value["supporting_runs"]),
        ["r1", "r2", "r5"]
    );
    assert!(
        run_ids(&findings[0].value["counterexamples"]).is_empty(),
        "a missing link is completeness-unknown, not a counterexample"
    );
}

#[test]
fn the_same_app_run_in_two_captures_counts_once() {
    let fixture = fixture();
    capture(
        &fixture,
        &[
            ("t1", "r1", RunEnd::Repaired(FIXED)),
            ("t1", "r2", RunEnd::Repaired(FIXED)),
        ],
    );
    capture(&fixture, &[("t1", "r2", RunEnd::Repaired(FIXED))]);
    let attempt = admit_skill_distill_attempt(&fixture.vault, T0).expect("the skills job");
    let report = fixture
        .vault
        .run_coach_workaround_skills(&attempt, T0)
        .expect("the workaround pass");
    assert_eq!(report.captures, 2);
    assert_eq!(report.nominations, 0, "r2 captured twice is one run");
    assert!(skills(&fixture.vault).expect("skills").is_empty());

    capture(&fixture, &[("t1", "r3", RunEnd::Repaired(FIXED))]);
    let report = fixture
        .vault
        .run_coach_workaround_skills(&attempt, T0)
        .expect("the workaround pass");
    assert_eq!(report.nominations, 1);
    let findings = findings(&fixture.vault).expect("findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(
        run_ids(&findings[0].value["supporting_runs"]),
        ["r1", "r2", "r3"]
    );
}

#[test]
fn a_second_pass_over_the_same_evidence_files_no_second_skill() {
    let fixture = fixture();
    capture(
        &fixture,
        &[
            ("t1", "r1", RunEnd::Repaired(FIXED)),
            ("t1", "r2", RunEnd::Repaired(FIXED)),
            ("t1", "r3", RunEnd::Repaired(FIXED)),
        ],
    );
    let attempt = admit_skill_distill_attempt(&fixture.vault, T0).expect("the skills job");
    let first = fixture
        .vault
        .run_coach_workaround_skills(&attempt, T0)
        .expect("the first pass");
    assert_eq!(first.skills_created, 1);
    let second = fixture
        .vault
        .run_coach_workaround_skills(&attempt, T0)
        .expect("the second pass");
    assert!(
        second.errors.is_empty(),
        "no write rolled back: {:?}",
        second.errors
    );
    assert_eq!(second.skills_created, 0, "no second skill");
    assert_eq!(second.skills_dup, 1, "the bytes are the first skill's");
    assert_eq!(skills(&fixture.vault).expect("skills").len(), 1);
    let findings = findings(&fixture.vault).expect("findings");
    assert_eq!(
        findings.len(),
        1,
        "the same evidence files no second finding"
    );
}
