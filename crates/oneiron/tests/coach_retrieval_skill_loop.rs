//! Census L1-18: the Coach's slow retrieval loop reads the library skill
//! tune-oneiron-retrieval (ARCH-0053 #tune-retrieval: "It reads
//! `skills/tune-oneiron-retrieval` for knob ranges, the symptom → cause →
//! change playbook and the judging rules."). These tests pin the skill in the
//! default hub and find the owner's import, then run the slow loop: the
//! nightly tune queues one review after its bandit update, and the review
//! keeps the host's proposal as an offer stamped with the skill it read
//! (Engine ruling L1-18-PROPOSAL = A: offer only).
//!
//! The hub is a local folder fixture. tests/fixtures/tune-oneiron-retrieval-pin
//! holds a byte copy of oneiron-hub's skills/tune-oneiron-retrieval at the
//! released commit (`COMMIT`), and that subtree's Git tree id (`TREE`).
//! Moving the pin means refreshing the copy.
#![cfg(oneiron_test_support)]

use std::path::Path;
use std::process::Command;

use std::cell::RefCell;

use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::dreamer_runner::maintenance::coach::COACH_RETRIEVAL_SKILL_REVIEW_FACET;
use oneiron::dreamer_runner::maintenance::retrieval_skill_review::{
    RETRIEVAL_TUNING_NOTIFICATION_PRODUCER, RetrievalSkillBrief, RetrievalSkillReviewer,
    RetrievalTuningDisposition, RetrievalTuningKnob, RetrievalTuningProposal,
    RetrievalTuningProposalKind, RetrievalTuningReceipt,
};
use oneiron::inbox::{INBOX_PAGE_DEFAULT, NotificationKind, NotificationRow};
use oneiron::skill::SkillLifecycle;
use oneiron::skill_hub::{
    HubPin, HubRef, HubSyncPolicy, InstalledLibrarySkill, SkillHubKind, SkillHubRecord,
    SkillHubTrustTier, TUNE_ONEIRON_RETRIEVAL_SUBTREE, default_skill_hub_commit,
    default_skill_hub_id,
};
use oneiron::store::{
    GateDecisionId, RetrievalAction, RetrievalBlendSignal, RetrievalRunId, RetrievalRunRecord,
    RetrievalSignal, RetrievalState,
};
use oneiron::test_doors::coach_retrieval_review;
use oneiron::test_doors::retrieval_policy_default_floor::record_retrieval_run;
use oneiron::verbs::{EmptyRequest, retrieval_policy_get_as_owner};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tune-oneiron-retrieval-pin"
);

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

fn fixture_line(name: &str) -> String {
    std::fs::read_to_string(Path::new(FIXTURE).join(name))
        .expect("fixture file")
        .trim()
        .to_owned()
}

/// Runs git offline in `dir`, with no system or user configuration.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .output()
        .expect("local git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git stdout")
        .trim()
        .to_owned()
}

fn copy_folder(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("fixture folder");
    for entry in std::fs::read_dir(from).expect("fixture listing") {
        let entry = entry.expect("fixture entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("fixture entry type").is_dir() {
            copy_folder(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("fixture copy");
        }
    }
}

/// A local Git repository holding the fixture's skills/ folder in one
/// commit: the folder and that commit.
fn fixture_hub() -> (tempfile::TempDir, String) {
    let repository = tempfile::tempdir().expect("hub folder");
    copy_folder(
        &Path::new(FIXTURE).join("skills"),
        &repository.path().join("skills"),
    );
    git(repository.path(), &["init", "--quiet"]);
    git(repository.path(), &["add", "."]);
    git(
        repository.path(),
        &["commit", "-qm", "library skill fixture"],
    );
    let commit = git(repository.path(), &["rev-parse", "HEAD"]);
    (repository, commit)
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
}

impl Fixture {
    fn open() -> Self {
        Self::open_with(false)
    }

    /// A vault whose retrieval telemetry capture is on or off.
    fn open_with(capture: bool) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::default();
        config.retrieval_telemetry_capture = capture;
        let vault = Vault::open(dir.path(), config).expect("vault");
        let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(
                owner_id,
                "principal:fixture-owner",
                true,
                GateDecisionId::now(),
            )
            .expect("authenticated owner");
        Self {
            _dir: dir,
            vault,
            owner,
        }
    }

    /// The owner points the default hub at `folder`, a local folder hub
    /// under the pinned-commit policy. Nothing is fetched.
    fn point_default_hub_at(&self, folder: &Path) {
        let record = SkillHubRecord::new(
            SkillHubKind::LocalDir,
            folder.to_str().expect("utf8 folder"),
            SkillHubTrustTier::Verified,
            HubSyncPolicy::PinnedCommit,
        )
        .expect("hub record");
        self.vault
            .configure_skill_hub(&self.owner, &hub(), &record, at(1), 1)
            .expect("configure the default hub");
    }

    fn import(&self, commit: &str) -> EntityId {
        coach_retrieval_review::import_default_hub_skill_at(
            &self.vault,
            &self.owner,
            TUNE_ONEIRON_RETRIEVAL_SUBTREE,
            commit,
            at(2),
            2,
        )
        .expect("the owner's library import")
    }

    fn installed(&self) -> Option<InstalledLibrarySkill> {
        self.vault
            .installed_default_hub_skill(TUNE_ONEIRON_RETRIEVAL_SUBTREE)
            .expect("installed library skill read")
    }
}

fn hub() -> EntityId {
    default_skill_hub_id().expect("default hub id")
}

#[test]
fn tune_oneiron_retrieval_imports_from_the_pinned_default_hub() {
    // The fixture is the hub's own subtree at the engine's released commit.
    assert_eq!(fixture_line("COMMIT"), default_skill_hub_commit());
    let (folder, commit) = fixture_hub();
    assert_eq!(
        git(
            folder.path(),
            &[
                "rev-parse",
                &format!("HEAD:{TUNE_ONEIRON_RETRIEVAL_SUBTREE}")
            ]
        ),
        fixture_line("TREE"),
        "the fixture folder is the hub's subtree at the released commit, byte for byte"
    );
    let fixture = Fixture::open();
    fixture.point_default_hub_at(folder.path());

    let id = fixture.import(&commit);

    let record = fixture
        .vault
        .get_skill_record(&id)
        .expect("skill read")
        .expect("the imported skill");
    assert_eq!(record.skill_id, "tune-oneiron-retrieval");
    assert_eq!(record.version, "0.1.0");
    assert_eq!(
        record.lifecycle_status,
        SkillLifecycle::Candidate,
        "a library import lands a Candidate; nothing activates it"
    );
    let source = HubRef::new(
        hub(),
        TUNE_ONEIRON_RETRIEVAL_SUBTREE,
        HubPin::Commit(commit.clone()),
    )
    .expect("hub ref");
    let receipt = fixture
        .vault
        .hub_import_receipt(&id, &source)
        .expect("receipt read")
        .expect("an import receipt from the default hub");
    assert_eq!(receipt.ref_string, TUNE_ONEIRON_RETRIEVAL_SUBTREE);
    assert_eq!(receipt.pin_value.as_deref(), Some(commit.as_str()));
}

#[test]
fn the_library_skill_is_found_only_after_the_owner_imports_it() {
    let (folder, commit) = fixture_hub();
    let fixture = Fixture::open();
    assert_eq!(
        fixture.installed(),
        None,
        "nothing imports the library skill on open"
    );
    fixture.point_default_hub_at(folder.path());
    assert_eq!(
        fixture.installed(),
        None,
        "pointing the hub at the skill fetches nothing"
    );
    // Today's nightly retrieval tune runs, and with no skill installed it
    // queues no host-run Coach job.
    coach_retrieval_review::run_retrieval_tune(&fixture.vault, 10)
        .expect("the retrieval tune completes");
    assert!(
        coach_retrieval_review::next_coach_host_attempt(&fixture.vault, 10)
            .expect("Coach host queue read")
            .is_none(),
        "no host-run Coach job waits"
    );

    let id = fixture.import(&commit);

    assert_eq!(
        fixture.installed(),
        Some(InstalledLibrarySkill {
            entity: id,
            skill_id: "tune-oneiron-retrieval".to_owned(),
            version: "0.1.0".to_owned(),
            commit,
        })
    );
}

/// Runs the seed publishes: enough for the skill to read a pattern, none of
/// them a number the engine judges by.
const SEEDED_RUNS: u64 = 40;

/// One published run whose vector channel never ran and that surfaced
/// nothing: the skill's first symptom ("Many empty packs") with its first
/// cause ("`Vector` is missing from `signals`").
fn run_without_vector(started_at: u64) -> RetrievalRunRecord {
    RetrievalRunRecord {
        version: 0,
        run_id: RetrievalRunId::now(),
        action: RetrievalAction::Pipeline,
        started_at,
        elapsed_us: 1_000,
        state: RetrievalState::default(),
        policy_trace: None,
        replay_inputs: None,
        turn: None,
        query_expander_id: None,
        dispatch_attempt: None,
        policy_manifest_ref: None,
        policy_manifest_body_hash: None,
        reranker_id: None,
        signals: vec![RetrievalSignal::Text],
        result_ids: Vec::new(),
        score_breakdown: Vec::new(),
        total_in_scope: 0,
        claims_suppressed: 0,
        empty_reason: Some("filter_matched_none".to_owned()),
        trace: None,
        quality: None,
        degradation: Vec::new(),
        confidence_adjustment: None,
    }
}

/// Publishes [`SEEDED_RUNS`] runs without the vector channel; their ids.
fn seed_runs_without_vector(vault: &Vault) -> Vec<RetrievalRunId> {
    (0..SEEDED_RUNS)
        .map(|at| {
            let run = run_without_vector(100 + at);
            record_retrieval_run(vault, &run).expect("publish a retrieval run");
            run.run_id
        })
        .collect()
}

/// The slow loop one night in: capture on, the skill imported, the runs
/// published, the nightly tune run and the review it queued leased.
struct Night {
    fixture: Fixture,
    commit: String,
    runs: Vec<RetrievalRunId>,
    review: DreamerAdmittedAttempt,
    _hub: tempfile::TempDir,
}

impl Night {
    fn after_the_tune() -> Self {
        let (hub, commit) = fixture_hub();
        let fixture = Fixture::open_with(true);
        fixture.point_default_hub_at(hub.path());
        fixture.import(&commit);
        let runs = seed_runs_without_vector(&fixture.vault);
        coach_retrieval_review::run_retrieval_tune(&fixture.vault, 1_000)
            .expect("the retrieval tune completes");
        let review = coach_retrieval_review::next_coach_host_attempt(&fixture.vault, 1_000)
            .expect("Coach host queue read")
            .expect("the review the tune queued");
        Self {
            fixture,
            commit,
            runs,
            review,
            _hub: hub,
        }
    }

    fn review_with(&self, reviewer: &Scripted, now: u64) -> RetrievalTuningReceipt {
        self.fixture
            .vault
            .run_coach_retrieval_skill_review(&self.review, reviewer, now)
            .expect("the review keeps a receipt")
    }

    /// The owner's served retrieval policy, as `vault.retrieval.policy.get`
    /// answers it.
    fn served_policy(&self) -> oneiron::verbs::RetrievalPolicyView {
        let vault = &self.fixture.vault;
        let memory = vault.memory(
            self.fixture
                .owner
                .actor_for_read(vault)
                .expect("owner actor"),
            EdgeActorClass::Human,
        );
        retrieval_policy_get_as_owner(&memory, &self.fixture.owner, EmptyRequest {})
            .expect("the owner reads the served policy")
    }

    /// What the bandit and the learner hold: the active blend table, the
    /// pins and the posterior, as served.
    fn learned_state(&self) -> serde_json::Value {
        let view = self.served_policy();
        serde_json::json!({
            "active": view.active,
            "pins": view.pins,
            "posterior": [
                view.posterior_tuned_at,
                view.posterior_labeled_runs,
                view.posterior_observations,
            ],
        })
    }

    fn owner_notes(&self) -> Vec<NotificationRow> {
        let vault = &self.fixture.vault;
        vault
            .memory(
                self.fixture
                    .owner
                    .actor_for_read(vault)
                    .expect("owner actor"),
                EdgeActorClass::Human,
            )
            .inbox_list(None, INBOX_PAGE_DEFAULT)
            .expect("inbox read")
            .rows
            .into_iter()
            .filter(|row| row.source.producer == RETRIEVAL_TUNING_NOTIFICATION_PRODUCER)
            .collect()
    }
}

/// A test double of the host's model: answers with one fixed proposal and
/// keeps the brief it read.
struct Scripted {
    proposal: RetrievalTuningProposal,
    brief: RefCell<Option<RetrievalSkillBrief>>,
}

impl Scripted {
    fn answering(proposal: RetrievalTuningProposal) -> Self {
        Self {
            proposal,
            brief: RefCell::new(None),
        }
    }
}

impl RetrievalSkillReviewer for Scripted {
    fn review(&self, brief: &RetrievalSkillBrief) -> oneiron::Result<RetrievalTuningProposal> {
        *self.brief.borrow_mut() = Some(brief.clone());
        Ok(self.proposal.clone())
    }
}

fn proposal(
    kind: RetrievalTuningProposalKind,
    knob: Option<RetrievalTuningKnob>,
    change: Option<&str>,
    evidence_runs: Vec<RetrievalRunId>,
) -> RetrievalTuningProposal {
    RetrievalTuningProposal {
        kind,
        symptom: "40 of 40 runs surfaced nothing; Vector is missing from signals in all 40"
            .to_owned(),
        causes_checked: vec!["1. the vector channel never ran: no query embedding".to_owned()],
        knob,
        slice: None,
        change: change.map(str::to_owned),
        evidence_runs,
    }
}

#[test]
fn sleep_queues_the_skill_review_after_the_bandit_update() {
    let (hub, commit) = fixture_hub();
    let fixture = Fixture::open_with(true);
    fixture.point_default_hub_at(hub.path());
    fixture.import(&commit);
    seed_runs_without_vector(&fixture.vault);

    let tune = coach_retrieval_review::run_retrieval_tune(&fixture.vault, 1_000)
        .expect("the retrieval tune completes");

    let review = coach_retrieval_review::next_coach_host_attempt(&fixture.vault, 1_000)
        .expect("Coach host queue read")
        .expect("one review waits on the Coach host queue");
    assert_eq!(
        review.status.payload.attempt_type,
        COACH_RETRIEVAL_SKILL_REVIEW_FACET
    );
    assert_eq!(
        review.status.payload.parent_attempt,
        Some(tune),
        "the bandit update's tune queued the review as its child"
    );
    let newest = fixture
        .vault
        .retrieval_runs(1)
        .expect("runs read")
        .first()
        .map(|run| run.run_id);
    let status = fixture
        .vault
        .retrieval_slow_loop()
        .expect("slow loop read")
        .status
        .expect("the tune's slow-loop status");
    assert_eq!(status.tune_attempt, tune);
    assert_eq!(status.skipped, None);
    assert_eq!(status.review, Some(review.status.attempt.id));
    assert_eq!(status.reviewed_through, newest);

    // Another tune with no new run queues nothing, and says why. One
    // second on, so the leased review's lease still holds.
    let quiet = coach_retrieval_review::run_retrieval_tune(&fixture.vault, 1_001)
        .expect("the second tune completes");
    assert!(
        coach_retrieval_review::next_coach_host_attempt(&fixture.vault, 1_001)
            .expect("Coach host queue read")
            .is_none(),
        "no second review for the same runs"
    );
    let status = fixture
        .vault
        .retrieval_slow_loop()
        .expect("slow loop read")
        .status
        .expect("the second tune's status");
    assert_eq!(status.tune_attempt, quiet);
    assert_eq!(
        status.skipped.as_deref(),
        Some("no retrieval run was published since the last review")
    );
    assert_eq!(status.review, Some(review.status.attempt.id));
    assert_eq!(status.reviewed_through, newest);
}

#[test]
fn no_installed_skill_queues_no_review_and_names_the_import() {
    let (hub, _commit) = fixture_hub();
    let fixture = Fixture::open_with(true);
    fixture.point_default_hub_at(hub.path());
    seed_runs_without_vector(&fixture.vault);

    let tune = coach_retrieval_review::run_retrieval_tune(&fixture.vault, 1_000)
        .expect("the retrieval tune completes");

    assert!(
        coach_retrieval_review::next_coach_host_attempt(&fixture.vault, 1_000)
            .expect("Coach host queue read")
            .is_none(),
        "no review without the skill"
    );
    let status = fixture
        .vault
        .retrieval_slow_loop()
        .expect("slow loop read")
        .status
        .expect("the tune's slow-loop status");
    assert_eq!(status.tune_attempt, tune);
    assert_eq!(
        status.skipped.as_deref(),
        Some("tune-oneiron-retrieval is not installed; import skills/tune-oneiron-retrieval")
    );
    assert_eq!(status.review, None);
}

#[test]
fn a_vault_without_capture_queues_no_review_and_says_so() {
    let (hub, commit) = fixture_hub();
    let fixture = Fixture::open_with(false);
    fixture.point_default_hub_at(hub.path());
    fixture.import(&commit);
    seed_runs_without_vector(&fixture.vault);

    coach_retrieval_review::run_retrieval_tune(&fixture.vault, 1_000)
        .expect("the retrieval tune completes");

    assert!(
        coach_retrieval_review::next_coach_host_attempt(&fixture.vault, 1_000)
            .expect("Coach host queue read")
            .is_none(),
        "no review while capture is off"
    );
    let status = fixture
        .vault
        .retrieval_slow_loop()
        .expect("slow loop read")
        .status
        .expect("the tune's slow-loop status");
    assert_eq!(
        status.skipped.as_deref(),
        Some("retrieval telemetry capture is off; the slow loop reviews captured runs")
    );
}

#[test]
fn the_review_writes_one_proposal_stamped_with_the_skill_version() {
    let night = Night::after_the_tune();
    let learned = night.learned_state();
    let sent = proposal(
        RetrievalTuningProposalKind::OwnerRecommendation,
        Some(RetrievalTuningKnob::Other(
            "the host's query embedding".to_owned(),
        )),
        Some("none -> pass the query embedding to retrieval"),
        night.runs[..5].to_vec(),
    );
    let reviewer = Scripted::answering(sent.clone());

    let receipt = night.review_with(&reviewer, 2_000);

    let brief = reviewer
        .brief
        .borrow()
        .clone()
        .expect("the reviewer read a brief");
    let skill_text =
        std::fs::read_to_string(Path::new(FIXTURE).join("skills/tune-oneiron-retrieval/SKILL.md"))
            .expect("fixture SKILL.md");
    assert!(
        brief
            .files
            .iter()
            .any(|file| file.path == "SKILL.md" && file.text == skill_text),
        "the brief holds the imported SKILL.md, byte for byte"
    );
    assert!(
        brief
            .files
            .iter()
            .any(|file| file.path == "references/knobs.md"),
        "the brief holds the skill's knob table"
    );
    let mut read: Vec<String> = brief.runs.iter().map(|run| run.run_id.to_hex()).collect();
    let mut seeded: Vec<String> = night.runs.iter().map(|run| run.to_hex()).collect();
    read.sort();
    seeded.sort();
    assert_eq!(read, seeded, "the brief holds every published run");

    assert_eq!(receipt.attempt, night.review.status.attempt.id);
    assert_eq!(
        receipt.tune_attempt,
        night.review.status.payload.parent_attempt
    );
    assert_eq!(receipt.skill_id, "tune-oneiron-retrieval");
    assert_eq!(receipt.skill_version, "0.1.0");
    assert_eq!(receipt.hub_commit, night.commit);
    assert_eq!(receipt.proposal, sent);
    assert_eq!(receipt.disposition, RetrievalTuningDisposition::Offered);
    assert_eq!(
        night.learned_state(),
        learned,
        "the review writes no live value: the blend table, pins and posterior are unchanged"
    );
    let notes = night.owner_notes();
    assert_eq!(notes.len(), 1, "one owner inbox note: {notes:?}");
    assert_eq!(notes[0].kind, NotificationKind::Ask);
    assert_eq!(
        notes[0].source.detail.as_deref(),
        Some(sent.symptom.as_str())
    );
    assert_eq!(
        night.served_policy().slow_loop.receipts,
        vec![receipt.clone()],
        "vault.retrieval.policy.get lists the receipt"
    );

    // A replay of the attempt returns its receipt and asks nothing.
    let replay = Scripted::answering(proposal(
        RetrievalTuningProposalKind::EngineWork,
        None,
        None,
        Vec::new(),
    ));
    assert_eq!(night.review_with(&replay, 3_000), receipt);
    assert!(
        replay.brief.borrow().is_none(),
        "the replay asked the reviewer nothing"
    );
    assert_eq!(night.owner_notes().len(), 1);
}

#[test]
fn a_proposal_that_sets_a_bandit_value_is_refused() {
    let night = Night::after_the_tune();
    let learned = night.learned_state();
    let reviewer = Scripted::answering(proposal(
        RetrievalTuningProposalKind::LearnerReseed,
        Some(RetrievalTuningKnob::BlendWeight(
            RetrievalBlendSignal::Recency,
        )),
        Some("0.35 -> 0.50"),
        night.runs[..5].to_vec(),
    ));

    let receipt = night.review_with(&reviewer, 2_000);

    let RetrievalTuningDisposition::Refused { reason } = &receipt.disposition else {
        panic!("a live blend weight is refused: {:?}", receipt.disposition);
    };
    assert!(
        reason.contains("a value the bandit learns"),
        "the refusal names the rule: {reason}"
    );
    assert!(
        night.owner_notes().is_empty(),
        "a refused proposal reaches no inbox"
    );
    assert_eq!(
        night.learned_state(),
        learned,
        "the blend table is unchanged"
    );
}

#[test]
fn a_proposal_citing_a_run_outside_the_brief_is_refused() {
    let night = Night::after_the_tune();
    let stranger = RetrievalRunId::now();
    let reviewer = Scripted::answering(proposal(
        RetrievalTuningProposalKind::OwnerRecommendation,
        Some(RetrievalTuningKnob::Other(
            "the host's query embedding".to_owned(),
        )),
        Some("none -> pass the query embedding to retrieval"),
        vec![night.runs[0], stranger],
    ));

    let receipt = night.review_with(&reviewer, 2_000);

    let RetrievalTuningDisposition::Refused { reason } = &receipt.disposition else {
        panic!(
            "a run outside the brief is refused: {:?}",
            receipt.disposition
        );
    };
    assert!(
        reason.contains(&stranger.to_hex()),
        "the refusal names the run: {reason}"
    );
    assert!(night.owner_notes().is_empty());
}
