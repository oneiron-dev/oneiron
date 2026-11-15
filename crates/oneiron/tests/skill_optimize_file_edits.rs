//! Census L9-02 (Engine ruling 13 Nov 22:39): a skill_optimize draft may
//! replace whole the existing text and data files of a skill's tree, within
//! bounds, and never a script or a new path. The proposal's package holds the
//! edits, the held-out gate scores the edited files, and admission serves the
//! new tree under its recomputed content hash.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, ManifestEntry,
    ManifestKind,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::error::{ErrorKind, Result};
use oneiron::skill::{SkillGovernanceTier, SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface};
use oneiron::skill_optimize::{
    PROVENANCE_OPTIMIZE_EDITED_FILES_KEY, SkillEditDisposition, SkillEditDraft, SkillFileEdit,
    SkillOptimizeAuthor, SkillOptimizeBrief, admit_optimized_skill_revision,
    score_gate_skill_edit_in_cycle,
};
use oneiron::test_doors::skill_optimize_files::{
    draft_on_skill, enqueue_skill_optimize_attempt, marker_scorer, served_skill_package,
};
use oneiron::test_doors::skill_package::land_active_skill_with_files;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const SKILL_ID: &str = "skill-files.fixture";
const DESC: &str = "Follow the guide and report.";
const BODY: &str = "Follow references/guide.md, then report.\n";
const GUIDE: &str = "Step one: read the task.\n";
const SCRIPT: &str = "#!/bin/sh\necho run\n";
const LIMITS: &str = "{\"max_steps\": 4}\n";
/// The phrase the fixture judge rewards; only the edited guide carries it.
const MARKER: &str = "check result";
const EDITED_GUIDE: &str = "Step one: read the task.\nStep two: check result before you report.\n";
const EDITED_BODY: &str = "Follow references/guide.md step by step, then report.\n";
/// A rule skill's text naming a dial of its `policy.json` at 4.
const POLICY_DESC: &str =
    "Follow the guide and report; stop a loop after health.loop.repeats at 4 rounds.";
/// The `policy.json` beside [`POLICY_DESC`], holding the 4 its text names.
const POLICY: &str = "{\"health.loop.repeats\": 4}\n";
/// [`POLICY_DESC`] with the dial moved to 6.
const POLICY_DESC_AT_6: &str =
    "Follow the guide and report; stop a loop after health.loop.repeats at 6 rounds.";

fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

fn skill_md(desc: &str) -> String {
    format!("---\nname: {SKILL_ID}\ndescription: {desc}\nversion: 1\n---\n{BODY}")
}

fn tree() -> Vec<HubFile> {
    vec![
        HubFile::new("SKILL.md", skill_md(DESC).into_bytes()),
        HubFile::new("references/guide.md", GUIDE),
        HubFile::new("scripts/run.sh", SCRIPT),
        HubFile::new("data/limits.json", LIMITS),
    ]
}

/// The tree above as a rule skill described as [`POLICY_DESC`], with
/// [`POLICY`] beside it.
fn policy_tree() -> Vec<HubFile> {
    let mut files = tree();
    files[0] = HubFile::new("SKILL.md", skill_md(POLICY_DESC).into_bytes());
    files.push(HubFile::new("policy.json", POLICY));
    files
}

/// A vault holding one active, Standard, human-authored skill with the
/// four-file tree above, and a held-out reserve of its outcomes.
fn fixture() -> (tempfile::TempDir, Vault, EntityId, SkillRecord) {
    fixture_with(DESC, tree())
}

/// [`fixture`] for a skill described as `desc` with the tree `files`.
fn fixture_with(
    desc: &str,
    files: Vec<HubFile>,
) -> (tempfile::TempDir, Vault, EntityId, SkillRecord) {
    let temp = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(temp.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            owner,
            "principal:fixture-owner",
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("authenticated owner");
    let mut record = SkillRecord::new(
        SKILL_ID,
        desc,
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.5,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("skill-files-fixture"),
        )]),
    )
    .with_governance_tier(SkillGovernanceTier::Standard);
    record.content_hash = Some(
        HubPackage::new(
            record.clone(),
            files.clone(),
            SkillCapabilitySurface::default(),
        )
        .content_hash()
        .expect("tree hash"),
    );
    let skill = land_active_skill_with_files(&vault, &record, files).expect("active skill");
    reserve(&vault, &skill);
    let stored = vault.get_skill_record(&skill).unwrap().expect("stored");
    (temp, vault, skill, stored)
}

/// Records attributed wins of the skill until its held-out reserve is not
/// empty, so the gate has evidence to score against.
fn reserve(vault: &Vault, skill: &EntityId) {
    let queue = AttemptQueue::new(vault);
    let dispatcher = AgentDispatcher::new(vault);
    for _ in 0..200 {
        let now = vault.now_recorded_at();
        let AgentDispatchOutcome::Dispatched(dispatched) = dispatcher
            .dispatch_default_base(None, None, None, now)
            .expect("enqueue typed agent dispatch")
        else {
            panic!("fresh agent dispatch");
        };
        let attempt = dispatched.attempt;
        queue
            .append_manifest_entry(
                attempt.id,
                ManifestEntry::new(ManifestKind::Skill, SKILL_ID, "1", now),
            )
            .expect("skill manifest");
        let ClaimOutcome::Claimed(leased) = queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "fixture".to_owned(),
                    now: vault.now_recorded_at(),
                },
            )
            .expect("claim")
        else {
            panic!("claimable attempt");
        };
        assert_eq!(leased.id, attempt.id);
        queue
            .set_executor_model(
                attempt.id,
                "fixture",
                leased.attempt_count,
                "fixture/model@1",
            )
            .expect("executor stamp");
        assert!(matches!(
            queue
                .complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: "fixture".to_owned(),
                    attempt_count: leased.attempt_count,
                    now: vault.now_recorded_at(),
                })
                .expect("complete"),
            CompleteOutcome::Completed(_)
        ));
        let receipt = oneiron::receipt::attempt_pack_receipt_id(&attempt.id);
        oneiron::skill_reliability::record_skill_contributing_win(
            vault,
            skill,
            &receipt,
            vault.now_recorded_at(),
        )
        .expect("attribute win");
        if !oneiron::skill_optimize::held_out_receipts(vault, skill)
            .expect("held-out reserve")
            .is_empty()
        {
            return;
        }
    }
    panic!("fixture did not obtain held-out evidence");
}

/// An author that answers one fixed draft and keeps every brief it read.
struct FixedAuthor {
    answer: SkillEditDraft,
    seen: RefCell<Vec<SkillOptimizeBrief>>,
}

impl FixedAuthor {
    fn editing(desc: &str, files: &[(&str, &str)]) -> Self {
        Self {
            answer: SkillEditDraft::Edit {
                desc: desc.to_owned(),
                rationale: "the guide misses the step the evidence names".to_owned(),
                files: files
                    .iter()
                    .map(|(path, content)| SkillFileEdit {
                        path: (*path).to_owned(),
                        content: (*content).to_owned(),
                    })
                    .collect(),
            },
            seen: RefCell::new(Vec::new()),
        }
    }

    fn brief(&self) -> SkillOptimizeBrief {
        self.seen.borrow().first().cloned().expect("one brief")
    }
}

impl SkillOptimizeAuthor for FixedAuthor {
    fn draft(&self, brief: &SkillOptimizeBrief) -> Result<SkillEditDraft> {
        self.seen.borrow_mut().push(brief.clone());
        Ok(self.answer.clone())
    }
}

fn file<'a>(package: &'a HubPackage, path: &str) -> &'a [u8] {
    package
        .files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.content.as_slice())
        .unwrap_or_else(|| panic!("the tree holds {path}"))
}

/// `SKILL.md`'s frontmatter and body.
fn split_skill_md(content: &[u8]) -> (String, String) {
    let text = std::str::from_utf8(content).expect("SKILL.md is text");
    let front = text.strip_prefix("---\n").expect("frontmatter");
    let end = front.find("\n---\n").expect("closed frontmatter");
    (front[..end].to_owned(), front[end + 5..].to_owned())
}

/// A JSON array of `word` strings, one per line, of about `bytes` bytes:
/// dense in quotes and newlines, which the judge's JSON state escapes.
fn dense_json(word: &str, bytes: usize) -> String {
    let mut text = String::from("[\n");
    while text.len() + 2 * word.len() + 16 < bytes {
        text.push_str(&format!("  \"{word}\",\n"));
    }
    text.push_str(&format!("  \"{word}\"\n]\n"));
    text
}

fn edited_files(record: &SkillRecord) -> Option<Vec<String>> {
    let rmpv::Value::Map(entries) = &record.provenance else {
        panic!("provenance is a map");
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(PROVENANCE_OPTIMIZE_EDITED_FILES_KEY))
        .map(|(_, value)| {
            value
                .as_array()
                .expect("edited paths")
                .iter()
                .map(|path| path.as_str().expect("a path").to_owned())
                .collect()
        })
}

#[test]
fn an_edit_may_replace_a_skill_files_text_and_is_served_under_a_new_content_hash() {
    let (_temp, vault, skill, parent) = fixture();
    let now = vault.now_recorded_at();
    let author = FixedAuthor::editing(
        DESC,
        &[
            ("references/guide.md", EDITED_GUIDE),
            ("SKILL.md", EDITED_BODY),
        ],
    );
    let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("optimize attempt");
    let outcome = draft_on_skill(&vault, &skill, attempt, &author, now).expect("drafted");
    let proposal = outcome.proposal.expect("a file edit lands a proposal");

    // The brief carries the text and data files whole, SKILL.md as its body,
    // and never the script.
    let brief = author.brief();
    let carried: Vec<(&str, Option<&str>)> = brief
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.content.as_deref()))
        .collect();
    assert_eq!(
        carried,
        vec![
            ("SKILL.md", Some(BODY)),
            ("data/limits.json", Some(LIMITS)),
            ("references/guide.md", Some(GUIDE)),
        ]
    );

    // The proposal holds the edits; the script and the data file stay
    // byte-exact; the tree hash is recomputed.
    let staged = vault
        .get_skill_record(&proposal)
        .unwrap()
        .expect("proposal");
    assert_eq!(staged.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(staged.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(staged.desc, DESC, "a file edit may keep the instructions");
    assert_ne!(staged.version, parent.version);
    assert_ne!(staged.content_hash, parent.content_hash);
    assert_eq!(
        edited_files(&staged),
        Some(vec![
            "references/guide.md".to_owned(),
            "SKILL.md".to_owned()
        ])
    );
    let package = served_skill_package(&vault, &proposal)
        .unwrap()
        .expect("the proposal has a package");
    assert_eq!(
        file(&package, "references/guide.md"),
        EDITED_GUIDE.as_bytes()
    );
    assert_eq!(file(&package, "scripts/run.sh"), SCRIPT.as_bytes());
    assert_eq!(file(&package, "data/limits.json"), LIMITS.as_bytes());
    let (front, body) = split_skill_md(file(&package, "SKILL.md"));
    assert_eq!(body, EDITED_BODY, "a non-workflow skill's body can change");
    assert!(
        front
            .lines()
            .any(|line| line.starts_with("description:") && line.contains(DESC)),
        "the frontmatter's description is the draft's desc: {front}"
    );

    // The gate's judge reads the edited guide: only it names the marker.
    let wake = enqueue_skill_optimize_attempt(&vault, Some("wake-1"), now + 10).expect("wake");
    let verdict = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &marker_scorer(MARKER),
        wake,
        vault.now_recorded_at(),
    )
    .expect("gate");
    assert_eq!(verdict.disposition, SkillEditDisposition::Accepted);

    // Admission serves the edited tree under the recomputed hash.
    let admitted_at = vault.now_recorded_at();
    admit_optimized_skill_revision(&vault, &proposal, at(admitted_at), admitted_at)
        .expect("admitted");
    let admitted = vault
        .get_skill_record(&proposal)
        .unwrap()
        .expect("admitted");
    assert_eq!(admitted.approval_status, ClaimApprovalStatus::Approved);
    assert_eq!(admitted.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(admitted.content_hash, staged.content_hash);
    assert_ne!(admitted.content_hash, parent.content_hash);
    let served = served_skill_package(&vault, &proposal)
        .unwrap()
        .expect("the admitted skill serves a package");
    assert_eq!(
        file(&served, "references/guide.md"),
        EDITED_GUIDE.as_bytes()
    );
    assert_eq!(file(&served, "scripts/run.sh"), SCRIPT.as_bytes());
}

#[test]
fn a_draft_naming_a_script_or_a_new_path_is_refused() {
    let (_temp, vault, skill, _) = fixture();
    let refused = |files: &[(&str, &str)], desc: &str| {
        let now = vault.now_recorded_at();
        let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("attempt");
        let error = draft_on_skill(
            &vault,
            &skill,
            attempt,
            &FixedAuthor::editing(desc, files),
            now,
        )
        .expect_err("refused");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidSkillBody,
            "{files:?}: {error}"
        );
    };
    refused(&[("scripts/run.sh", "#!/bin/sh\necho changed\n")], DESC);
    refused(&[("references/new.md", "A new page.\n")], DESC);
    refused(&[("references/guide.md", GUIDE)], DESC);
    refused(
        &[
            ("references/guide.md", EDITED_GUIDE),
            ("references/guide.md", EDITED_GUIDE),
        ],
        DESC,
    );
    refused(&[], DESC);

    // No refusal left a proposal behind: the target has no open revision,
    // so a valid edit still lands.
    let now = vault.now_recorded_at();
    let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("attempt");
    let outcome = draft_on_skill(
        &vault,
        &skill,
        attempt,
        &FixedAuthor::editing(DESC, &[("references/guide.md", EDITED_GUIDE)]),
        now,
    )
    .expect("a valid edit lands");
    assert!(outcome.proposal.is_some());
}

#[test]
fn an_instructions_only_edit_keeps_every_file_but_the_description() {
    let (_temp, vault, skill, parent) = fixture();
    let now = vault.now_recorded_at();
    let desc = "Follow the guide, check each step, then report.";
    let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("attempt");
    let proposal = draft_on_skill(
        &vault,
        &skill,
        attempt,
        &FixedAuthor::editing(desc, &[]),
        now,
    )
    .expect("drafted")
    .proposal
    .expect("an instructions edit lands a proposal");
    let staged = vault
        .get_skill_record(&proposal)
        .unwrap()
        .expect("proposal");
    assert_eq!(staged.desc, desc);
    assert_eq!(edited_files(&staged), None);
    assert_ne!(staged.content_hash, parent.content_hash);
    let package = served_skill_package(&vault, &proposal)
        .unwrap()
        .expect("the proposal has a package");
    assert_eq!(file(&package, "references/guide.md"), GUIDE.as_bytes());
    assert_eq!(file(&package, "scripts/run.sh"), SCRIPT.as_bytes());
    assert_eq!(file(&package, "data/limits.json"), LIMITS.as_bytes());
    let (_, body) = split_skill_md(file(&package, "SKILL.md"));
    assert_eq!(body, BODY);
}

/// A rule skill's `policy.json` holds each number its text names (FIX
/// 10878; cold read N3 of #7949): a draft whose text moves the number moves
/// the dial, a file edit that keeps the text keeps the file, and a drafted
/// `policy.json` lands only when it is one JSON object, with no key named
/// twice, that holds the numbers the final text names and runs them for
/// each detector dial (review round 2 of #7949), so no revision's text
/// names a dial value its file does not run.
#[test]
fn a_drafted_policy_json_holds_the_numbers_its_text_names() {
    let drafted_policy = |desc: &str, files: &[(&str, &str)]| -> Result<Vec<u8>> {
        let (_temp, vault, skill, _) = fixture_with(POLICY_DESC, policy_tree());
        let now = vault.now_recorded_at();
        let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("attempt");
        let proposal = draft_on_skill(
            &vault,
            &skill,
            attempt,
            &FixedAuthor::editing(desc, files),
            now,
        )?
        .proposal
        .expect("the draft lands a proposal");
        let package = served_skill_package(&vault, &proposal)
            .unwrap()
            .expect("the proposal has a package");
        Ok(file(&package, "policy.json").to_vec())
    };
    let policy_at = |repeats: u32| format!("{{\"health.loop.repeats\": {repeats}}}\n");

    assert_eq!(
        drafted_policy(POLICY_DESC, &[("SKILL.md", EDITED_BODY)]).expect("drafted"),
        POLICY.as_bytes(),
        "a file edit that keeps the text keeps the file"
    );
    let moved: serde_json::Value =
        serde_json::from_slice(&drafted_policy(POLICY_DESC_AT_6, &[]).expect("drafted"))
            .expect("policy.json is JSON");
    assert_eq!(
        moved["health.loop.repeats"].as_f64(),
        Some(6.0),
        "a text that moves the number moves the dial: {moved}"
    );
    assert_eq!(
        drafted_policy(POLICY_DESC_AT_6, &[("policy.json", policy_at(6).as_str())])
            .expect("drafted"),
        policy_at(6).as_bytes(),
        "a drafted policy.json that holds its text's number lands as drafted"
    );
    let error = drafted_policy(POLICY_DESC, &[("policy.json", policy_at(9).as_str())])
        .expect_err("a drafted policy.json at another number than its text names is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidSkillBody, "{error}");
    // A file that leaves a named dial out, or holds it past the dial's
    // bounds (the loop dial's least is 2), runs the compiled seed, 3.
    for (desc, policy, shape) in [
        (POLICY_DESC, "{}\n", "the dial its text names at 4 left out"),
        (
            "Follow the guide and report; stop a loop after health.loop.repeats at 1 rounds.",
            "{\"health.loop.repeats\": 1}\n",
            "the dial its text names at 1 held out of bounds",
        ),
    ] {
        let error = drafted_policy(desc, &[("policy.json", policy)])
            .expect_err("a drafted policy.json that does not run its text's number is refused");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidSkillBody,
            "{shape}: {error}"
        );
    }
    assert_eq!(
        drafted_policy(
            "Follow the guide and report; stop a loop after health.loop.repeats at 3 rounds.",
            &[("policy.json", "{}\n")],
        )
        .expect("drafted"),
        "{}\n".as_bytes(),
        "a file that leaves out a dial its text names at the compiled seed runs that number"
    );
    for (policy, shape) in [
        ("[4]\n", "not one JSON object"),
        (
            "{\"health.loop.repeats\": 9, \"health.loop.repeats\": 4}\n",
            "a key named twice",
        ),
    ] {
        let error = drafted_policy(POLICY_DESC, &[("policy.json", policy)])
            .expect_err("a drafted policy.json its reader sets aside whole is refused");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidSkillBody,
            "{shape}: {error}"
        );
    }
}

/// A dependency or package manifest chooses the third-party code a skill's
/// scripts install and run, and an optimizer revision runs no advisory scan
/// (cold read N2 of #7949): the brief never offers one, and a draft naming
/// one is refused like a script.
#[test]
fn a_dependency_manifest_is_never_draftable() {
    let mut files = tree();
    files.push(HubFile::new("requirements.txt", "requests==2.31.0\n"));
    files.push(HubFile::new(
        "package.json",
        "{\"dependencies\": {\"left-pad\": \"1.3.0\"}}\n",
    ));
    let (_temp, vault, skill, _) = fixture_with(DESC, files);
    for (path, content) in [
        ("requirements.txt", "requests==2.5.0\n"),
        (
            "package.json",
            "{\"dependencies\": {\"left-pad\": \"1.0.0\"}}\n",
        ),
    ] {
        let now = vault.now_recorded_at();
        let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("attempt");
        let author = FixedAuthor::editing(DESC, &[(path, content)]);
        let drafted = draft_on_skill(&vault, &skill, attempt, &author, now);
        let offered: Vec<String> = author
            .brief()
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect();
        assert!(
            !offered
                .iter()
                .any(|offered| offered == "requirements.txt" || offered == "package.json"),
            "the brief offers no dependency manifest: {offered:?}"
        );
        let error = drafted.expect_err("a draft naming a dependency manifest is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidSkillBody, "{path}: {error}");
    }

    // No refusal left a proposal behind, and a data file edit still lands.
    let now = vault.now_recorded_at();
    let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("attempt");
    let outcome = draft_on_skill(
        &vault,
        &skill,
        attempt,
        &FixedAuthor::editing(DESC, &[("references/guide.md", EDITED_GUIDE)]),
        now,
    )
    .expect("a valid edit lands");
    assert!(outcome.proposal.is_some());
}

/// The held-out gate judges each arm through a decision state of at most
/// 64 KiB, which a larger state is cut to fit, keeping a prefix of the
/// instructions (cold read N1 of #7949). A draft whose files, each and all
/// inside the brief's bounds, would carry its arm past half that bound is
/// refused at the draft door, so the judge never scores a prefix that stops
/// before the last file; one such file fits and lands.
#[test]
fn a_file_draft_the_judge_cannot_read_whole_is_refused() {
    const TABLE_BYTES: usize = 14 * 1024;
    let tables: Vec<String> = (1..=4).map(|n| format!("data/table-{n}.json")).collect();
    let mut files = tree();
    for table in &tables {
        files.push(HubFile::new(
            table.as_str(),
            dense_json("step", TABLE_BYTES),
        ));
    }
    let (_temp, vault, skill, _) = fixture_with(DESC, files);
    let edited: Vec<String> = (1..=4)
        .map(|n| dense_json(if n == 4 { MARKER } else { "next" }, TABLE_BYTES))
        .collect();
    let edits: Vec<(&str, &str)> = tables
        .iter()
        .zip(&edited)
        .map(|(path, content)| (path.as_str(), content.as_str()))
        .collect();

    let now = vault.now_recorded_at();
    let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("attempt");
    let author = FixedAuthor::editing(DESC, &edits);
    let drafted = draft_on_skill(&vault, &skill, attempt, &author, now);
    let whole = author
        .brief()
        .files
        .iter()
        .filter(|file| file.path.starts_with("data/table-") && file.content.is_some())
        .count();
    assert_eq!(whole, 4, "the brief carries every table whole");
    let error = drafted.expect_err("a draft the judge cannot read whole is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidSkillBody, "{error}");

    // No refusal left a proposal behind, and one table fits the judge whole.
    let now = vault.now_recorded_at();
    let attempt = enqueue_skill_optimize_attempt(&vault, None, now).expect("attempt");
    let outcome = draft_on_skill(
        &vault,
        &skill,
        attempt,
        &FixedAuthor::editing(DESC, &edits[3..]),
        now,
    )
    .expect("one table fits the judge whole");
    assert!(outcome.proposal.is_some());
}
