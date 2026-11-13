//! The Coach's workaround skills (CLIF-STEALS 2: ARCH-0053
//! #outside-app-evidence, ARCH-0027 #ag-ui-source; Engine RULING
//! L2-15-SHAPE = A): the skills job also distils a skill from a person's
//! repeated workaround in an outside app after the app agent's run. Fixed
//! code, no model call, so it needs no seat.
//!
//! The evidence is the owner's AG-UI captures. In a capture, a `Linked`
//! repair link joins one app-reported failure, the person's repair of it and
//! the reported outcome inside one app run (its thread and run ids). The
//! links group by where the capture stands (its project), the app, the
//! failure name and the repair name: the owner-registered CUSTOM names. A
//! group whose links fall in at least [`WORKAROUND_MIN_RUNS`] distinct app
//! runs nominates one new skill. An app run counts once, however many
//! captures or outcomes repeat it.
//!
//! A nomination lands in one write: a born-Proposed, Candidate Native skill
//! on the Dreamer-distill road (birth `dreamer_distill`) and one Proposed
//! finding where the captures stand. The skill's files name only the app,
//! the failure and the repair by their registered names, and the trigger. No
//! imported payload text reaches an instruction-bearing file: an imported
//! event is evidence, never an instruction. The finding shows the supporting
//! runs and the counterexamples, each as an exact anchor in its capture. A
//! counterexample is a linked run of the same failure that the person
//! repaired another way. A missing link, or an outcome with no repair, is
//! completeness-unknown and is neither.
//!
//! Repetition nominates a fix and never proves one. The Candidate is inert:
//! it waits on the ordinary skill gate like any other birth, and the Coach
//! never admits, activates or queues anything for it. A content-hash
//! duplicate files no second skill, and its finding points at the holder. A
//! skill id another skill holds files only a collision finding. Findings are
//! content-addressed, so the same evidence files nothing new.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;
use serde::Serialize;

use super::coach::COACH_SKILL_DISTILL_FACET;
use super::proposals::{self, FindingPlace};
use super::site_skills::skill_holders_in_txn;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::entity_id::bytes_to_hex_lower;
use crate::ingest::{
    AgUiAppObservation, AgUiRepairLinkStatus, StoredAgUiCapture, ag_ui_capture_holds_in_txn,
    standing_ag_ui_captures_in_txn,
};
use crate::skill::{SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash};
use crate::skill_hub::{HubFile, SkillPackageFormat, package_from_source};
use crate::skill_reliability::{ProvenanceTrustClass, SkillReliabilityPosterior};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteEnvelope;
use crate::{EntityId, Error, Result, Vault};

/// The distinct app runs a repeated workaround needs before it nominates a
/// skill: an Engine constant (RULING L2-15-SHAPE = A), not a setting.
pub const WORKAROUND_MIN_RUNS: usize = 3;

/// The predicate a workaround-skill finding is filed under.
pub const COACH_WORKAROUND_SKILLS_PREDICATE: &str = "coach.workaround_skills.proposal";

/// The prefix of every workaround skill's id.
pub const WORKAROUND_SKILL_ID_PREFIX: &str = "workaround-";

/// The record and frontmatter version of every workaround skill: its bytes
/// are a function of the three names alone.
const WORKAROUND_SKILL_VERSION: &str = "0.1.0";

/// The finding value's version.
const WORKAROUND_DISTILL_VERSION: u32 = 1;

/// The domain a capture's place digest is hashed in.
const PLACE_DOMAIN: &[u8] = b"oneiron:coach-workaround-skill-place:v1";

/// The domain a skill id's suffix is hashed in.
const SKILL_ID_DOMAIN: &[u8] = b"oneiron:coach-workaround-skill-id:v1";

/// The longest a name renders in a description, cut at a char boundary.
const DESCRIPTION_NAME_CAP: usize = 256;

/// The longest a name renders in the skill's body, cut at a char boundary.
const BODY_NAME_CAP: usize = 1024;

/// The longest slug a skill id carries before its hash suffix.
const SLUG_CAP: usize = 40;

/// What one workaround-skills pass read and filed.
#[derive(Debug, Clone, Default)]
pub struct CoachWorkaroundSkillsReport {
    /// Standing captures read.
    pub captures: usize,
    /// Standing captures that failed the capture binding and were not read.
    pub unread: usize,
    /// Distinct (place, app, failure, repair) groups among the linked runs.
    pub groups: usize,
    /// Groups at or past [`WORKAROUND_MIN_RUNS`] distinct app runs.
    pub nominations: usize,
    /// Skills landed.
    pub skills_created: usize,
    /// Nominations whose bytes an existing skill already holds.
    pub skills_dup: usize,
    /// Nominations whose skill id another skill holds.
    pub collisions: usize,
    /// Findings written (a finding with the same content lands once).
    pub findings: usize,
    /// Nominations whose cited capture changed before the write.
    pub withheld: usize,
    /// Nominations whose write rolled back, and why.
    pub errors: Vec<String>,
}

/// One linked app run's exact anchor in its capture: the app's own ids and
/// the event ordinals of the failure, the repair and the outcome.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct RunAnchor {
    thread_id: String,
    run_id: String,
    tool_call_id: Option<String>,
    repair: String,
    capture: String,
    source_hash: String,
    failure_ordinal: usize,
    repair_ordinal: usize,
    outcome_ordinal: usize,
}

/// The failure half of a group key: where the capture stands, the app and
/// the failure's registered name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FailureKey {
    place: [u8; 32],
    project: EntityId,
    app_id: String,
    failure: String,
}

/// One failure's linked runs, by repair name and app run, plus the body of
/// the first capture that named it, for where its finding stands.
struct FailureRuns {
    body: ClaimBody,
    repairs: BTreeMap<String, BTreeMap<(String, String), RunAnchor>>,
    hashes: BTreeMap<EntityId, String>,
}

/// One group past the threshold: what its write files.
struct Nomination {
    key: FailureKey,
    repair: String,
    body: ClaimBody,
    supporting: Vec<RunAnchor>,
    counterexamples: Vec<RunAnchor>,
    captures: Vec<(EntityId, String)>,
}

/// How one nomination's write ended.
enum CommitOutcome {
    Withheld,
    Created,
    Dup,
    Collision,
}

impl Vault {
    /// One workaround-skills pass under the leased `coach.skill_distill`
    /// attempt: every standing AG-UI capture's linked repairs, grouped by
    /// place, app, failure and repair, and each group with linked runs in at
    /// least [`WORKAROUND_MIN_RUNS`] distinct app runs landed in one write.
    /// A write that fails rolls back and is reported; the pass goes on.
    ///
    /// # Errors
    ///
    /// A lease that is not this facet's Coach attempt, and storage errors
    /// reading the captures.
    pub fn run_coach_workaround_skills(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<CoachWorkaroundSkillsReport> {
        self.require_coach_attempt(attempt, COACH_SKILL_DISTILL_FACET)?;
        let envelope = proposals::run_tray_envelope(
            self,
            COACH_SKILL_DISTILL_FACET,
            attempt.status.attempt.id,
        )?;
        let coach = self.coach_authority()?.entity_ref();
        let (captures, unread) = {
            let rtxn = self.store.env.read_txn()?;
            standing_ag_ui_captures_in_txn(self, &rtxn)?
        };
        let mut report = CoachWorkaroundSkillsReport {
            captures: captures.len(),
            unread,
            ..CoachWorkaroundSkillsReport::default()
        };
        let failures = failure_runs(&captures)?;
        report.groups = failures.values().map(|runs| runs.repairs.len()).sum();
        for nomination in nominations(failures) {
            report.nominations += 1;
            match self.commit_workaround(&nomination, coach, &envelope, now) {
                Ok(CommitOutcome::Withheld) => report.withheld += 1,
                Ok(CommitOutcome::Created) => {
                    report.skills_created += 1;
                    report.findings += 1;
                }
                Ok(CommitOutcome::Dup) => {
                    report.skills_dup += 1;
                    report.findings += 1;
                }
                Ok(CommitOutcome::Collision) => {
                    report.collisions += 1;
                    report.findings += 1;
                }
                Err(error) => report.errors.push(format!(
                    "workaround {} / {}: {error}",
                    nomination.key.failure, nomination.repair
                )),
            }
        }
        Ok(report)
    }

    /// One nomination's transaction: every cited capture must still stand
    /// at the fingerprint the pass read, then the content-hash duplicate,
    /// the skill-id collision, or the landing.
    fn commit_workaround(
        &self,
        nomination: &Nomination,
        coach: EntityId,
        envelope: &WriteEnvelope,
        now: u64,
    ) -> Result<CommitOutcome> {
        let skill_id = skill_id_for(nomination);
        let files = render_files(&skill_id, nomination)?;
        let content_hash = canonical_skill_tree_hash(
            files
                .iter()
                .map(|file| (file.path.as_str(), file.content.as_slice())),
        )?;
        let finding = FindingWrite {
            nomination,
            skill_id: &skill_id,
            sources: nomination.captures.iter().map(|(id, _)| *id).collect(),
            place: place_of(&nomination.body),
            coach,
            envelope,
            now,
        };
        self.with_write_txn_grouped(|txn| {
            for (capture, hash) in &nomination.captures {
                if !ag_ui_capture_holds_in_txn(self, txn, capture, hash)? {
                    return Ok(CommitOutcome::Withheld);
                }
            }
            if let Some(existing) = self.skill_entity_for_content_hash_in_txn(txn, content_hash)? {
                finding.emit_in_txn(self, txn, "workaround_skill", existing)?;
                return Ok(CommitOutcome::Dup);
            }
            if let Some((holder, _)) = skill_holders_in_txn(self, txn, &skill_id)?.first() {
                finding.emit_in_txn(self, txn, "id_collision", *holder)?;
                return Ok(CommitOutcome::Collision);
            }
            let id = self.store.clock.entity_id()?;
            let record = skill_record(&skill_id, nomination, content_hash);
            let package = package_from_source(&record, files.clone(), SkillPackageFormat::Native)?;
            self.put_skill_record_in_txn(
                txn,
                &id,
                &record,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            self.persist_hub_package_in_txn(txn, &id, &package)?;
            finding.emit_in_txn(self, txn, "workaround_skill", id)?;
            Ok(CommitOutcome::Created)
        })
    }
}

/// One nomination's finding: what it cites, where it stands and who files it.
struct FindingWrite<'a> {
    nomination: &'a Nomination,
    skill_id: &'a str,
    sources: Vec<EntityId>,
    place: FindingPlace,
    coach: EntityId,
    envelope: &'a WriteEnvelope,
    now: u64,
}

impl FindingWrite<'_> {
    /// Files the finding naming `skill` (the landing, the duplicate's holder
    /// or the colliding holder) under `kind`, citing it and every capture.
    fn emit_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        kind: &str,
        skill: EntityId,
    ) -> Result<EntityId> {
        let value = finding_value(self.nomination, self.skill_id, kind, &skill.to_hex());
        let mut cites = Vec::with_capacity(self.sources.len() + 1);
        cites.push(skill);
        cites.extend(self.sources.iter().copied());
        proposals::emit_scoped_in_txn(
            vault,
            txn,
            self.coach,
            COACH_WORKAROUND_SKILLS_PREDICATE,
            &value,
            &cites,
            &self.place,
            self.envelope,
            self.now,
        )
    }
}

/// Every linked repair of `captures`, grouped by failure and then by repair
/// and app run. Captures come in claim id order and links in event order, so
/// the first anchor of an app run is kept, deterministically.
fn failure_runs(captures: &[StoredAgUiCapture]) -> Result<BTreeMap<FailureKey, FailureRuns>> {
    let mut failures: BTreeMap<FailureKey, FailureRuns> = BTreeMap::new();
    for capture in captures {
        let place = place_digest(&capture.body)?;
        let by_ordinal: BTreeMap<usize, &AgUiAppObservation> = capture
            .observations
            .iter()
            .map(|observation| (observation.ordinal, observation))
            .collect();
        for link in &capture.repair_links {
            if link.status != AgUiRepairLinkStatus::Linked {
                continue;
            }
            let (Some(repair_ordinal), Some(failure_ordinal)) =
                (link.repair_ordinal, link.failure_ordinal)
            else {
                continue;
            };
            let (Some(outcome), Some(repair), Some(failure)) = (
                by_ordinal.get(&link.outcome_ordinal),
                by_ordinal.get(&repair_ordinal),
                by_ordinal.get(&failure_ordinal),
            ) else {
                continue;
            };
            let (Some(thread_id), Some(run_id)) = (&outcome.thread_id, &outcome.run_id) else {
                continue;
            };
            let key = FailureKey {
                place,
                project: capture.project,
                app_id: capture.app_id.clone(),
                failure: failure.name.clone(),
            };
            let runs = failures.entry(key).or_insert_with(|| FailureRuns {
                body: capture.body.clone(),
                repairs: BTreeMap::new(),
                hashes: BTreeMap::new(),
            });
            runs.hashes
                .insert(capture.claim, capture.source_hash.clone());
            runs.repairs
                .entry(repair.name.clone())
                .or_default()
                .entry((thread_id.clone(), run_id.clone()))
                .or_insert_with(|| RunAnchor {
                    thread_id: thread_id.clone(),
                    run_id: run_id.clone(),
                    tool_call_id: outcome.tool_call_id.clone(),
                    repair: repair.name.clone(),
                    capture: capture.claim.to_hex(),
                    source_hash: capture.source_hash.clone(),
                    failure_ordinal,
                    repair_ordinal,
                    outcome_ordinal: link.outcome_ordinal,
                });
        }
    }
    Ok(failures)
}

/// Each (failure, repair) group with linked runs in at least
/// [`WORKAROUND_MIN_RUNS`] distinct app runs, with its counterexamples: the
/// same failure's linked runs that took another repair and are not among
/// the group's own runs.
fn nominations(failures: BTreeMap<FailureKey, FailureRuns>) -> Vec<Nomination> {
    let mut out = Vec::new();
    for (key, runs) in failures {
        for (repair, supporting) in &runs.repairs {
            if supporting.len() < WORKAROUND_MIN_RUNS {
                continue;
            }
            let counterexamples: Vec<RunAnchor> = runs
                .repairs
                .iter()
                .filter(|(other, _)| *other != repair)
                .flat_map(|(_, anchors)| anchors.iter())
                .filter(|(run, _)| !supporting.contains_key(*run))
                .map(|(_, anchor)| anchor.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let supporting: Vec<RunAnchor> = supporting.values().cloned().collect();
            let cited: BTreeSet<&str> = supporting
                .iter()
                .chain(&counterexamples)
                .map(|anchor| anchor.capture.as_str())
                .collect();
            let captures = runs
                .hashes
                .iter()
                .filter(|(id, _)| cited.contains(id.to_hex().as_str()))
                .map(|(id, hash)| (*id, hash.clone()))
                .collect();
            out.push(Nomination {
                key: key.clone(),
                repair: repair.clone(),
                body: runs.body.clone(),
                supporting,
                counterexamples,
                captures,
            });
        }
    }
    out
}

/// A digest of where a capture stands: its facet and project stamps, its
/// world, its relationships and its claim scope. Captures that stand apart
/// never share a finding.
fn place_digest(body: &ClaimBody) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PLACE_DOMAIN);
    hasher.update(body.scope_facet.as_bytes());
    hasher.update(body.scope_project.as_bytes());
    match body.world {
        Some(world) => {
            hasher.update(&[1]);
            hasher.update(world.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match &body.rel {
        Some(set) => {
            hasher.update(&[1]);
            hasher.update(&u64::try_from(set.len()).unwrap_or(u64::MAX).to_be_bytes());
            for id in set {
                hasher.update(id.as_bytes());
            }
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match &body.scope {
        Some(scope) => {
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, scope)
                .map_err(|_| Error::InvariantViolation("workaround place encode failed"))?;
            hasher.update(&[1]);
            hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(&bytes);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Where a nomination's finding stands: where its first capture does, so a
/// member who does not read the capture does not read the finding.
fn place_of(body: &ClaimBody) -> FindingPlace {
    FindingPlace {
        scope: body.scope.clone(),
        world: body.world,
        relationships: body.rel.clone(),
        stamps: Some((body.scope_facet, body.scope_project)),
    }
}

/// The skill id: [`WORKAROUND_SKILL_ID_PREFIX`], a slug, then 12 hex of a
/// hash over the three names, so two groups whose slugs agree still differ.
fn skill_id_for(nomination: &Nomination) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SKILL_ID_DOMAIN);
    for name in [
        nomination.key.app_id.as_str(),
        nomination.key.failure.as_str(),
        nomination.repair.as_str(),
    ] {
        hasher.update(&u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(name.as_bytes());
    }
    let hex = bytes_to_hex_lower(hasher.finalize().as_bytes());
    let slug = slug_of(&format!(
        "{} {} {}",
        nomination.key.app_id, nomination.key.failure, nomination.repair
    ));
    format!("{WORKAROUND_SKILL_ID_PREFIX}{slug}-{}", &hex[..12])
}

/// Lower case ASCII letters and digits, other runs as one `-`, capped at
/// [`SLUG_CAP`]. Never empty.
fn slug_of(text: &str) -> String {
    let mut slug = String::with_capacity(text.len().min(SLUG_CAP));
    let mut dash = true;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash {
            slug.push('-');
            dash = true;
        }
    }
    slug.truncate(SLUG_CAP);
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        slug.push_str("app");
    }
    slug
}

/// A name as a skill file shows it: control characters and backticks folded
/// to `-`, so one hostile name cannot add lines or break out of its code
/// span, and cut at `cap` bytes on a char boundary.
fn display_name(name: &str, cap: usize) -> String {
    let mut end = name.len().min(cap);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end]
        .chars()
        .map(|c| if c.is_control() || c == '`' { '-' } else { c })
        .collect()
}

/// The record and frontmatter description.
fn description_for(nomination: &Nomination) -> String {
    format!(
        "Workaround in {}: after the failure {}, people applied the repair {}.",
        display_name(&nomination.key.app_id, DESCRIPTION_NAME_CAP),
        display_name(&nomination.key.failure, DESCRIPTION_NAME_CAP),
        display_name(&nomination.repair, DESCRIPTION_NAME_CAP),
    )
}

/// Frontmatter quoting for one scalar: JSON string syntax, which the
/// folder's scalar reader takes.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"workaround skill\"".to_owned())
}

/// The candidate folder: `SKILL.md` (frontmatter and the trigger) and
/// `workaround.json` (the three names). Only the registered names render;
/// no imported payload, id or count does, so the bytes are a function of
/// the names alone.
fn render_files(skill_id: &str, nomination: &Nomination) -> Result<Vec<HubFile>> {
    let app = display_name(&nomination.key.app_id, BODY_NAME_CAP);
    let failure = display_name(&nomination.key.failure, BODY_NAME_CAP);
    let repair = display_name(&nomination.repair, BODY_NAME_CAP);
    let mut md = String::new();
    md.push_str("---\n");
    md.push_str(&format!("name: {skill_id}\n"));
    md.push_str(&format!(
        "description: {}\n",
        quoted(&description_for(nomination))
    ));
    md.push_str(&format!("version: {WORKAROUND_SKILL_VERSION}\n"));
    md.push_str("role: knowledge\n");
    md.push_str("---\n");
    md.push_str(&format!("# {skill_id}\n\n"));
    md.push_str("A person's repeated workaround in an outside app, distilled from the\n");
    md.push_str("owner's AG-UI captures. The names below are the app and the CUSTOM\n");
    md.push_str("event names the owner registered; this skill holds no text the app\n");
    md.push_str("sent. Repetition nominated it and does not prove it: the held-out\n");
    md.push_str("check decides.\n\n");
    md.push_str("## Trigger\n\n");
    md.push_str(&format!("App: {app}\n"));
    md.push_str(&format!(
        "When the app reports the failure `{failure}` after its agent's run.\n\n"
    ));
    md.push_str("## Workaround\n\n");
    md.push_str(&format!(
        "Apply the step the app reports as the repair `{repair}`: what people did\n"
    ));
    md.push_str("after that failure.\n");
    let mut json = serde_json::to_string_pretty(&serde_json::json!({
        "app": nomination.key.app_id,
        "failure": nomination.key.failure,
        "repair": nomination.repair,
    }))
    .map_err(|_| Error::InvariantViolation("workaround.json encode failed"))?;
    json.push('\n');
    Ok(vec![
        HubFile::new("SKILL.md", md.into_bytes()),
        HubFile::new("workaround.json", json.into_bytes()),
    ])
}

/// The born-Proposed, Candidate record a landing files: Generated on the
/// Dreamer-distill road, knowledge role, no dependencies, no parent.
fn skill_record(
    skill_id: &str,
    nomination: &Nomination,
    content_hash: crate::skill::SkillContentHash,
) -> SkillRecord {
    let provenance = vec![
        (Value::from("birth"), Value::from("dreamer_distill")),
        (Value::from("kind"), Value::from("workaround")),
        (
            Value::from("app"),
            Value::from(display_name(&nomination.key.app_id, DESCRIPTION_NAME_CAP)),
        ),
        (
            Value::from("failure"),
            Value::from(display_name(&nomination.key.failure, DESCRIPTION_NAME_CAP)),
        ),
        (
            Value::from("repair"),
            Value::from(display_name(&nomination.repair, DESCRIPTION_NAME_CAP)),
        ),
    ];
    SkillRecord::new(
        skill_id.to_owned(),
        description_for(nomination),
        WORKAROUND_SKILL_VERSION,
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::Generated).mean(),
        true,
        false,
        Vec::new(),
        Value::Map(provenance),
    )
    .with_content_hash(content_hash)
    .with_role(SkillRole::Knowledge, None)
}

/// The finding's stable value: no time or attempt, so the same evidence
/// files nothing new. `kind` is `workaround_skill` (a landing or a
/// duplicate) or `id_collision` (`skill` is then the holder).
fn finding_value(
    nomination: &Nomination,
    skill_id: &str,
    kind: &str,
    skill: &str,
) -> serde_json::Value {
    serde_json::json!({
        "version": WORKAROUND_DISTILL_VERSION,
        "kind": kind,
        "project": nomination.key.project.to_hex(),
        "app": nomination.key.app_id,
        "failure": nomination.key.failure,
        "repair": nomination.repair,
        "skill_id": skill_id,
        "skill": skill,
        "min_runs": WORKAROUND_MIN_RUNS,
        "supporting_runs": nomination.supporting,
        "counterexamples": nomination.counterexamples,
        "captures": nomination
            .captures
            .iter()
            .map(|(id, _)| id.to_hex())
            .collect::<Vec<_>>(),
    })
}
