//! The Coach's feedback triage on the host (OF-420 T1; ARCH-0056: "GitHub
//! issues still work. We sweep both on a schedule with the triage skill").
//! The sweep rides the Coach's nightly wake, or the owner's run-now, and
//! hands each new revision of the open inbox and of each bound GitHub
//! repository (the `github` child) to its own job. Each job runs the SKILL
//! the owner bound: its SKILL.md is the Coach's instruction and the item,
//! with its ids, goes as data, on the Coach's seat. The typed answer is filed
//! through [`oneiron::Vault::run_coach_feedback_triage`], whose findings land
//! Proposed in the owner's run tray. No bound skill, no seat or answer, an
//! answer that does not parse, or a write the engine refuses fails the job:
//! the revision stays unacknowledged, and the next sweep queues it again.
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::feedback::{
    FeedbackInboxNote, FeedbackTriageItem, FeedbackTriageJob, FeedbackTriageOutput,
    FeedbackTriageSourceRef, GithubIssueRevision,
};
use oneiron::limit_ask::EngineLimit;
use oneiron::{EntityId, Error, LlmMessageRole};
use serde::Serialize;

use super::code_fix::{HostModels, message};
use crate::server::SyncServer;

mod github;

/// The call purpose the triage call is metered under.
const PURPOSE: &str = "coach_feedback_triage";
/// What one job's call may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// The skill's file the Coach runs; the note goes as data.
const SKILL_FILE: &str = "SKILL.md";

/// One feedback sweep: the open inbox, then each bound GitHub repository,
/// each walked on its own, so a source that fails holds no other back. Each
/// new revision goes to its own job. What a repository answers in place of
/// a page stays on its row and fails nothing; the sweep fails with the first
/// engine error once every source has run. With no skill bound it
/// completes doing nothing: no source is read, and nothing is retained,
/// queued or written.
pub(super) fn run_sweep(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let mut failed = match server.vault().run_coach_feedback_sweep(admitted, now) {
        Ok(sweep) => {
            tracing::debug!(
                handed_off = sweep.handed_off,
                known = sweep.known,
                requeued = sweep.requeued,
                "the Coach swept the feedback inbox"
            );
            None
        }
        Err(error) => Some(error),
    };
    let sources = github::GithubIssueSource::bound(server);
    if !sources.is_empty() {
        match github::client() {
            Ok(client) => {
                // Every source is walked, whichever fails.
                for source in &sources {
                    if let Err(error) = github::sweep(server, &client, admitted, source) {
                        failed = failed.or(Some(error));
                    }
                }
            }
            Err(error) => failed = failed.or(Some(error)),
        }
    }
    failed.map_or(Ok(()), Err)
}

/// The data the triage reads: the item whole, with the ids its findings
/// cite. An inbox note goes as `note`, a GitHub item as `issue`.
#[derive(Serialize)]
struct TriageData<'a> {
    source_ref: &'a FeedbackTriageSourceRef,
    evidence: &'a EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a FeedbackInboxNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issue: Option<&'a GithubIssueRevision>,
}

/// One revision's triage on the bound skill.
pub(super) fn run_revision(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let input = match vault.feedback_triage_job(admitted)? {
        // A replayed job finds its result and files nothing.
        FeedbackTriageJob::Acknowledged(_) => return Ok(()),
        FeedbackTriageJob::Pending(input) => input,
    };
    let attempt = &admitted.status.attempt;
    let models = HostModels::open(
        server,
        format!(
            "coach-feedback-triage:{}",
            EntityId::from_bytes(*attempt.id.as_bytes())?.to_hex()
        ),
        PURPOSE,
        BUDGET_UNITS,
    )?;
    let executor = server
        .ai
        .model_runtime()
        .seat(models.coach())
        .map(|seat| seat.model.as_str().to_owned())
        .ok_or_else(|| unavailable("no seat serves the Coach's feedback triage"))?;
    // The load stamps the skill's revision and the Coach's model on the
    // attempt; a retired, unapproved or deleted skill fails the job.
    let loaded = vault.load_attempt_skill_pack(
        attempt.id,
        &input.skill,
        attempt.lease_owner.as_deref().unwrap_or_default(),
        attempt.attempt_count,
        &executor,
        now,
    )?;
    let instruction = loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .map(str::to_owned)
        .ok_or_else(|| unavailable("the bound feedback triage skill has no SKILL.md"))?;
    let (note, issue) = match &input.item {
        FeedbackTriageItem::Inbox(note) => (Some(note.as_ref()), None),
        FeedbackTriageItem::Github(issue) => (None, Some(issue.as_ref())),
    };
    let data = serde_json::to_string(&TriageData {
        source_ref: &input.source_ref,
        evidence: &input.evidence,
        note,
        issue,
    })
    .map_err(|_| unavailable("the feedback item could not be encoded"))?;
    // Rule 5: the item goes to the model whole; its size is measured. An item
    // the model's window cannot take fails the job and stays unacknowledged.
    // It is the source's data, never an instruction: it goes as the User.
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, data.len() as u64);
    // The call reads the item's evidence and the skill it loaded (FIX 6997).
    let (text, served) = models
        .generate_served_sourced(
            models.coach(),
            vec![
                message(LlmMessageRole::System, instruction),
                message(LlmMessageRole::User, data),
            ],
            Some(vec![input.evidence, loaded.entity]),
        )?
        .ok_or_else(|| unavailable("no seat took the Coach's feedback triage"))?;
    let output = parse_output(&text)
        .ok_or_else(|| unavailable("the Coach's feedback triage answer holds no findings"))?;
    let result = vault.run_coach_feedback_triage(
        admitted,
        &output,
        (loaded.entity, loaded.record.version),
        &served,
        now,
    )?;
    tracing::debug!(
        findings = result.findings.len(),
        "the Coach triaged one feedback item"
    );
    Ok(())
}

fn unavailable(what: &str) -> Error {
    Error::InvalidConfig(what.to_owned())
}

/// The one JSON object in the answer, typed; `None` when there is none or
/// it is not a triage answer.
fn parse_output(text: &str) -> Option<FeedbackTriageOutput> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str(text.get(start..=end)?).ok()
}
