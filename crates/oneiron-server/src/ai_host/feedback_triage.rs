//! The Coach's feedback triage on the host (OF-420 T1; ARCH-0056: "We sweep
//! both on a schedule with the triage skill"). The sweep hands each new
//! open-inbox revision to its own job. Each job runs the SKILL the owner
//! bound: its SKILL.md is the Coach's instruction and the note, with its ids,
//! goes as data, on the Coach's seat. The typed answer is filed through
//! [`oneiron::Vault::run_coach_feedback_triage`], whose findings land
//! Proposed in the owner's run tray. No bound skill, no seat or answer, an
//! answer that does not parse, or a write the engine refuses fails the job:
//! the revision stays unacknowledged, and the next sweep queues it again.
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::feedback::{
    FeedbackInboxNote, FeedbackTriageJob, FeedbackTriageOutput, FeedbackTriageSourceRef,
};
use oneiron::limit_ask::EngineLimit;
use oneiron::{EntityId, Error, LlmMessageRole};
use serde::Serialize;

use super::code_fix::{HostModels, message};
use crate::server::SyncServer;

/// The call purpose the triage call is metered under.
const PURPOSE: &str = "coach_feedback_triage";
/// What one job's call may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// The skill's file the Coach runs; the note goes as data.
const SKILL_FILE: &str = "SKILL.md";

/// One feedback sweep: hands each new revision to its own job.
pub(super) fn run_sweep(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let sweep = server.vault().run_coach_feedback_sweep(admitted, now)?;
    tracing::debug!(
        handed_off = sweep.handed_off,
        known = sweep.known,
        requeued = sweep.requeued,
        "the Coach swept the feedback inbox"
    );
    Ok(())
}

/// The data the triage reads: the note whole, with the ids its findings
/// cite.
#[derive(Serialize)]
struct TriageData<'a> {
    source_ref: &'a FeedbackTriageSourceRef,
    evidence: &'a EntityId,
    note: &'a FeedbackInboxNote,
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
    let data = serde_json::to_string(&TriageData {
        source_ref: &input.source_ref,
        evidence: &input.evidence,
        note: &input.note,
    })
    .map_err(|_| unavailable("the feedback note could not be encoded"))?;
    // Rule 5: the note goes to the model whole; its size is measured. A note
    // the model's window cannot take fails the job and stays unacknowledged.
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, data.len() as u64);
    // The call reads the note's evidence and the skill it loaded (FIX 6997).
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
        "the Coach triaged one feedback note"
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
