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
//! A revision whose evidence ASSET the owner erased is not triaged: its job
//! files nothing, and the next sweep settles it erased (FIX 7551).
//!
//! A revision whose whole request the Coach's window cannot take is triaged
//! in parts (FIX 7549): its job cuts the item into spans that each fit (the
//! `parts` child), each answered by its own part child, then joins the
//! answers in ordered batches that fit, level after level, on synthesis
//! children (the `synthesis` child). The job parks on its children, which
//! wake it as each level completes. Every child loads exactly the skill arm
//! the job pinned, and the job alone files the final answer. Nothing is cut
//! away, and every answer is kept.
use oneiron::attempt_queue::AttemptRecord;
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerRunnerStore};
use oneiron::feedback::{
    COACH_FEEDBACK_TRIAGE_FACET, COACH_FEEDBACK_TRIAGE_PARK_OWNER, FeedbackInboxNote,
    FeedbackTriageInput, FeedbackTriageItem, FeedbackTriageJob, FeedbackTriageNodeInput,
    FeedbackTriageNodeJob, FeedbackTriageOutput, FeedbackTriagePin, FeedbackTriageSourceRef,
    FeedbackTriageSplit, FeedbackTriageStep, FeedbackTriageWork, GithubIssueRevision,
};
use oneiron::limit_ask::EngineLimit;
use oneiron::skill::LoadedSkillPack;
use oneiron::{EntityId, Error, LlmMessageRole, Vault};
use serde::Serialize;

use super::code_fix::{HostModels, message};
use crate::server::SyncServer;

mod github;
mod parts;
mod synthesis;

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

/// One leased revision job's run: the server, its attempt and its clock.
struct Run<'a> {
    server: &'a SyncServer,
    admitted: &'a DreamerAdmittedAttempt,
    now: u64,
}

/// One revision's triage on the bound skill. A revision too long for the
/// Coach's window is cut into parts, and its job parks on them; each later
/// run of the job takes its next step on that graph (FIX 7549).
pub(super) fn run_revision(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let mut input = match vault.feedback_triage_job(admitted)? {
        // A replayed job finds its result, and a job whose evidence the
        // owner erased, or that runs while no skill is bound, finds nothing
        // to triage: none calls or files.
        FeedbackTriageJob::Acknowledged(_)
        | FeedbackTriageJob::Erased
        | FeedbackTriageJob::Unbound => return Ok(()),
        FeedbackTriageJob::Pending(input) => input,
    };
    let attempt = &admitted.status.attempt;
    let models = HostModels::open(
        server,
        run_label(&EntityId::from_bytes(*attempt.id.as_bytes())?),
        PURPOSE,
        BUDGET_UNITS,
    )?;
    let executor = executor(server, &models)?;
    if let Some(work) = input.work.take() {
        let run = Run {
            server,
            admitted,
            now,
        };
        return resume(&run, &models, &executor, &input, work);
    }
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
    let instruction = instruction(&loaded)?;
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
    // Rule 5: the item goes to the model whole when the Coach's window takes
    // it, and its size is measured; one the window cannot take is cut into
    // parts that each fit, none of it left out (FIX 7549). It is the
    // source's data, never an instruction: it goes as the User.
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, data.len() as u64);
    if let Some(window) = parts::window(server, &models)
        && !parts::fits(window.input_tokens, &instruction, &data)
    {
        let run = Run {
            server,
            admitted,
            now,
        };
        return parts::begin(&run, &input, &loaded, &instruction, window);
    }
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

/// Whether this run of a revision's job parked it on its part children
/// (FIX 7549): the job's own park, written at `now`. The host then leaves
/// the job pending under its park and gives back only its unit.
pub(super) fn yielded(
    store: &DreamerRunnerStore<'_>,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<bool> {
    if admitted.status.payload.attempt_type != COACH_FEEDBACK_TRIAGE_FACET {
        return Ok(false);
    }
    Ok(store
        .parked_attempt(admitted.status.attempt.id)?
        .is_some_and(|park| {
            park.park_owner == COACH_FEEDBACK_TRIAGE_PARK_OWNER && park.parked_at >= now
        }))
}

/// One part child (FIX 7549): its span of a long revision's item, answered
/// on the arm the revision's job pinned.
pub(super) fn run_part(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    run_node(server, admitted, now, parts::node_data)
}

/// One synthesis child (FIX 7549): an ordered batch of a long revision's
/// answers, joined on the arm the revision's job pinned.
pub(super) fn run_synthesis(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    run_node(server, admitted, now, synthesis::node_data)
}

/// A part or synthesis child's run: the pinned arm's SKILL.md as the
/// instruction and the node's data as the User, on the Coach's seat, its
/// typed answer recorded on the node. A child whose arm no longer loads, or
/// whose window shrank under its node, answers nothing and hands the node
/// back to the revision's job.
fn run_node(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
    encode: fn(&FeedbackTriageNodeInput) -> oneiron::Result<String>,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let input = match vault.feedback_triage_node(admitted)? {
        FeedbackTriageNodeJob::Settled => return Ok(()),
        FeedbackTriageNodeJob::Pending(input) => input,
    };
    let attempt = &admitted.status.attempt;
    // Every child spends under its revision job's run: one logical spend.
    let models = HostModels::open(server, run_label(&input.parent), PURPOSE, BUDGET_UNITS)?;
    let executor = executor(server, &models)?;
    let Some(loaded) = pinned_load(vault, attempt, &executor, &input.pin.skill, &input.pin, now)?
    else {
        return vault.record_coach_feedback_triage_node(admitted, None, now);
    };
    let instruction = instruction(&loaded)?;
    let data = encode(&input)?;
    if let Some(window) = parts::window(server, &models)
        && window.input_tokens != input.pin.input_tokens
        && !parts::fits(window.input_tokens, &instruction, &data)
    {
        return vault.record_coach_feedback_triage_node(admitted, None, now);
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, data.len() as u64);
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
    vault.record_coach_feedback_triage_node(admitted, Some((&output, &served)), now)
}

/// The next step of a revision already cut (FIX 7549). From here its job is
/// never failed for a step: a step that errs parks the job on its graph,
/// and its last child or the next sweep wakes it again.
fn resume(
    run: &Run<'_>,
    models: &HostModels<'_>,
    executor: &str,
    input: &FeedbackTriageInput,
    work: FeedbackTriageWork,
) -> oneiron::Result<()> {
    let Err(error) = advance(run, models, executor, input, work) else {
        return Ok(());
    };
    tracing::warn!(kind = ?error.kind(), "a feedback triage in parts waits for its next wake");
    match run.server.vault().park_coach_feedback_triage(
        run.admitted,
        FeedbackTriageStep::Wait,
        run.now,
    ) {
        Ok(_) => Ok(()),
        Err(_) => Err(error),
    }
}

/// Plans the revision's next step on its graph and parks its job on it, or
/// files the final answer once one answer stands or no batch joins two.
fn advance(
    run: &Run<'_>,
    models: &HostModels<'_>,
    executor: &str,
    input: &FeedbackTriageInput,
    work: FeedbackTriageWork,
) -> oneiron::Result<()> {
    let vault = run.server.vault();
    let attempt = &run.admitted.status.attempt;
    let window =
        parts::window(run.server, models).unwrap_or_else(|| parts::Window::from_pin(&work.pin));
    let Some(loaded) = pinned_load(vault, attempt, executor, &input.skill, &work.pin, run.now)?
    else {
        // The pinned arm no longer loads, or the owner bound another skill:
        // a new generation, on the arm the load routes this job to now.
        let loaded = vault.load_attempt_skill_pack(
            attempt.id,
            &input.skill,
            attempt.lease_owner.as_deref().unwrap_or_default(),
            attempt.attempt_count,
            executor,
            run.now,
        )?;
        let instruction = instruction(&loaded)?;
        return parts::begin(run, input, &loaded, &instruction, window);
    };
    let instruction = instruction(&loaded)?;
    let step = if work.owed() {
        if window.input_tokens == work.pin.input_tokens {
            FeedbackTriageStep::Wait
        } else {
            repartition(input, &work, &instruction, window)?
        }
    } else {
        let level: Vec<_> = work.current().collect();
        let batches = synthesis::batches(input, &work, &level, &window, &instruction)?;
        if !batches.iter().any(|batch| batch.len() > 1) {
            let (output, served) = synthesis::assemble(&level);
            let result = vault.run_coach_feedback_triage(
                run.admitted,
                &output,
                (work.pin.entity, work.pin.version),
                &served,
                run.now,
            )?;
            tracing::debug!(
                findings = result.findings.len(),
                "the Coach triaged one long feedback item in parts"
            );
            return Ok(());
        }
        FeedbackTriageStep::Synthesis { batches }
    };
    vault
        .park_coach_feedback_triage(run.admitted, step, run.now)
        .map(drop)
}

/// The window changed under owed nodes: each unanswered node that no longer
/// fits whole is cut again, and the pin takes the new window.
fn repartition(
    input: &FeedbackTriageInput,
    work: &FeedbackTriageWork,
    instruction: &str,
    window: parts::Window,
) -> oneiron::Result<FeedbackTriageStep> {
    let item = input.item.text()?;
    let mut splits = Vec::new();
    for node in work.current().filter(|node| node.answer.is_none()) {
        let split = match node.span {
            Some(span) => {
                let spans = parts::split(input, &item, span, window.input_tokens, instruction)?;
                spans.map(|spans| FeedbackTriageSplit {
                    node: node.id,
                    spans,
                    batches: Vec::new(),
                })
            }
            None => {
                let batches = synthesis::split(input, work, node, &window, instruction)?;
                batches.map(|batches| FeedbackTriageSplit {
                    node: node.id,
                    spans: Vec::new(),
                    batches,
                })
            }
        };
        splits.extend(split);
    }
    Ok(FeedbackTriageStep::Repartition {
        pin: FeedbackTriagePin {
            model: window.model,
            input_tokens: window.input_tokens,
            ..work.pin.clone()
        },
        splits,
    })
}

/// The arm `pin` names, loaded exactly as pinned under `attempt`; `None`
/// once it no longer loads, or the owner bound another skill than `bound`.
fn pinned_load(
    vault: &Vault,
    attempt: &AttemptRecord,
    executor: &str,
    bound: &EntityId,
    pin: &FeedbackTriagePin,
    now: u64,
) -> oneiron::Result<Option<LoadedSkillPack>> {
    if pin.skill != *bound {
        return Ok(None);
    }
    match vault.load_attempt_pinned_skill_pack(
        attempt,
        bound,
        (&pin.entity, &pin.version),
        executor,
        now,
    ) {
        Ok(loaded) => Ok(Some(loaded)),
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The run every call of one revision spends under: its job's.
fn run_label(job: &EntityId) -> String {
    format!("coach-feedback-triage:{}", job.to_hex())
}

/// The model of the Coach's seat.
fn executor(server: &SyncServer, models: &HostModels<'_>) -> oneiron::Result<String> {
    server
        .ai
        .model_runtime()
        .seat(models.coach())
        .map(|seat| seat.model.as_str().to_owned())
        .ok_or_else(|| unavailable("no seat serves the Coach's feedback triage"))
}

/// The loaded skill's SKILL.md: the Coach's instruction.
fn instruction(loaded: &LoadedSkillPack) -> oneiron::Result<String> {
    loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .map(str::to_owned)
        .ok_or_else(|| unavailable("the bound feedback triage skill has no SKILL.md"))
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
