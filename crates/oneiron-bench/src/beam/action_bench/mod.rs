//! The in-house action bench (ARCH-0042 #action-bench, owner ruling
//! 2026-10-21): does memory change what a reader later does, not only what it
//! recalls. It is a small screen that works for us, with no
//! publication-grade sizing.
//!
//! Each history is one synthetic user's past, frozen at a time; each held-out
//! follow-up asks the reader to act through one of the follow-up's tools. Every
//! memory arm hands the same pinned reader, through BEAM's measured host, the
//! same `{question, context}` input; only the context differs. A deterministic
//! scorer reads the reply against the follow-up's rubric, which never reaches
//! the reader. Uncertainty is paired by history against the no-memory arm.
//!
//! The extraction arms (`extraction.rs`) hold the derived memory's maker
//! apart instead: each reads claims its own vault's Dreamer extracted from
//! the raw turns, right after the correction and again at the freeze.
//!
//! `oneiron-bench beam action-bench <plan.json>`.

mod arms;
mod extraction;
mod score;
mod tasks;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Instant,
};

use oneiron::{CallPurpose, ModelId, ModelLocality};
use serde::{Deserialize, Serialize};

use self::{
    arms::{ArmContext, HistoryVault, MemoryArm},
    extraction::{
        EXTRACTION_ARMS_MAPPING, ExtractionHost, ExtractionPin, ExtractionRow, ExtractionVault,
        Probe,
    },
    score::{ArmSummary, FollowUpScore, PairedRow},
    tasks::{TaskFile, TaskKind},
};
use super::{
    BeamError, BeamResult,
    judge::AnswerPromptPin,
    llm_host::{HostConfig, ModelPin, ModelSession},
    report_model::CostComponentReport,
};

/// The report's schema; a change to a row's meaning bumps it.
const ACTION_BENCH_REPORT_VERSION: &str = "action-bench-report-v1";
/// The most memory items one recall may hand the reader.
const MAX_RECALL_LIMIT: usize = 200;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionBenchPlan {
    /// The tasks file, relative to the plan's folder unless absolute.
    tasks: PathBuf,
    host: HostConfig,
    reader: ModelPin,
    /// The reader's system prompt, pinned by the SHA-256 of its exact bytes.
    reader_prompt: AnswerPromptPin,
    /// The memory arms to run, `none` among them: it is the pairing baseline.
    arms: Vec<MemoryArm>,
    /// The most memory items one recall hands the reader.
    recall_limit: usize,
    /// The extraction model, on the reader's host; required when an
    /// extraction arm runs, and refused without one.
    #[serde(default)]
    extraction: Option<ExtractionPin>,
}

impl ActionBenchPlan {
    fn validate(&self) -> BeamResult<()> {
        let distinct: BTreeSet<_> = self.arms.iter().collect();
        if distinct.len() != self.arms.len() || !distinct.contains(&MemoryArm::None) {
            return Err(refusal(
                "the arms must be distinct and include `none`, the pairing baseline",
            ));
        }
        if !self
            .reader_prompt
            .matches_exact_text(&self.reader_prompt.content)
        {
            return Err(refusal(
                "reader_prompt.sha256 is not the SHA-256 of its content",
            ));
        }
        if !(1..=MAX_RECALL_LIMIT).contains(&self.recall_limit) {
            return Err(refusal("recall_limit must be 1 to 200"));
        }
        if self.arms.iter().any(|arm| arm.extracts()) != self.extraction.is_some() {
            return Err(refusal(
                "an extraction arm needs the extraction pin, and the pin needs an extraction arm",
            ));
        }
        Ok(())
    }
}

/// What one run measured, row by row and paired by history.
#[derive(Debug, Serialize)]
pub(super) struct ActionBenchReport {
    version: &'static str,
    tasks_version: u32,
    reader: ModelId,
    reader_prompt_sha256: String,
    recall_limit: usize,
    arms: Vec<MemoryArm>,
    /// The extraction model and the locality its vaults admit, when an
    /// extraction arm ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    extraction_model: Option<ModelId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extraction_locality: Option<ModelLocality>,
    /// What each extraction arm stands for (LightMem's online and sleep-time
    /// updates).
    #[serde(skip_serializing_if = "Option::is_none")]
    extraction_arms_mapping: Option<&'static str>,
    histories: Vec<HistoryRow>,
    /// One row per history and extraction arm.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    extraction: Vec<ExtractionRow>,
    rows: Vec<ActionRow>,
    summary: Vec<ArmSummary>,
    paired: Vec<PairedRow>,
}

/// One history's ingest stage: what entered its vault and what the freeze
/// kept out.
#[derive(Debug, Serialize)]
struct HistoryRow {
    history: String,
    frozen_at: u64,
    worlds_created: usize,
    turns_witnessed: usize,
    claims_written: usize,
    items_after_freeze: usize,
    /// Turns and claims the user deleted before the freeze.
    items_deleted: usize,
    ingest_elapsed_us: u64,
}

/// One follow-up under one arm.
#[derive(Debug, Serialize)]
pub(super) struct ActionRow {
    history: String,
    follow_up: String,
    kind: TaskKind,
    arm: MemoryArm,
    /// When an extraction arm read its vault; none for a memory arm.
    #[serde(skip_serializing_if = "Option::is_none")]
    probe: Option<Probe>,
    /// The reader's whole user input is `{question, context}`.
    question: String,
    context: String,
    context_lines: usize,
    /// Recall items of a kind this arm does not read, dropped before the reader.
    items_off_arm: usize,
    recall_elapsed_us: u64,
    reply: String,
    reply_truncated: bool,
    reader: CostComponentReport,
    score: FollowUpScore,
    score_elapsed_us: u64,
}

pub(super) fn run(path: &Path) -> BeamResult<ActionBenchReport> {
    let plan: ActionBenchPlan = serde_json::from_slice(&std::fs::read(path)?)?;
    plan.validate()?;
    let tasks_path = if plan.tasks.is_relative() {
        path.parent().unwrap_or(Path::new(".")).join(&plan.tasks)
    } else {
        plan.tasks.clone()
    };
    let tasks = tasks::load(&tasks_path)?;
    let ActionBenchPlan {
        host,
        reader,
        reader_prompt,
        arms,
        recall_limit,
        extraction,
        ..
    } = plan;
    let extraction = extraction
        .as_ref()
        .map(|pin| ExtractionHost::connect(&host, pin))
        .transpose()?;
    let session = ModelSession::connect(host, std::slice::from_ref(&reader))?;
    let settings = RunSettings {
        reader: &reader,
        reader_prompt: &reader_prompt,
        arms: &arms,
        recall_limit,
        extraction: extraction.as_ref(),
    };
    run_with_session(&settings, &tasks, &session)
}

struct RunSettings<'a> {
    reader: &'a ModelPin,
    reader_prompt: &'a AnswerPromptPin,
    arms: &'a [MemoryArm],
    recall_limit: usize,
    extraction: Option<&'a ExtractionHost>,
}

fn run_with_session(
    settings: &RunSettings<'_>,
    tasks: &TaskFile,
    session: &ModelSession,
) -> BeamResult<ActionBenchReport> {
    let mut histories = Vec::new();
    let mut rows = Vec::new();
    let mut extraction = Vec::new();
    // Every history's correction point, before any vault opens: an
    // extraction arm needs one, and a history without one fails the trace
    // check's world part.
    let corrections = match settings.extraction {
        Some(_) => tasks
            .histories
            .iter()
            .map(tasks::correction_point)
            .collect::<BeamResult<Vec<_>>>()?,
        None => Vec::new(),
    };
    for (place, history) in tasks.histories.iter().enumerate() {
        let seeded = HistoryVault::seed(history)?;
        histories.push(HistoryRow {
            history: history.id.clone(),
            frozen_at: history.frozen_at,
            worlds_created: seeded.worlds_created(),
            turns_witnessed: seeded.turns_witnessed,
            claims_written: seeded.claims_written,
            items_after_freeze: seeded.items_after_freeze,
            items_deleted: seeded.items_deleted,
            ingest_elapsed_us: seeded.ingest_elapsed_us,
        });
        for follow_up in tasks.follow_ups_of(&history.id) {
            let question = tasks::question(follow_up);
            for &arm in settings.arms.iter().filter(|arm| !arm.extracts()) {
                let context = arms::context(&seeded.view(), arm, follow_up, settings.recall_limit)?;
                rows.push(act(
                    settings, session, follow_up, &question, arm, None, context,
                )?);
            }
        }
        if let (Some(host), Some(&correction_at)) = (settings.extraction, corrections.get(place)) {
            for &arm in settings.arms.iter().filter(|arm| arm.extracts()) {
                let row = extract(
                    settings,
                    session,
                    tasks,
                    history,
                    arm,
                    correction_at,
                    host,
                    &mut rows,
                )?;
                extraction.push(row);
            }
        }
    }
    let summary = score::summarize(&rows, settings.arms)?;
    let paired = score::paired_by_history(&rows, settings.arms);
    Ok(ActionBenchReport {
        version: ACTION_BENCH_REPORT_VERSION,
        tasks_version: tasks.version,
        reader: settings.reader.model_id.clone(),
        reader_prompt_sha256: settings.reader_prompt.sha256.clone(),
        recall_limit: settings.recall_limit,
        arms: settings.arms.to_vec(),
        extraction_model: settings.extraction.map(|host| host.model().clone()),
        extraction_locality: settings.extraction.map(ExtractionHost::locality),
        extraction_arms_mapping: settings.extraction.map(|_| EXTRACTION_ARMS_MAPPING),
        histories,
        extraction,
        rows,
        summary,
        paired,
    })
}

/// One history under one extraction arm: a fresh vault replays the turns
/// through the correction, the reader acts on each corrected-source
/// follow-up, the replay runs on to the freeze with every lane drained, and
/// the reader acts on every follow-up.
#[allow(
    clippy::too_many_arguments,
    reason = "one call site; the run's parts and one history's"
)]
fn extract(
    settings: &RunSettings<'_>,
    session: &ModelSession,
    tasks: &TaskFile,
    history: &tasks::History,
    arm: MemoryArm,
    correction_at: u64,
    host: &ExtractionHost,
    rows: &mut Vec<ActionRow>,
) -> BeamResult<ExtractionRow> {
    let mut vault = ExtractionVault::open(history, arm, host)?;
    vault.replay_through_correction(correction_at, host)?;
    for follow_up in tasks
        .follow_ups_of(&history.id)
        .filter(|follow_up| follow_up.kind == TaskKind::CorrectedSource)
    {
        let question = tasks::question(follow_up);
        let context = arms::context(&vault.view(), arm, follow_up, settings.recall_limit)?;
        rows.push(act(
            settings,
            session,
            follow_up,
            &question,
            arm,
            Some(Probe::AfterCorrection),
            context,
        )?);
    }
    vault.replay_to_freeze(host)?;
    for follow_up in tasks.follow_ups_of(&history.id) {
        let question = tasks::question(follow_up);
        let context = arms::context(&vault.view(), arm, follow_up, settings.recall_limit)?;
        rows.push(act(
            settings,
            session,
            follow_up,
            &question,
            arm,
            Some(Probe::AfterConsolidation),
            context,
        )?);
    }
    vault.row(host, &session.prices)
}

/// One reader call and its score. The reader's input has no arm label,
/// rubric, gold field or task id: only the question and the arm's context.
fn act(
    settings: &RunSettings<'_>,
    session: &ModelSession,
    follow_up: &tasks::FollowUp,
    question: &str,
    arm: MemoryArm,
    probe: Option<Probe>,
    context: ArmContext,
) -> BeamResult<ActionRow> {
    let input = serde_json::to_string(&serde_json::json!({
        "question": question,
        "context": context.text,
    }))?;
    let (reply, reader, reply_truncated) = session.invoke_capped(
        settings.reader,
        CallPurpose::AnswerGen,
        &settings.reader_prompt.content,
        &input,
    )?;
    let started = Instant::now();
    let score = score::score(follow_up, &reply);
    let score_elapsed_us = elapsed_us(started);
    Ok(ActionRow {
        history: follow_up.history.clone(),
        follow_up: follow_up.id.clone(),
        kind: follow_up.kind,
        arm,
        probe,
        question: question.to_owned(),
        context_lines: context.lines,
        context: context.text,
        items_off_arm: context.items_off_arm,
        recall_elapsed_us: context.recall_elapsed_us,
        reply,
        reply_truncated,
        reader,
        score,
        score_elapsed_us,
    })
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn refusal(reason: &str) -> BeamError {
    BeamError::Comparability {
        reason: format!("action bench: {reason}"),
    }
}
