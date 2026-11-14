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
//! `oneiron-bench beam action-bench <plan.json>`.

mod arms;
mod score;
mod tasks;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Instant,
};

use oneiron::{CallPurpose, ModelId};
use serde::{Deserialize, Serialize};

use self::{
    arms::{ArmContext, HistoryVault, MemoryArm},
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
    histories: Vec<HistoryRow>,
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
    turns_witnessed: usize,
    claims_written: usize,
    items_after_freeze: usize,
    ingest_elapsed_us: u64,
}

/// One follow-up under one arm.
#[derive(Debug, Serialize)]
pub(super) struct ActionRow {
    history: String,
    follow_up: String,
    kind: TaskKind,
    arm: MemoryArm,
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
        ..
    } = plan;
    let session = ModelSession::connect(host, std::slice::from_ref(&reader))?;
    let settings = RunSettings {
        reader: &reader,
        reader_prompt: &reader_prompt,
        arms: &arms,
        recall_limit,
    };
    run_with_session(&settings, &tasks, &session)
}

struct RunSettings<'a> {
    reader: &'a ModelPin,
    reader_prompt: &'a AnswerPromptPin,
    arms: &'a [MemoryArm],
    recall_limit: usize,
}

fn run_with_session(
    settings: &RunSettings<'_>,
    tasks: &TaskFile,
    session: &ModelSession,
) -> BeamResult<ActionBenchReport> {
    let mut histories = Vec::new();
    let mut rows = Vec::new();
    for history in &tasks.histories {
        let seeded = HistoryVault::seed(history)?;
        histories.push(HistoryRow {
            history: history.id.clone(),
            frozen_at: history.frozen_at,
            turns_witnessed: seeded.turns_witnessed,
            claims_written: seeded.claims_written,
            items_after_freeze: seeded.items_after_freeze,
            ingest_elapsed_us: seeded.ingest_elapsed_us,
        });
        for follow_up in tasks.follow_ups_of(&history.id) {
            let question = tasks::question(follow_up);
            for &arm in settings.arms {
                let context = arms::context(&seeded, arm, follow_up, settings.recall_limit)?;
                rows.push(act(settings, session, follow_up, &question, arm, context)?);
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
        histories,
        rows,
        summary,
        paired,
    })
}

/// One reader call and its score. The reader's input has no arm label,
/// rubric, gold field or task id: only the question and the arm's context.
fn act(
    settings: &RunSettings<'_>,
    session: &ModelSession,
    follow_up: &tasks::FollowUp,
    question: &str,
    arm: MemoryArm,
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
