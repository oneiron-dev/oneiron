//! The host's notes beside decided answers (FIX 3040, 654): a critic review's
//! evidence refs and suggested edits, a seat pick's why and an auto check's
//! hold reasons, written by the host's notes model, the big model
//! `[models.decisions.big]` binds. With none bound, or when its call fails or
//! writes nothing usable, the note is the template the decision itself gives
//! ([`LadderNotes`]). The answer is decided before its note is asked, and a
//! note never changes it. A note call runs only when its whole budget fits in
//! the time the decision left, so it never holds a decision past its clock.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::critic::review::{ReviewFinding, ReviewNote, ReviewNotes};
use oneiron::llm::decision::cut_text;
use serde_json::{Value, json};

use super::{
    AutoCheckCandidate, AutoCheckNotes, LadderNotes, ModelId, ReasoningEffort, RetrievalDeadline,
    SeatCandidate, SeatNotes, SeatTask,
};
use crate::big_rung::BigModel;

/// The longest one note call takes. A decision with less time left keeps its
/// template note.
const NOTE_BUDGET: Duration = Duration::from_secs(3);
/// The most bytes of a task's text a seat note's call reads.
const NOTE_TASK_BYTES: usize = 2048;
/// The engine's bounds on a critique's notes (critic.rs): evidence refs, the
/// bytes of one ref, and the bytes of a suggested edit. A generated note past
/// them is cut to fit, so a note never fails its review.
const REVIEW_EVIDENCE_REFS: usize = 64;
const REVIEW_EVIDENCE_REF_BYTES: usize = 256;
const REVIEW_SUGGESTED_EDIT_BYTES: usize = 8192;

const REVIEW_NOTE_SYSTEM: &str = "You write notes beside a critic review's findings. Each \
finding is already decided, and your notes cannot change it. For each finding, name the \
evidence refs that support it, and when a change would address it, one suggested edit. Reply \
with one JSON array and nothing else: [{\"finding\": <its index>, \"evidence_refs\": [<ref>], \
\"suggested_edit\": <text or null>}].";

const SEAT_NOTE_SYSTEM: &str = "In one or two plain sentences, say why the host's decision \
ladder picked this model at this effort for the task, from the candidates it had. The pick is \
already made. Reply with the explanation only.";

const HOLD_NOTE_SYSTEM: &str = "The host's auto check held this write for a reviewer. From the \
candidate's fields, give the reasons the reviewer needs, one plain sentence per line. The hold \
is already decided. Reply with the reasons only.";

/// The host's notes: its notes model when one is bound, else the template.
#[derive(Clone, Default)]
pub(crate) struct HostNotes {
    model: Option<Arc<BigModel>>,
}

impl HostNotes {
    pub(super) fn new(model: Option<Arc<BigModel>>) -> Self {
        Self { model }
    }

    /// The model's text under `system` over `data`, read from `sources`, when
    /// a model is bound and `left`, the time the decision left, holds the
    /// whole [`NOTE_BUDGET`]; else `None`.
    fn written(
        &self,
        system: &str,
        data: &Value,
        sources: Option<Vec<oneiron::EntityId>>,
        left: Duration,
    ) -> Option<String> {
        if left < NOTE_BUDGET {
            return None;
        }
        self.model
            .as_ref()?
            .note(system, data.to_string(), sources, NOTE_BUDGET)
    }
}

/// A critic review's notes (FIX 3040): one call for every finding, after the
/// typed answers are in. A finding the reply names no usable note for keeps
/// none, as it did before.
impl ReviewNotes for HostNotes {
    fn notes(&self, findings: &[ReviewFinding]) -> oneiron::Result<Vec<ReviewNote>> {
        let mut notes = vec![ReviewNote::default(); findings.len()];
        if findings.is_empty() {
            return Ok(notes);
        }
        let data = Value::Array(
            findings
                .iter()
                .enumerate()
                .map(|(index, finding)| {
                    json!({
                        "finding": index,
                        "target": finding.input.target.to_hex(),
                        "lens": finding.input.lens.id,
                        "lens_contract": finding.input.lens.prompt_contract,
                        "axis": finding.input.axis,
                        "verdict": finding.verdict,
                        "severity": finding.severity,
                        "hard_check_passed": finding.hard_check_passed,
                        "out_of_scope": finding.out_of_scope,
                    })
                })
                .collect(),
        );
        let mut sources: Vec<_> = findings
            .iter()
            .map(|finding| finding.input.target)
            .collect();
        sources.sort_unstable();
        sources.dedup();
        let Some(text) = self.written(REVIEW_NOTE_SYSTEM, &data, Some(sources), NOTE_BUDGET) else {
            return Ok(notes);
        };
        for (index, note) in review_notes(&text) {
            if let Some(slot) = notes.get_mut(index) {
                *slot = note;
            }
        }
        Ok(notes)
    }
}

/// Each usable note in a review notes reply, by the finding it names: its
/// refs nonempty and cut to the engine's bounds, its edit cut to fit.
fn review_notes(text: &str) -> Vec<(usize, ReviewNote)> {
    let Some(rows) = text
        .find('[')
        .zip(text.rfind(']'))
        .and_then(|(start, end)| text.get(start..=end))
        .and_then(|array| serde_json::from_str::<Vec<Value>>(array).ok())
    else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let index = usize::try_from(row.get("finding")?.as_u64()?).ok()?;
            let evidence_refs = row
                .get("evidence_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|evidence| !evidence.is_empty())
                .map(|evidence| cut_text(evidence, Some(REVIEW_EVIDENCE_REF_BYTES)).to_owned())
                .take(REVIEW_EVIDENCE_REFS)
                .collect();
            let suggested_edit = row
                .get("suggested_edit")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|edit| !edit.is_empty())
                .map(|edit| cut_text(edit, Some(REVIEW_SUGGESTED_EDIT_BYTES)).to_owned());
            Some((
                index,
                ReviewNote {
                    evidence_refs,
                    suggested_edit,
                    prediction: None,
                },
            ))
        })
        .collect()
}

/// A seat pick's why (FIX 654): the model's, within the pick's clock, else the
/// template.
impl SeatNotes for HostNotes {
    fn why(
        &self,
        task: &SeatTask,
        candidates: &[SeatCandidate],
        model: &ModelId,
        effort: ReasoningEffort,
        deadline: &RetrievalDeadline,
    ) -> oneiron::Result<String> {
        let data = json!({
            "task": cut_text(&task.task, Some(NOTE_TASK_BYTES)),
            "profile": task.facet,
            "picked": model.to_string(),
            "effort": effort,
            "candidates": candidates
                .iter()
                .map(|candidate| json!({
                    "model": candidate.model.to_string(),
                    "description": candidate.description.first().map(|line| line.text.as_str()),
                }))
                .collect::<Vec<_>>(),
        });
        match self.written(SEAT_NOTE_SYSTEM, &data, None, deadline.decision_time_left()) {
            Some(why) => Ok(why),
            None => LadderNotes.why(task, candidates, model, effort, deadline),
        }
    }
}

/// An auto check's hold reasons (FIX 654): the model's, one per line, when
/// the gate's wait holds a whole note call, else the template.
impl AutoCheckNotes for HostNotes {
    fn hold_reasons(
        &self,
        candidate: &AutoCheckCandidate<'_>,
        due: Instant,
    ) -> oneiron::Result<Vec<String>> {
        let data = json!({
            "predicate": candidate.predicate,
            "value_preview": candidate.value_preview,
            "source": candidate.source.as_str(),
            "actor_class": candidate.actor_class,
            "sensitivity_band": candidate.sensitivity_band,
            "recent_writes": candidate.signals.recent_writes,
            "window_secs": candidate.signals.window_secs,
            "failure_streak": candidate.signals.failure_streak,
        });
        let left = due.saturating_duration_since(Instant::now());
        let reasons: Vec<String> = self
            .written(HOLD_NOTE_SYSTEM, &data, None, left)
            .map(|text| {
                text.lines()
                    .map(|line| line.trim().trim_start_matches(['-', '*']).trim())
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if reasons.is_empty() {
            return LadderNotes.hold_reasons(candidate, due);
        }
        Ok(reasons)
    }
}
