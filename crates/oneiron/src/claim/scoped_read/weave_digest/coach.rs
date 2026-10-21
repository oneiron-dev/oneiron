//! The Coach's rule for an owner's digest settings (FIX 5495): closed-form,
//! no model call, over the owner's own behaviour only (what he opened,
//! dismissed or told it), never anyone else's. It proposes one step: the
//! rhythm he asked for, the section he asked to lead, or, on a daily digest
//! he keeps leaving, a weekly one. Implicit signals never propose a faster
//! rhythm or a layout change, and a step the owner declined or undid under
//! the current settings generation is never proposed again (CALLS: FIX 5495
//! signals and steps). With a host Coach serving the vault, its model drafts
//! the step instead (FIX 5609): the engine builds its brief and checks its
//! answer here, and this rule decides only while the model is unavailable.

use super::settings::{StoredFeedback, WeaveDigestFeedback};
use super::{WeaveDigestCadence, WeaveSectionKind, invalid};
use crate::EntityId;
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// A daily digest whose last this many opened periods were each opened a
/// cadence or more after they came is proposed weekly.
const LATE_OPENS_TO_SLOW: usize = 3;
/// A daily digest whose current period's notice he dismissed unopened, and
/// which has waited this many cadences, is proposed weekly.
const DISMISSED_PERIODS_TO_SLOW: u64 = 3;

/// One step the Coach may take on an Owner schedule. Its JSON form is the
/// `weave-digest-settings` skill's step: `{"cadence": ...}` or `{"lead": ...}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CoachStep {
    /// Set the rhythm.
    Cadence(WeaveDigestCadence),
    /// Move the first section of this kind to the front, the rest in order.
    Lead(WeaveSectionKind),
}

/// The owner's own record of one period.
#[derive(Debug, Clone)]
pub(super) struct PeriodRecord {
    pub(super) scheduled_for: u64,
    pub(super) cadence: WeaveDigestCadence,
    pub(super) opened_at: Option<u64>,
    /// Its due notice carries his acknowledgement while it is unopened.
    pub(super) dismissed: bool,
}

/// What the rule reads: the owner's own records, his settings and what he
/// already refused.
pub(super) struct CoachInput<'a> {
    pub(super) now: u64,
    pub(super) cadence: WeaveDigestCadence,
    pub(super) sections: &'a [WeaveSectionKind],
    pub(super) feedback: Option<&'a StoredFeedback>,
    pub(super) periods: &'a [PeriodRecord],
    /// The steps he declined or undid under the current generation.
    pub(super) refused: &'a [CoachStep],
}

/// The host's drafter of one owner's digest settings step on the Coach's
/// model (FIX 5609). The engine builds the brief, the `weave-digest-settings`
/// hub skill's input, and checks the answer; the drafter runs the skill on it.
pub trait WeaveDigestSettingsDrafter {
    /// The model's answer to `brief`, `owner`'s evaluation under his settings
    /// `generation`, as text: the evaluation is named so the drafter can
    /// meter each owner's own (FIX 6166). `Ok(None)`: the drafter is
    /// unavailable (no Coach or chat seat, a refused model call, or no hub
    /// skill), and the closed-form rule decides instead.
    ///
    /// # Errors
    /// A state or storage error, never read as the drafter being unavailable.
    fn draft(&self, owner: EntityId, generation: u64, brief: &str) -> Result<Option<String>>;

    /// [`Self::draft`], handed the rows the brief was read from (FIX 7105):
    /// `Some` only when every constituent the brief read has a typed
    /// witness, `None` when any lacks one. A drafter that sources its model
    /// call overrides this; the default drops the rows and drafts as
    /// [`Self::draft`] does. `None` never refuses or changes a draft.
    ///
    /// # Errors
    /// As [`Self::draft`].
    fn draft_sourced(
        &self,
        owner: EntityId,
        generation: u64,
        brief: &str,
        _source_rows: Option<Vec<EntityId>>,
    ) -> Result<Option<String>> {
        self.draft(owner, generation, brief)
    }
}

/// What the Coach's model answered, as the engine admits it.
pub(super) enum CoachDraft {
    /// `{"step": null}`: nothing is worth changing.
    Nothing,
    /// One step the engine admits, with its reason to him.
    Step(CoachStep, String),
    /// An answer outside the skill's output, or a step the engine refuses.
    Refused,
}

/// One period as the brief shows it.
#[derive(Serialize)]
struct BriefPeriod {
    due_at: u64,
    cadence: WeaveDigestCadence,
    opened_at: Option<u64>,
    dismissed: bool,
}

/// The `weave-digest-settings` skill's input, field for field.
#[derive(Serialize)]
struct Brief<'a> {
    now: u64,
    cadence: WeaveDigestCadence,
    sections: &'a [WeaveSectionKind],
    feedback: Option<WeaveDigestFeedback>,
    periods: Vec<BriefPeriod>,
    refused: &'a [CoachStep],
}

/// The skill's output: a step and its reason, or `{"step": null}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerWire {
    step: serde_json::Value,
    #[serde(default)]
    reason: Option<String>,
}

/// The brief the Coach's model reads: what the rule reads, his periods
/// newest first, as JSON.
pub(super) fn weave_digest_coach_brief(input: &CoachInput<'_>) -> Result<String> {
    let mut periods: Vec<BriefPeriod> = input
        .periods
        .iter()
        .map(|period| BriefPeriod {
            due_at: period.scheduled_for,
            cadence: period.cadence,
            opened_at: period.opened_at,
            dismissed: period.dismissed,
        })
        .collect();
    periods.sort_by_key(|period| std::cmp::Reverse(period.due_at));
    serde_json::to_string(&Brief {
        now: input.now,
        cadence: input.cadence,
        sections: input.sections,
        feedback: input.feedback.map(|feedback| WeaveDigestFeedback {
            preferred_cadence: feedback.preferred_cadence,
            lead_section: feedback.lead_section,
            keep_current: feedback.keep_current,
        }),
        periods,
        refused: input.refused,
    })
    .map_err(|_| invalid())
}

/// The rows [`weave_digest_coach_brief`] reads `input` from, for
/// [`WeaveDigestSettingsDrafter::draft_sourced`] (FIX 7105). `None` today:
/// its schedule, settings and feedback, period and change rows are side-table
/// rows with no entity witness.
pub(super) fn coach_brief_sources(_input: &CoachInput<'_>) -> Option<Vec<EntityId>> {
    None
}

/// The Coach's model's answer, the one JSON object in its text, checked
/// against what it read. Only the skill's output shapes parse. A step needs a
/// reason that is not blank, must change his rhythm or lead with a section
/// he already has, must not be one he refused, and never stands over his
/// `keep_current`. The rule's thresholds and order are not gates on it.
pub(super) fn weave_digest_coach_draft(input: &CoachInput<'_>, answer: &str) -> CoachDraft {
    let Some(wire) = answer
        .find('{')
        .zip(answer.rfind('}'))
        .and_then(|(start, end)| answer.get(start..=end))
        .and_then(|object| serde_json::from_str::<AnswerWire>(object).ok())
    else {
        return CoachDraft::Refused;
    };
    let (step, reason) = match (wire.step, wire.reason) {
        (serde_json::Value::Null, None) => return CoachDraft::Nothing,
        (step, Some(reason)) => match serde_json::from_value::<CoachStep>(step) {
            Ok(step) => (step, reason),
            Err(_) => return CoachDraft::Refused,
        },
        (_, None) => return CoachDraft::Refused,
    };
    let reason = reason.trim();
    let changes = match step {
        CoachStep::Cadence(cadence) => cadence != input.cadence,
        CoachStep::Lead(kind) => {
            input.sections.contains(&kind) && input.sections.first() != Some(&kind)
        }
    };
    if reason.is_empty()
        || !changes
        || input.refused.contains(&step)
        || input.feedback.is_some_and(|feedback| feedback.keep_current)
    {
        return CoachDraft::Refused;
    }
    CoachDraft::Step(step, reason.to_owned())
}

fn cadence_word(cadence: WeaveDigestCadence) -> &'static str {
    match cadence {
        WeaveDigestCadence::Daily => "daily",
        WeaveDigestCadence::Weekly => "weekly",
    }
}

/// The step the owner's own behaviour asks for, with its short reason, or
/// `None`.
pub(super) fn weave_digest_coach_step(input: &CoachInput<'_>) -> Option<(CoachStep, String)> {
    let open = |step: CoachStep| !input.refused.contains(&step);
    if let Some(feedback) = input.feedback {
        if feedback.keep_current {
            return None;
        }
        if let Some(cadence) = feedback.preferred_cadence
            && cadence != input.cadence
            && open(CoachStep::Cadence(cadence))
        {
            return Some((
                CoachStep::Cadence(cadence),
                format!("you asked for a {} digest", cadence_word(cadence)),
            ));
        }
        if let Some(kind) = feedback.lead_section
            && input.sections.first() != Some(&kind)
            && input.sections.contains(&kind)
            && open(CoachStep::Lead(kind))
        {
            return Some((
                CoachStep::Lead(kind),
                format!(
                    "you asked for {} first",
                    kind.policy_name().replace('_', " ")
                ),
            ));
        }
    }
    let slower = CoachStep::Cadence(WeaveDigestCadence::Weekly);
    if input.cadence != WeaveDigestCadence::Daily || !open(slower) {
        return None;
    }
    let day = WeaveDigestCadence::Daily.seconds();
    let mut opened: Vec<(u64, u64)> = input
        .periods
        .iter()
        .filter(|period| period.cadence == WeaveDigestCadence::Daily)
        .filter_map(|period| Some((period.scheduled_for, period.opened_at?)))
        .collect();
    opened.sort_by_key(|&(scheduled_for, _)| std::cmp::Reverse(scheduled_for));
    if opened.len() >= LATE_OPENS_TO_SLOW
        && opened
            .iter()
            .take(LATE_OPENS_TO_SLOW)
            .all(|(scheduled_for, opened_at)| opened_at.saturating_sub(*scheduled_for) >= day)
    {
        return Some((
            slower,
            format!(
                "you opened your last {LATE_OPENS_TO_SLOW} daily digests a day or more after \
                 each came"
            ),
        ));
    }
    if let Some(current) = input
        .periods
        .iter()
        .max_by_key(|period| period.scheduled_for)
        && current.cadence == WeaveDigestCadence::Daily
        && current.dismissed
        && current.opened_at.is_none()
        && input.now.saturating_sub(current.scheduled_for)
            >= DISMISSED_PERIODS_TO_SLOW.saturating_mul(day)
    {
        return Some((
            slower,
            format!(
                "you dismissed your digest unopened, and it has waited \
                 {DISMISSED_PERIODS_TO_SLOW} days"
            ),
        ));
    }
    None
}
