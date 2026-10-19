//! The Coach's rule for an owner's digest settings (FIX 5495): closed-form,
//! no model call, over the owner's own behaviour only (what he opened,
//! dismissed or told it), never anyone else's. It proposes one step: the
//! rhythm he asked for, the section he asked to lead, or, on a daily digest
//! he keeps leaving, a weekly one. Implicit signals never propose a faster
//! rhythm or a layout change, and a step the owner declined or undid under
//! the current settings generation is never proposed again (CALLS: FIX 5495
//! signals and steps).

use super::settings::StoredFeedback;
use super::{WeaveDigestCadence, WeaveSectionKind};

/// A daily digest whose last this many opened periods were each opened a
/// cadence or more after they came is proposed weekly.
const LATE_OPENS_TO_SLOW: usize = 3;
/// A daily digest whose current period's notice he dismissed unopened, and
/// which has waited this many cadences, is proposed weekly.
const DISMISSED_PERIODS_TO_SLOW: u64 = 3;

/// One step the Coach may take on an Owner schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
