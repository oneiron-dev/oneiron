//! `demonstration.start` and `demonstration.stop` on a browser session
//! (CUA E9a): the one recording that runs, the ones that ended and wait to
//! be given, and the session's verbs' edges where the capture is drained.
//!
//! An agent verb's own act is its effect's receipt, as the session's
//! history keeps it (`trail`): the events its pages sent while the verb ran
//! only give a type's field's final text, or show it secret. Events
//! between verbs, and those of a verb that left no replayable act (a
//! `click_at`), are matched to the outline (`driver::recorder`).
//!
//! A recording ends at its stop, at a handover (it never records a
//! person's input as the agent's), at a successful engine switch, or when
//! the guest is lost or abandoned. One that ended so waits on the session,
//! outside its engine, and the next stop naming it, or else the session's
//! next answer, gives it once; neither needs the guest.

use super::BrowserSession;
use super::trail::{Event, origin_of};
use crate::demonstration::{Edited, Recording};
use crate::driver::recorder::last_edit;
use crate::{
    BrowserError, DemonstrationOutput, DemonstrationStartInput, DemonstrationStarted,
    DemonstrationStopCause, DemonstrationStopInput, DraftGapKind, DraftInput, DraftOutcome,
    DraftStep, RecordedStep, RecordingGapKind, ReplayAction,
};

/// A session's demonstrations: the one that runs, those that ended and
/// wait to be given, the last id given, and whether a verb's act runs now
/// (from which receipt).
#[derive(Default)]
pub(super) struct Demonstrations {
    active: Option<Recording>,
    ended: Vec<Ended>,
    last: u64,
    acting: Option<u64>,
}

/// A recording that ended: why, and when.
struct Ended {
    recording: Recording,
    cause: DemonstrationStopCause,
    stopped_at_ms: u64,
}

/// A start while a recording runs (`demonstration_start_policy`, CALLS
/// row): one recording per session; the running one is the answer, as it
/// is, never a refusal and never a second.
fn demonstration_start_policy(active: Option<&Recording>) -> Option<DemonstrationStarted> {
    active.map(|running| running.started(true))
}

/// A recorded step as E7's draft reads it.
fn draft_step(step: &RecordedStep) -> DraftStep {
    let outcome = match (&step.failed, step.no_effect) {
        (Some(cause), _) => DraftOutcome::Failed {
            cause: cause.clone(),
        },
        (None, true) => DraftOutcome::NoEffect,
        (None, false) => DraftOutcome::Ok,
    };
    let requested_origin = match &step.action {
        Some(ReplayAction::Open { url }) => origin_of(url),
        _ => None,
    };
    DraftStep {
        seq: step.seq,
        verb: step.verb.clone(),
        tab: step.tab.clone(),
        result_tab: step.result_tab.clone(),
        source_url: step.source_url.clone(),
        source_origin: step.source_url.as_deref().and_then(origin_of),
        result_url: step.result_url.clone().unwrap_or_default(),
        result_origin: step.result_url.as_deref().and_then(origin_of),
        requested_origin,
        target_name: step.target_name.clone(),
        effect_class: step.effect_class.clone(),
        action: step.action.clone().ok_or(DraftGapKind::NoAction),
        outcome,
    }
}

impl BrowserSession {
    /// `demonstration.start`: records the attached browser from now on, or
    /// answers the recording that runs. Chromium only.
    pub(super) fn demonstration_begin(
        &mut self,
        input: DemonstrationStartInput,
    ) -> Result<DemonstrationStarted, BrowserError> {
        self.agent_has()?;
        if let Some(running) = demonstration_start_policy(self.demos.active.as_ref()) {
            return Ok(running);
        }
        let url = self.live()?.url()?;
        let uncovered = self.driver.record_start()?;
        self.demos.last += 1;
        let label = input
            .label
            .map(|label| label.trim().to_owned())
            .filter(|label| !label.is_empty());
        let id = format!("dm{}", self.demos.last);
        let page = (origin_of(&url), url);
        let mut recording = Recording::new(id, label, super::now_ms(), page);
        for target in uncovered {
            recording.gap(None, None, RecordingGapKind::Uncovered { target });
        }
        let started = recording.started(false);
        self.demos.active = Some(recording);
        Ok(started)
    }

    /// `demonstration.stop`: ends demonstration `id` if it runs, or takes
    /// it where it ended, and gives it once, drafted with the caller's
    /// subgoal and checks.
    pub(super) fn demonstration_end(
        &mut self,
        input: DemonstrationStopInput,
    ) -> Result<DemonstrationOutput, BrowserError> {
        self.agent_has()?;
        let runs = self
            .demos
            .active
            .as_ref()
            .is_some_and(|running| running.id == input.id);
        if runs {
            // A guest lost or abandoned ends it here, with that cause, and
            // nothing more is asked of it.
            let _ = self.guest_up();
            self.recording_close(DemonstrationStopCause::Stopped);
        }
        let at = self
            .demos
            .ended
            .iter()
            .position(|ended| ended.recording.id == input.id)
            .ok_or_else(|| {
                BrowserError::Input(format!(
                    "no demonstration {} runs or waits in this session; an ended one is given once",
                    input.id
                ))
            })?;
        let ended = self.demos.ended.remove(at);
        self.demonstration_delivery_policy(ended, Some(input))
    }

    /// A demonstration that ended since the agent's last answer, once, with
    /// a draft that names no subgoal and no checks: the host's door gives
    /// it as that answer's `demonstration`.
    pub fn take_demonstration(&mut self) -> Option<DemonstrationOutput> {
        if self.demos.ended.is_empty() {
            return None;
        }
        let ended = self.demos.ended.remove(0);
        self.demonstration_delivery_policy(ended, None).ok()
    }

    /// Ends the running recording for `cause`: its capture's last events
    /// taken, from a guest that still answers, and kept on the session.
    pub(super) fn recording_close(&mut self, cause: DemonstrationStopCause) {
        let Some(mut recording) = self.demos.active.take() else {
            return;
        };
        let answers = !matches!(
            cause,
            DemonstrationStopCause::GuestLost | DemonstrationStopCause::Abandoned
        );
        let cues = if answers {
            self.driver.record_stop()
        } else {
            self.driver.record_off()
        };
        for seen in self.driver.record_map(cues, recording.pages(), answers) {
            recording.demonstration_coalesce_policy(seen);
        }
        recording.finish();
        self.demos.ended.push(Ended {
            recording,
            cause,
            stopped_at_ms: super::now_ms(),
        });
    }

    /// An agent verb's entry outside an act: what the pages sent since the
    /// last drain is acts no verb of the run made.
    pub(super) fn recording_drain(&mut self) {
        if self.demos.acting.is_some() {
            return;
        }
        let Some(recording) = self.demos.active.as_mut() else {
            return;
        };
        let cues = self.driver.record_drain();
        if cues.is_empty() {
            return;
        }
        for seen in self.driver.record_map(cues, recording.pages(), true) {
            recording.demonstration_coalesce_policy(seen);
        }
    }

    /// An effect verb starts its act, after the receipt `from`.
    pub(super) fn recording_act(&mut self, from: u64) {
        self.recording_drain();
        if self.demos.active.is_some() {
            self.demos.acting = Some(from);
        }
    }

    /// An effect verb's act ended: each replayable act it receipted is a
    /// step, a type's taking the final text its field showed; with none,
    /// what its pages sent is matched as any other act.
    pub(super) fn recording_acted(&mut self) {
        let Some(from) = self.demos.acting.take() else {
            return;
        };
        let Some(recording) = self.demos.active.as_mut() else {
            return;
        };
        let cues = self.driver.record_drain();
        let own = own_steps(&self.trail, from);
        if own.is_empty() {
            for seen in self.driver.record_map(cues, recording.pages(), true) {
                recording.demonstration_coalesce_policy(seen);
            }
            return;
        }
        let mut edited: Option<Edited> = last_edit(&cues);
        for step in own {
            let typed = matches!(
                step.action,
                Some(ReplayAction::Type { .. } | ReplayAction::Fill { .. })
            );
            recording.own(step, if typed { edited.take() } else { None });
        }
    }

    /// Gives an ended recording, drafted with the caller's subgoal and
    /// checks, or none (`demonstration_delivery_policy`, CALLS row: a
    /// recording its stop did not end is drafted with neither, and its
    /// draft names both missing).
    fn demonstration_delivery_policy(
        &mut self,
        ended: Ended,
        input: Option<DemonstrationStopInput>,
    ) -> Result<DemonstrationOutput, BrowserError> {
        let Ended {
            recording,
            cause,
            stopped_at_ms,
        } = ended;
        let (subgoal, postcondition) = input.map_or_else(Default::default, |input| {
            (input.subgoal, input.postcondition)
        });
        let steps: Vec<DraftStep> = recording.steps.iter().map(draft_step).collect();
        let url = recording
            .steps
            .iter()
            .rev()
            .find_map(|step| step.result_url.clone())
            .unwrap_or_else(|| recording.url.clone());
        let draft = DraftInput {
            subgoal,
            postcondition,
            after_seq: Some(0),
            through_seq: Some(recording.steps.last().map_or(0, |step| step.seq)),
            past_press: false,
        };
        let draft = self.draft_over(draft, &steps, url)?;
        Ok(DemonstrationOutput {
            origin: draft.origin.clone().or(recording.origin),
            id: recording.id,
            source: recording.source,
            label: recording.label,
            steps: recording.steps,
            gaps: recording.gaps,
            started_at_ms: recording.started_at_ms,
            stopped_at_ms,
            stop_cause: cause,
            draft,
        })
    }
}

/// The replayable acts the history receipted after `from`, as recorded
/// steps: each marked failed when a stop after it says so. A verb that
/// made no such act records none.
fn own_steps(trail: &[Event], from: u64) -> Vec<RecordedStep> {
    let recent = move || {
        trail
            .iter()
            .rev()
            .take_while(move |event| seq_of(event) > from)
    };
    let mut steps: Vec<RecordedStep> = recent()
        .filter_map(Event::receipt)
        .filter(|receipt| receipt.action.is_some())
        .map(|receipt| RecordedStep {
            seq: 0,
            verb: receipt.verb.clone(),
            tab: receipt.tab.clone(),
            result_tab: receipt.result_tab.clone(),
            source_url: receipt.source_url.clone(),
            result_url: Some(receipt.url.clone()),
            target_name: receipt.target_name.clone(),
            effect_class: receipt.effect_class.clone(),
            receipt: Some(receipt.seq),
            action: receipt.action.clone(),
            failed: None,
            no_effect: receipt.fact.is_some(),
        })
        .collect();
    steps.reverse();
    for event in recent() {
        if let Event::Stop(marker) = event
            && let Some(step) = steps
                .iter_mut()
                .find(|step| step.receipt == marker.stop.receipt)
        {
            step.failed = Some(marker.stop.cause.clone());
        }
    }
    steps
}

/// An entry's seq on the history's one sequence.
fn seq_of(event: &Event) -> u64 {
    match event {
        Event::Effect(receipt) => receipt.seq,
        Event::Stop(marker) => marker.seq,
    }
}
