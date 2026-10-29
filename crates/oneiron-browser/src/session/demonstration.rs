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
//!
//! A person's span records only where the agent's ask opted in (CUA E9b):
//! the take of that ask starts it, through the same listeners, and the
//! person's inputs reach it as their pages' own events; no receipt is
//! taken of them. Their handback ends it and drafts it at once, with the
//! ask's reason and the handback's checks, before the session forgets what
//! it read: the person gets a copy, and the agent's next answer the same,
//! once. The browser going away ends it too, drafted with what it kept.

use super::BrowserSession;
use super::trail::{Event, origin_of};
use crate::demonstration::{Edited, Recording};
use crate::driver::recorder::last_edit;
use crate::{
    BrowserError, DemonstrationId, DemonstrationOutput, DemonstrationSource,
    DemonstrationStartInput, DemonstrationStarted, DemonstrationStopCause, DemonstrationStopInput,
    DraftGap, DraftGapKind, DraftInput, DraftOutcome, DraftOutput, DraftStep, ExpectInput,
    RecordedStep, RecordingGapKind, ReplayAction,
};

/// A session's demonstrations: the one that runs, those that ended and
/// wait to be given, the last id given, whether a verb's act runs now
/// (from which receipt), and a person's span (CUA E9b): the reason of the
/// ask that opted in, until its take, then the span that take started, and
/// the one the browser's going away ended, for the seat's end.
#[derive(Default)]
pub(super) struct Demonstrations {
    active: Option<Recording>,
    ended: Vec<Ended>,
    last: u64,
    acting: Option<u64>,
    asked: Option<String>,
    takeover: Option<TakeoverSpan>,
    abandoned: Option<DemonstrationOutput>,
}

/// A recording that ended: why, and when; a person's span, with the draft
/// its handback made (CUA E9b).
struct Ended {
    recording: Recording,
    cause: DemonstrationStopCause,
    stopped_at_ms: u64,
    draft: Option<DraftOutput>,
}

impl Ended {
    /// The demonstration this recording gives, with `draft`.
    fn output(&self, draft: DraftOutput) -> DemonstrationOutput {
        let recording = &self.recording;
        DemonstrationOutput {
            origin: draft.origin.clone().or_else(|| recording.origin.clone()),
            id: recording.id.clone(),
            source: recording.source,
            label: recording.label.clone(),
            steps: recording.steps.clone(),
            gaps: recording.gaps.clone(),
            started_at_ms: recording.started_at_ms,
            stopped_at_ms: self.stopped_at_ms,
            stop_cause: self.cause,
            draft,
        }
    }
}

/// The span a person's take of an opted-in ask records (CUA E9b): its
/// recording's id, and the ask's reason.
struct TakeoverSpan {
    id: DemonstrationId,
    reason: String,
}

/// A start while a recording runs (`demonstration_start_policy`, CALLS
/// row): one recording per session; the running one is the answer, as it
/// is, never a refusal and never a second.
fn demonstration_start_policy(active: Option<&Recording>) -> Option<DemonstrationStarted> {
    active.map(|running| running.started(true))
}

/// A person's span as its draft reads it (`takeover_draft_policy`, CALLS
/// row): the ask's reason, whole, is its subgoal, never a label; the
/// handback's checks are its checks, and with none E7 names the
/// postcondition missing, none inferred.
fn takeover_draft_policy(
    span: TakeoverSpan,
    postcondition: Vec<ExpectInput>,
) -> DemonstrationStopInput {
    DemonstrationStopInput {
        id: span.id,
        subgoal: span.reason,
        postcondition,
    }
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
        let shown = self.driver.url_shown(&url);
        let label = input
            .label
            .map(|label| label.trim().to_owned())
            .filter(|label| !label.is_empty());
        let gaps = uncovered
            .into_iter()
            .map(|target| RecordingGapKind::Uncovered { target })
            .collect();
        let page = (origin_of(&url), shown);
        Ok(self.recording_open(DemonstrationSource::Agent, label, page, gaps))
    }

    /// Starts the one recording, from `source`, on `page` (its origin, and
    /// its URL as an observation shows it, FIX 10331), naming `gaps` from
    /// its start: the agent's start and a person's take (CUA E9b) each come
    /// here past their own gate.
    fn recording_open(
        &mut self,
        source: DemonstrationSource,
        label: Option<String>,
        page: (Option<String>, String),
        gaps: Vec<RecordingGapKind>,
    ) -> DemonstrationStarted {
        self.demos.last += 1;
        let id = format!("dm{}", self.demos.last);
        let mut recording = Recording::new(id, source, label, super::now_ms(), page);
        for gap in gaps {
            recording.gap(None, None, gap);
        }
        let started = recording.started(false);
        self.demos.active = Some(recording);
        started
    }

    /// A handover's ask, with its reason where it opts the person's span
    /// in (CUA E9b): the person who takes it starts the span.
    pub(super) fn takeover_asked(&mut self, reason: Option<String>) {
        self.demos.asked = reason;
    }

    /// A person's take starts their span where its ask opted in
    /// (`takeover_start_policy`, CALLS row): Chromium only, as any
    /// recording. A start the engine refuses keeps the take: the span
    /// records nothing and names the refusal. Any other take records
    /// nothing.
    pub(super) fn takeover_start_policy(&mut self) {
        let Some(reason) = self.demos.asked.take() else {
            return;
        };
        let (url, capture) = match self.driver.url() {
            Ok(url) => (url, self.driver.record_start()),
            Err(refused) => (String::new(), Err(refused)),
        };
        let gaps = match capture {
            Ok(uncovered) => uncovered
                .into_iter()
                .map(|target| RecordingGapKind::Uncovered { target })
                .collect(),
            Err(refused) => vec![RecordingGapKind::NotStarted {
                refusal: refused.to_string(),
            }],
        };
        let page = (origin_of(&url), self.driver.url_shown(&url));
        let started = self.recording_open(DemonstrationSource::Takeover, None, page, gaps);
        self.demos.takeover = Some(TakeoverSpan {
            id: started.id,
            reason,
        });
    }

    /// Ends a person's span for `cause` as their custody ends (a handback,
    /// or the browser going away) and drafts it at once, before the session
    /// forgets what it read (`takeover_end_policy`, CALLS row): a guest lost
    /// or abandoned ends it with that cause, and a span that ended so keeps
    /// it. The draft is kept for the agent's next answer, once; this is a
    /// copy. An ask never taken, or a take no ask opted in, gives none.
    pub(super) fn takeover_end_policy(
        &mut self,
        cause: DemonstrationStopCause,
        postcondition: Vec<ExpectInput>,
    ) -> Option<DemonstrationOutput> {
        self.demos.asked = None;
        let span = self.demos.takeover.take()?;
        let runs = self
            .demos
            .active
            .as_ref()
            .is_some_and(|running| running.id == span.id);
        if runs {
            // A guest lost or abandoned ends it here, with that cause, and
            // nothing more is asked of it.
            let _ = self.guest_up();
            self.recording_close(cause);
        }
        let at = self
            .demos
            .ended
            .iter()
            .position(|ended| ended.recording.id == span.id)?;
        let mut ended = self.demos.ended.remove(at);
        let input = takeover_draft_policy(span, postcondition);
        ended.draft = self.recording_draft(&ended.recording, Some(input)).ok();
        let copy = ended.draft.clone().map(|draft| ended.output(draft));
        self.demos.ended.insert(at, ended);
        copy
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

    /// Ends a person's span as the browser goes away (CUA E9b), drafted
    /// with what it kept, for the seat's end to land with the abandoned
    /// takeover.
    pub(super) fn takeover_abandoned(&mut self) {
        self.demos.abandoned =
            self.takeover_end_policy(DemonstrationStopCause::Abandoned, Vec::new());
    }

    /// The person's span the browser's going away ended, once (CUA E9b):
    /// the seat's end lands it in the abandoned takeover's receipt.
    pub fn take_abandoned_demonstration(&mut self) -> Option<DemonstrationOutput> {
        self.demos.abandoned.take()
    }

    /// A demonstration that ended since the agent's last answer, once, with
    /// a draft that names no subgoal and no checks: the host's door gives
    /// it as that answer's `demonstration`. A person's span waits for their
    /// handback, and gives the draft it made (CUA E9b).
    pub fn take_demonstration(&mut self) -> Option<DemonstrationOutput> {
        let held = self.demos.takeover.as_ref().map(|span| span.id.as_str());
        let at = self
            .demos
            .ended
            .iter()
            .position(|ended| Some(ended.recording.id.as_str()) != held)?;
        let ended = self.demos.ended.remove(at);
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
            draft: None,
        });
    }

    /// An agent verb's entry outside an act, or a person's input or front
    /// tab's change while they hold the browser (CUA E9b): what the pages
    /// sent since the last drain is acts no verb of the run made.
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
        // The tabs whose page sent its document by this drain; an own act
        // that loaded another page in a tab whose document had not is
        // followed by that document later (FIX 10429).
        let loaded: Vec<&str> = cues
            .iter()
            .filter(|cue| cue.k == "doc" && cue.top)
            .map(|cue| cue.tab.as_str())
            .collect();
        for step in own {
            let typed = matches!(
                step.action,
                Some(ReplayAction::Type { .. } | ReplayAction::Fill { .. })
            );
            let moved = step.verb == "open" || step.result_url != step.source_url;
            let late = step
                .result_tab
                .clone()
                .filter(|tab| moved && !loaded.contains(&tab.as_str()));
            recording.own(step, if typed { edited.take() } else { None });
            if let Some(tab) = late {
                recording.awaits_document(tab);
            }
        }
    }

    /// Gives an ended recording, drafted with the caller's subgoal and
    /// checks, or none (`demonstration_delivery_policy`, CALLS row: a
    /// recording its stop did not end is drafted with neither, and its
    /// draft names both missing; a person's span, as its handback drafted
    /// it, CUA E9b).
    fn demonstration_delivery_policy(
        &mut self,
        mut ended: Ended,
        input: Option<DemonstrationStopInput>,
    ) -> Result<DemonstrationOutput, BrowserError> {
        let draft = match ended.draft.take() {
            Some(draft) => draft,
            None => self.recording_draft(&ended.recording, input)?,
        };
        Ok(ended.output(draft))
    }

    /// `recording`'s steps drafted through E7's one helper with the
    /// caller's subgoal and checks, or neither.
    fn recording_draft(
        &mut self,
        recording: &Recording,
        input: Option<DemonstrationStopInput>,
    ) -> Result<DraftOutput, BrowserError> {
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
        let mut draft = self.draft_over(draft, &steps, url)?;
        // A navigation no recorded act made leaves the draft incomplete,
        // not only the recording's gaps (FIX 9413).
        for gap in &recording.gaps {
            if gap.gap == RecordingGapKind::UnrecordedNavigation {
                draft.gaps.push(DraftGap {
                    seq: gap.seq,
                    verb: None,
                    gap: DraftGapKind::UnrecordedNavigation,
                });
                draft.complete = false;
            }
        }
        Ok(draft)
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
