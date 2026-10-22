//! A batch's no-progress monitor (CUA E3): steps that act and leave the
//! page as it was, [`NO_PROGRESS_STEPS`] in a row, send the batch up to the
//! planner as `NoProgress`. It is an escalation, never a refusal, and caps
//! no count: the third such step has run, and the batch goes up after it.
//!
//! The monitor compares whole reads of the page taken around each step that
//! counts ([`BatchStep::counts_for_progress`]), never the steps' answers:
//! those edit the caller's base, which every step of the batch shares, and
//! may come whole. Its reads are hidden, as a routine step's looks are:
//! unpaged, so the caller's base and pages stay where they were.

use crate::observation::splice_of;
use crate::stop::elapsed_ms;
use crate::{
    BatchOutput, BatchStep, BatchStopCause, BrowserDriver, FailedStepReceipt, Observation,
    StepStop, SubgoalStatus,
};

/// The steps in a row that count and leave the page unchanged before the
/// batch goes up to the planner as `NoProgress` (CUA E3, CALLS row). The
/// run is the batch's own: each batch starts it again.
pub const NO_PROGRESS_STEPS: u32 = 3;

/// The stable code a batch that went up for no progress names as its
/// `error` (CUA E3, CALLS row).
const NO_PROGRESS: &str = "browser_no_progress";

impl BatchStep {
    /// Whether the step counts toward [`NO_PROGRESS_STEPS`] (CUA E3, CALLS
    /// row): a step that acts on the page (open, click, type, select, key,
    /// hotkey, scroll, and a routine step or a Fill once its act ran). A
    /// wait, a check and a screenshot only read it, so they neither count
    /// nor break a run of steps that did; a routine step's own looks and
    /// NONE answers, and a Fill's reads and choice, are no steps.
    #[must_use]
    pub const fn counts_for_progress(&self) -> bool {
        match self {
            Self::Open { .. }
            | Self::Click { .. }
            | Self::Type { .. }
            | Self::Select { .. }
            | Self::Key { .. }
            | Self::Hotkey { .. }
            | Self::Scroll { .. }
            | Self::Decide(_)
            | Self::Fill { .. } => true,
            Self::WaitFor { .. } | Self::Expect { .. } | Self::Screenshot { .. } => false,
        }
    }
}

/// One batch's monitor: the last complete read of the page, whether a step
/// ran since, and the steps in a row that counted and left it unchanged.
pub(crate) struct Progress {
    /// The page before the next step that counts, or after the last one;
    /// none when the last read was cut, showed no tree or was refused.
    page: Option<Observation>,
    /// The viewport's scroll offset at that read, where the driver reads
    /// one (FIX 8508): a scroll that moved it is progress.
    offset: Option<(f64, f64)>,
    /// `page` was read after the last step, and no step ran since.
    fresh: bool,
    unchanged: u32,
}

impl Progress {
    pub(crate) const fn new() -> Self {
        Self {
            page: None,
            offset: None,
            fresh: false,
            unchanged: 0,
        }
    }

    /// Before a step: for one that counts, the page as it is now, unless the
    /// read after the last step still stands. A wait, check or screenshot
    /// since is no step of the run, but a change it let show, or a read that
    /// proves nothing, starts the run again.
    pub(crate) fn before<D: BrowserDriver + ?Sized>(&mut self, driver: &mut D, counts: bool) {
        if !counts || self.fresh {
            return;
        }
        let now = complete_read(driver);
        let offset = driver.viewport_offset();
        if !unchanged(self.page.as_ref(), now.as_ref()) || moved(self.offset, offset) {
            self.unchanged = 0;
        }
        self.page = now;
        self.offset = offset;
    }

    /// After a step ran: for one that counts, the page as it is now against
    /// the page before it. The read that makes [`NO_PROGRESS_STEPS`]
    /// unchanged steps in a row comes back, for the batch to go up with.
    pub(crate) fn after<D: BrowserDriver + ?Sized>(
        &mut self,
        driver: &mut D,
        counts: bool,
    ) -> Option<Observation> {
        if !counts {
            self.fresh = false;
            return None;
        }
        let now = complete_read(driver);
        let offset = driver.viewport_offset();
        let same = unchanged(self.page.as_ref(), now.as_ref()) && !moved(self.offset, offset);
        self.unchanged = if same {
            self.unchanged.saturating_add(1)
        } else {
            0
        };
        self.page = now;
        self.offset = offset;
        self.fresh = true;
        if self.unchanged >= NO_PROGRESS_STEPS {
            return self.page.clone();
        }
        None
    }
}

/// A hidden whole read of the page, as a routine step's look takes it, when
/// it is complete: a cut tree walk or a window with no tree leaves rows
/// unseen, so it proves no page unchanged, and neither does a refused read.
fn complete_read<D: BrowserDriver + ?Sized>(driver: &mut D) -> Option<Observation> {
    driver
        .observe_hidden()
        .ok()
        .filter(|page| page.full && page.partial.is_none() && !page.no_tree)
}

/// Whether two complete reads show the page unchanged: the same scope (its
/// session, so its engine, and its tab's documents), URL and title, and an
/// empty ordered edit between their rows. A missing read proves nothing.
fn unchanged(was: Option<&Observation>, now: Option<&Observation>) -> bool {
    let (Some(was), Some(now)) = (was, now) else {
        return false;
    };
    if was.scope != now.scope || was.url != now.url || was.title != now.title {
        return false;
    }
    let (splice, rows) = splice_of(&was.rows, &now.rows);
    splice.delete_count == 0 && rows.is_empty()
}

/// Whether the viewport moved between two reads of its offset (FIX 8508):
/// a scroll that moved it is progress even where the outline already held
/// its rows; a scroll at the page's end moves nothing. An offset the driver
/// does not read proves no move.
fn moved(was: Option<(f64, f64)>, now: Option<(f64, f64)>) -> bool {
    match (was, now) {
        (Some((x, y)), Some((nx, ny))) => {
            x.to_bits() != nx.to_bits() || y.to_bits() != ny.to_bits()
        }
        _ => false,
    }
}

/// The stop a batch's history notes when it went up for no progress at a
/// `step` step (CUA E7): the receipt of that step's effect, which ran,
/// marked failed with it.
pub(crate) fn no_progress(step: &str, receipt: Option<u64>) -> StepStop {
    StepStop {
        step: step.to_owned(),
        cause: BatchStopCause::NoProgress,
        error: NO_PROGRESS.to_owned(),
        receipt,
        effect_class: None,
    }
}

/// `output`, gone up to the planner for no progress at step `step`, the
/// batch started at `started`: its receipt holds `page`, the complete read
/// that showed the page unchanged the last time, and no check, as none
/// failed. The step's own effect ran and stays in its receipts.
pub(crate) fn handed_up(
    mut output: BatchOutput,
    step: usize,
    page: Observation,
    started: std::time::Instant,
) -> BatchOutput {
    output.status = SubgoalStatus::NeedsAgent;
    output.failed_step = Some(step);
    output.error = Some(NO_PROGRESS.to_owned());
    output.stop_cause = Some(BatchStopCause::NoProgress);
    output.failed_receipt = Some(FailedStepReceipt {
        step: Some(step),
        stop_cause: BatchStopCause::NoProgress,
        missed: Vec::new(),
        observation: Some(page),
        error: Some(NO_PROGRESS.to_owned()),
        refusal: None,
        next: None,
    });
    output.elapsed_ms = elapsed_ms(started);
    output
}
