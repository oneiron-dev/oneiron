//! How long each gated startup step took. From `listening` to `startup
//! finished` the startup gate holds every request but health (FIX 22117), so
//! a client's first call waits for the whole block. Serve logs each step's
//! milliseconds once, on its `startup finished` line.

use std::fmt;
use std::time::{Duration, Instant};

/// The steps of one start, in order, each with the wall time since the step
/// before it.
#[derive(Debug)]
pub(crate) struct StartupTimings {
    began: Instant,
    last: Instant,
    steps: Vec<(&'static str, Duration)>,
}

impl StartupTimings {
    /// Starts timing now; the first step's time is counted from here.
    pub(crate) fn begin() -> Self {
        let now = Instant::now();
        Self {
            began: now,
            last: now,
            steps: Vec::new(),
        }
    }

    /// `step` ended now: it took the time since the step before it.
    pub(crate) fn mark(&mut self, step: &'static str) {
        let now = Instant::now();
        self.steps
            .push((step, now.saturating_duration_since(self.last)));
        self.last = now;
    }

    /// The steps `inner` timed inside the step that ends now, in their order,
    /// in place of that one step.
    pub(crate) fn absorb(&mut self, inner: Self) {
        self.steps.extend(inner.steps);
        self.last = Instant::now();
    }

    /// From [`Self::begin`] to the last step's end.
    pub(crate) fn total(&self) -> Duration {
        self.last.saturating_duration_since(self.began)
    }
}

/// `step=ms` for each step, in order, space-separated.
impl fmt::Display for StartupTimings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, (step, took)) in self.steps.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{step}={}", took.as_millis())?;
        }
        Ok(())
    }
}
