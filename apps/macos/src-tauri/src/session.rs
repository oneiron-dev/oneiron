//! The recorder session — the one place that knows whether this Mac is
//! recording.
//!
//! Both surfaces (the menu bar and the window) render from [`SessionView`], so
//! they cannot disagree about the state, and the menu bar cannot show
//! "Recording" over a capture that never opened. The disclosure gate is
//! upstream of every path into a capture.

use std::sync::{Arc, Mutex};

use oneiron::EntityId;
use serde::Serialize;

use crate::capture::{
    CaptureError, CaptureLauncher, Result as CaptureResult, RunningCapture, SegmentMeta,
    SegmentSink,
};
use crate::copy;
use crate::disclosure::{DisclosureError, DisclosureGate, DisclosureState};

/// How many segments the window lists.
const SEGMENT_LIST_LIMIT: usize = 20;

/// One committed segment, as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommittedSegment {
    /// Hex identity of the ASSET entity holding the audio.
    pub id: String,
    /// Unix second the segment opened.
    pub started_at: u64,
    /// How much audio it holds.
    pub duration_ms: u32,
    /// The echo-cancellation mode it actually got, spelled exactly as the
    /// claim spells it.
    pub aec_mode: &'static str,
    /// 1 for microphone only, 2 with the far end alongside it.
    pub channels: u16,
    /// The input device it was captured on.
    pub device: String,
}

/// What this session has committed so far.
#[derive(Debug, Clone, Default)]
pub struct SegmentLog(Arc<Mutex<Vec<CommittedSegment>>>);

impl SegmentLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&self, segment: CommittedSegment) {
        if let Ok(mut log) = self.0.lock() {
            log.push(segment);
        }
    }

    /// The most recent segments, newest first.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<CommittedSegment> {
        self.0.lock().map_or_else(
            |_| Vec::new(),
            |log| log.iter().rev().take(limit).cloned().collect(),
        )
    }
}

/// A sink that remembers what it passed through.
///
/// The window lists this session's segments without re-reading the vault, and
/// it lists exactly what was committed — the log is written on the way out of
/// a successful commit, never on the way in.
pub struct LoggingSink<S> {
    inner: S,
    log: SegmentLog,
}

impl<S: SegmentSink> LoggingSink<S> {
    /// Wraps `inner`, recording every commit into `log`.
    pub fn new(inner: S, log: SegmentLog) -> Self {
        Self { inner, log }
    }
}

impl<S: SegmentSink> SegmentSink for LoggingSink<S> {
    fn commit_segment(&self, audio: &[u8], meta: SegmentMeta) -> CaptureResult<EntityId> {
        let (started_at, duration_ms, aec_mode, channels) = (
            meta.started_at,
            meta.duration_ms,
            meta.aec.claim_mode(),
            meta.channels,
        );
        let device = meta.device.clone();
        let id = self.inner.commit_segment(audio, meta)?;
        self.log.record(CommittedSegment {
            id: id.to_hex(),
            started_at,
            duration_ms,
            aec_mode,
            channels,
            device,
        });
        Ok(id)
    }
}

/// Why a session refused.
#[derive(Debug)]
pub enum SessionError {
    /// The disclosure gate is closed.
    Disclosure(DisclosureError),
    /// The capture itself failed.
    Capture(CaptureError),
    /// A recording is already running.
    AlreadyRecording,
    /// Nothing is recording.
    NotRecording,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disclosure(err) => write!(f, "{err}"),
            Self::Capture(err) => write!(f, "{err}"),
            Self::AlreadyRecording => f.write_str("this Mac is already recording"),
            Self::NotRecording => f.write_str("nothing is recording"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<DisclosureError> for SessionError {
    fn from(err: DisclosureError) -> Self {
        Self::Disclosure(err)
    }
}

/// Everything both surfaces render from.
#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    /// Where the disclosure gate stands.
    pub disclosure: DisclosureState,
    /// Whether audio is being captured right now.
    pub recording: bool,
    /// Unix second the running capture began.
    pub started_at: Option<u64>,
    /// Unix second of the affirm that authorized it.
    pub disclosed_at: Option<u64>,
    /// The menu-bar title.
    pub menu_bar: &'static str,
    /// One line of guidance for the window.
    pub hint: &'static str,
    /// This session's committed segments, newest first.
    pub segments: Vec<CommittedSegment>,
}

/// The recorder's state machine.
pub struct RecorderSession {
    gate: DisclosureGate,
    launcher: Box<dyn CaptureLauncher>,
    capture: Option<Box<dyn RunningCapture>>,
    log: SegmentLog,
}

impl RecorderSession {
    /// A session that opens captures through `launcher` and lists `log`.
    #[must_use]
    pub fn new(launcher: Box<dyn CaptureLauncher>, log: SegmentLog) -> Self {
        Self {
            gate: DisclosureGate::new(),
            launcher,
            capture: None,
            log,
        }
    }

    /// Records the operator's disclosure affirm at `at`.
    pub const fn affirm(&mut self, at: u64) {
        self.gate.affirm(at);
    }

    /// Whether audio is being captured right now.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.capture.is_some()
    }

    /// Starts recording.
    ///
    /// The affirm is spent only if a capture actually opens: a microphone that
    /// refuses to start is not a reason to make the operator disclose twice.
    ///
    /// # Errors
    ///
    /// [`SessionError::Disclosure`] when the gate is closed — the invariant
    /// this whole app exists to keep — [`SessionError::AlreadyRecording`], or
    /// [`SessionError::Capture`] when the audio devices refuse.
    pub fn start(&mut self) -> Result<(), SessionError> {
        if self.capture.is_some() {
            return Err(SessionError::AlreadyRecording);
        }
        let permit = self.gate.take_permit()?;
        let affirmed_at = permit.affirmed_at();
        match self.launcher.launch(permit) {
            Ok(capture) => {
                self.capture = Some(capture);
                Ok(())
            }
            Err(err) => {
                self.gate.affirm(affirmed_at);
                Err(SessionError::Capture(err))
            }
        }
    }

    /// Stops recording. The segment that was open is committed on the way out.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotRecording`], or whatever the capture failed with
    /// while it ran.
    pub fn stop(&mut self) -> Result<(), SessionError> {
        let mut capture = self.capture.take().ok_or(SessionError::NotRecording)?;
        capture.stop().map_err(SessionError::Capture)
    }

    /// The state both surfaces render.
    #[must_use]
    pub fn view(&self) -> SessionView {
        let recording = self.capture.is_some();
        SessionView {
            disclosure: self.gate.state(),
            recording,
            started_at: self.capture.as_ref().map(|capture| capture.started_at()),
            disclosed_at: self.capture.as_ref().map(|capture| capture.disclosed_at()),
            menu_bar: if recording {
                copy::MENU_BAR_RECORDING
            } else {
                copy::MENU_BAR_IDLE
            },
            hint: match (recording, self.gate.state()) {
                (true, _) => copy::RECORDING_HINT,
                (false, DisclosureState::Affirmed) => copy::DISCLOSURE_AFFIRMED_HINT,
                (false, DisclosureState::Required) => copy::DISCLOSURE_REQUIRED_HINT,
            },
            segments: self.log.recent(SEGMENT_LIST_LIMIT),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::capture::{AecMode, OutputRoute};
    use crate::disclosure::CapturePermit;

    const NOW: u64 = 1_773_532_800;

    struct FakeCapture {
        stopped: Arc<AtomicUsize>,
        disclosed_at: u64,
    }

    impl RunningCapture for FakeCapture {
        fn started_at(&self) -> u64 {
            NOW
        }

        fn disclosed_at(&self) -> u64 {
            self.disclosed_at
        }

        fn stop(&mut self) -> CaptureResult<()> {
            self.stopped.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingLauncher {
        launches: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        refuse: bool,
    }

    impl CaptureLauncher for CountingLauncher {
        fn launch(&self, permit: CapturePermit) -> CaptureResult<Box<dyn RunningCapture>> {
            if self.refuse {
                return Err(CaptureError::NoInputDevice);
            }
            self.launches.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(FakeCapture {
                stopped: Arc::clone(&self.stops),
                disclosed_at: permit.affirmed_at(),
            }))
        }
    }

    fn session(launcher: CountingLauncher) -> RecorderSession {
        RecorderSession::new(Box::new(launcher), SegmentLog::new())
    }

    #[test]
    fn capture_cannot_start_before_the_disclosure_affirm() {
        let launches = Arc::new(AtomicUsize::new(0));
        let mut recorder = session(CountingLauncher {
            launches: Arc::clone(&launches),
            ..CountingLauncher::default()
        });

        let err = recorder.start().expect_err("the gate must refuse");
        assert!(matches!(err, SessionError::Disclosure(_)));
        assert_eq!(
            launches.load(Ordering::Relaxed),
            0,
            "no capture may even be attempted before the affirm"
        );
        assert!(!recorder.is_recording());
        assert_eq!(recorder.view().menu_bar, copy::MENU_BAR_IDLE);
    }

    #[test]
    fn one_affirm_authorizes_one_recording() {
        let launches = Arc::new(AtomicUsize::new(0));
        let stops = Arc::new(AtomicUsize::new(0));
        let mut recorder = session(CountingLauncher {
            launches: Arc::clone(&launches),
            stops: Arc::clone(&stops),
            refuse: false,
        });

        recorder.affirm(NOW);
        recorder.start().expect("the affirm opens the gate");
        assert!(recorder.is_recording());

        let view = recorder.view();
        assert_eq!(view.menu_bar, copy::MENU_BAR_RECORDING);
        assert_eq!(view.disclosed_at, Some(NOW));
        assert_eq!(view.disclosure, DisclosureState::Required);

        // Stop works while a segment is open, and the next recording needs a
        // fresh disclosure.
        recorder.stop().expect("stop");
        assert_eq!(stops.load(Ordering::Relaxed), 1);
        assert!(!recorder.is_recording());
        assert!(matches!(
            recorder
                .start()
                .expect_err("the gate closed behind the affirm"),
            SessionError::Disclosure(_)
        ));
        assert_eq!(launches.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_capture_that_refuses_to_open_does_not_spend_the_affirm() {
        let mut recorder = session(CountingLauncher {
            refuse: true,
            ..CountingLauncher::default()
        });
        recorder.affirm(NOW);

        let err = recorder.start().expect_err("the microphone refused");
        assert!(matches!(err, SessionError::Capture(_)));
        assert_eq!(
            recorder.view().disclosure,
            DisclosureState::Affirmed,
            "the operator disclosed; a broken microphone is not their doing"
        );
        assert!(!recorder.is_recording());
    }

    #[test]
    fn stopping_nothing_is_refused_and_double_start_is_refused() {
        let mut recorder = session(CountingLauncher::default());
        assert!(matches!(
            recorder.stop().expect_err("nothing to stop"),
            SessionError::NotRecording
        ));

        recorder.affirm(NOW);
        recorder.start().expect("start");
        recorder.affirm(NOW + 1);
        assert!(matches!(
            recorder.start().expect_err("already recording"),
            SessionError::AlreadyRecording
        ));
    }

    #[test]
    fn the_log_lists_what_was_committed_newest_first() {
        struct StubSink;
        impl SegmentSink for StubSink {
            fn commit_segment(&self, _audio: &[u8], _meta: SegmentMeta) -> CaptureResult<EntityId> {
                Ok(EntityId::now())
            }
        }

        let log = SegmentLog::new();
        let sink = LoggingSink::new(StubSink, log.clone());
        for offset in 0..3 {
            sink.commit_segment(
                b"audio",
                SegmentMeta {
                    started_at: NOW + offset,
                    duration_ms: 60_000,
                    aec: AecMode::Bypassed {
                        route: OutputRoute::Headphones,
                    },
                    device: "built-in-microphone".to_owned(),
                    channels: 2,
                },
            )
            .expect("commit");
        }

        let listed = log.recent(SEGMENT_LIST_LIMIT);
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].started_at, NOW + 2);
        assert_eq!(listed[0].aec_mode, "bypassed_headphones");
        assert!(!listed[0].id.is_empty(), "the committed identity is listed");
    }

    #[test]
    fn a_refused_commit_is_not_listed() {
        struct RefusingSink;
        impl SegmentSink for RefusingSink {
            fn commit_segment(&self, _audio: &[u8], _meta: SegmentMeta) -> CaptureResult<EntityId> {
                Err(CaptureError::EmptySegment)
            }
        }

        let log = SegmentLog::new();
        let sink = LoggingSink::new(RefusingSink, log.clone());
        assert!(
            sink.commit_segment(
                b"audio",
                SegmentMeta {
                    started_at: NOW,
                    duration_ms: 0,
                    aec: AecMode::Unavailable,
                    device: "built-in-microphone".to_owned(),
                    channels: 1,
                },
            )
            .is_err()
        );
        assert!(log.recent(SEGMENT_LIST_LIMIT).is_empty());
    }
}
