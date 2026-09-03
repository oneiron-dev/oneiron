//! The running capture: both legs, one worker thread, one cutter.
//!
//! The audio streams are not `Send`, so everything is opened on the worker
//! thread and the handle left behind is just a stop flag and a join handle.
//! `start` waits for the worker to report that recording has actually begun,
//! so the menu bar never shows "Recording" over a capture that failed to open.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::mic::MicStream;
use super::route::RouteSource;
use super::segment::{Frames, SegmentCutter, SegmentSink, SegmentSpec};
use super::{CaptureError, PcmQueue, Result};
use crate::disclosure::CapturePermit;

/// How often the worker moves audio from the callbacks into the cutter.
const TICK: Duration = Duration::from_millis(100);

/// How much unmatched audio one leg may run ahead by before the surplus is
/// dropped. Both legs are clocked by the same aggregate device, so this is a
/// backstop against an unbounded buffer, not a routine path.
const MAX_CARRY_SECONDS: usize = 10;

/// A capture in progress.
pub trait RunningCapture: Send {
    /// Unix second the recording began.
    fn started_at(&self) -> u64;
    /// Unix second of the disclosure affirm that authorized it.
    fn disclosed_at(&self) -> u64;
    /// Ends the recording, committing the segment that was open. Returns
    /// whatever went wrong while it ran.
    ///
    /// # Errors
    ///
    /// The worker's failure, if it had one.
    fn stop(&mut self) -> Result<()>;
}

/// How a session opens a capture.
///
/// The live launcher builds a [`DualStreamCapture`]; the seam exists so the
/// disclosure gate can be proven end to end without a microphone.
pub trait CaptureLauncher: Send + Sync {
    /// Starts recording. Taking the permit **by value** is the gate: there is
    /// no other way to reach this call.
    ///
    /// # Errors
    ///
    /// Whatever stopped the capture from opening.
    fn launch(&self, permit: CapturePermit) -> Result<Box<dyn RunningCapture>>;
}

/// The live launcher: microphone plus system-audio tap, committing to `sink`.
pub struct LiveCapture {
    sink: Arc<dyn SegmentSink>,
    route: Arc<dyn RouteSource>,
}

impl LiveCapture {
    /// A launcher that commits to `sink` and reads the route from `route`.
    #[must_use]
    pub fn new(sink: Arc<dyn SegmentSink>, route: Arc<dyn RouteSource>) -> Self {
        Self { sink, route }
    }
}

impl CaptureLauncher for LiveCapture {
    fn launch(&self, permit: CapturePermit) -> Result<Box<dyn RunningCapture>> {
        let capture =
            DualStreamCapture::start(permit, Arc::clone(&self.sink), Arc::clone(&self.route))?;
        Ok(Box::new(capture))
    }
}

/// Microphone and far end, cut into segments.
pub struct DualStreamCapture {
    started_at: u64,
    disclosed_at: u64,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl DualStreamCapture {
    /// Opens both legs and starts committing segments to `sink`.
    ///
    /// # Errors
    ///
    /// Whatever stopped the microphone from opening. A missing system-audio
    /// tap is **not** one of them: the far-end leg is dropped and the capture
    /// runs microphone-only rather than refusing to record.
    pub fn start(
        permit: CapturePermit,
        sink: Arc<dyn SegmentSink>,
        route: Arc<dyn RouteSource>,
    ) -> Result<Self> {
        let disclosed_at = permit.affirmed_at();
        let started_at = now_unix();
        let running = Arc::new(AtomicBool::new(true));
        let (ready_tx, ready_rx) = mpsc::channel();

        let worker = thread::spawn({
            let running = Arc::clone(&running);
            move || {
                record(
                    &running,
                    &ready_tx,
                    sink.as_ref(),
                    route.as_ref(),
                    started_at,
                )
            }
        });

        if ready_rx.recv().is_err() {
            // The worker never reached "recording"; its return value says why.
            return match worker.join() {
                Ok(outcome) => outcome.and(Err(CaptureError::Audio(
                    "capture ended before it started".to_owned(),
                ))),
                Err(_) => Err(CaptureError::Audio("capture worker panicked".to_owned())),
            };
        }

        Ok(Self {
            started_at,
            disclosed_at,
            running,
            worker: Some(worker),
        })
    }
}

impl RunningCapture for DualStreamCapture {
    fn started_at(&self) -> u64 {
        self.started_at
    }

    fn disclosed_at(&self) -> u64 {
        self.disclosed_at
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::Relaxed);
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .unwrap_or_else(|_| Err(CaptureError::Audio("capture worker panicked".to_owned()))),
            None => Ok(()),
        }
    }
}

impl Drop for DualStreamCapture {
    fn drop(&mut self) {
        // A dropped handle must not leave a recording running behind it.
        let _ = self.stop();
    }
}

/// The far-end leg, when this host has one.
///
/// System-audio capture is a macOS process-tap facility. Everywhere else
/// `open` says so plainly and the capture runs microphone-only.
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "the far-end leg only exists on macOS")
)]
struct FarEndLeg {
    /// Held for its lifetime: dropping it tears the tap down.
    #[cfg(target_os = "macos")]
    _tap: super::tap::SystemAudioTap,
    queue: PcmQueue,
    sample_rate: u32,
}

impl FarEndLeg {
    #[cfg(target_os = "macos")]
    fn open() -> Result<Self> {
        let queue = PcmQueue::new();
        let tap = super::tap::SystemAudioTap::start(queue.clone())?;
        let sample_rate = tap.sample_rate();
        Ok(Self {
            _tap: tap,
            queue,
            sample_rate,
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn open() -> Result<Self> {
        Err(CaptureError::NoSystemAudioTap)
    }
}

/// Opens both legs and runs until `running` goes false.
///
/// The far end rides along only when it is present **and** clocked at the
/// microphone's rate: with no resampler in this tree, aligning two different
/// rates by frame count would be a fiction, and a fictional alignment is worse
/// than an honest mono segment.
fn record(
    running: &AtomicBool,
    ready: &mpsc::Sender<()>,
    sink: &dyn SegmentSink,
    route: &dyn RouteSource,
    started_at: u64,
) -> Result<()> {
    let mic_queue = PcmQueue::new();
    let mic = MicStream::open(mic_queue.clone())?;
    let far = match FarEndLeg::open() {
        Ok(far) if far.sample_rate == mic.sample_rate() => Some(far),
        Ok(_) | Err(_) => None,
    };

    let spec = SegmentSpec::new(mic.sample_rate(), mic.device().to_owned());
    let max_carry = spec.sample_rate as usize * MAX_CARRY_SECONDS;
    let mut cutter = SegmentCutter::new(spec);
    let mut mic_carry: Vec<i16> = Vec::new();
    let mut far_carry: Vec<i16> = Vec::new();

    // Recording has begun; the handle may now honestly say so.
    if ready.send(()).is_err() {
        return Ok(());
    }

    let mut outcome = Ok(());
    while running.load(Ordering::Relaxed) {
        thread::sleep(TICK);
        if let Some(fault) = mic.fault() {
            outcome = Err(CaptureError::Audio(fault));
            break;
        }
        mic_carry.extend(mic_queue.drain());
        if let Some(far) = far.as_ref() {
            far_carry.extend(far.queue.drain());
        }
        trim_carry(&mut mic_carry, max_carry);
        trim_carry(&mut far_carry, max_carry);

        let paired = far.is_some();
        let take = if paired {
            mic_carry.len().min(far_carry.len())
        } else {
            mic_carry.len()
        };
        if take == 0 {
            continue;
        }
        let frames = Frames {
            mic: &mic_carry[..take],
            far: paired.then(|| &far_carry[..take]),
        };
        if let Err(err) = cutter.push(frames, started_at, route.output_route(), sink) {
            outcome = Err(err);
            break;
        }
        mic_carry.drain(..take);
        if paired {
            far_carry.drain(..take);
        }
    }

    // The segment that was open when stop arrived is committed, not discarded.
    let flushed = cutter.flush(sink);
    outcome.and(flushed.map(|_| ()))
}

/// Drops the oldest surplus when one leg has run far ahead of the other.
fn trim_carry(carry: &mut Vec<i16>, max: usize) {
    if max > 0 && carry.len() > max {
        carry.drain(..carry.len() - max);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
