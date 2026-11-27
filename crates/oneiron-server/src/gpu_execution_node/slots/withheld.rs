//! The withheld list's reader. One long-lived thread per slot table reads
//! `[gpu_jobs.devices].withheld_file`, and each ask waits for a read that
//! starts after the ask, for at most [`WITHHELD_READ_TIMEOUT`]. An open on a
//! hard network mount whose server is lost blocks however it is flagged,
//! so the read runs off the asking thread (the node tick, placement, a
//! lease): an ask with no answer in time reads as unreadable, so nothing
//! is offered and readiness fails its device step. While that read has
//! still not returned, later asks answer the same at once and start no
//! other read. The thread ends once its table is dropped and its read in
//! flight has returned.

use std::collections::BTreeSet;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::GpuProbeError;

/// The longest an ask waits for one read of the withheld list before it
/// counts as unreadable, so a lost mount never holds the tick or the table.
/// A local file reads in well under a millisecond; the driver query's own
/// bound is [`GPU_QUERY_TIMEOUT`](super::super::device::GPU_QUERY_TIMEOUT), 10 s.
pub(crate) const WITHHELD_READ_TIMEOUT: Duration = Duration::from_secs(2);

type WithheldSource = Box<dyn Fn() -> Result<BTreeSet<String>, String> + Send + Sync>;

pub(super) struct WithheldListReader {
    shared: Arc<ReaderShared>,
    timeout: Duration,
}

struct ReaderShared {
    path: PathBuf,
    source: WithheldSource,
    progress: Mutex<ReadProgress>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct ReadProgress {
    /// Reads asked so far; ask n is answered by a read that starts after it.
    asked: u64,
    /// The newest ask the read in flight (or the last read) serves.
    started: u64,
    /// The newest ask answered.
    answered: u64,
    /// The newest read's answer.
    answer: Option<Result<BTreeSet<String>, String>>,
    /// A read is in flight.
    reading: bool,
    /// An ask gave up waiting (on the read in flight, or on one not yet
    /// started): asks made while a read runs answer at once, until one
    /// returns.
    overdue: bool,
    /// The reader thread runs.
    thread_running: bool,
    /// The table is dropped: the thread ends after its read in flight.
    closed: bool,
}

impl std::fmt::Debug for WithheldListReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithheldListReader")
            .field("path", &self.shared.path)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

fn lock(shared: &ReaderShared) -> MutexGuard<'_, ReadProgress> {
    shared
        .progress
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

impl WithheldListReader {
    pub(super) fn new(path: PathBuf) -> Self {
        Self::with_source(
            path.clone(),
            WITHHELD_READ_TIMEOUT,
            Box::new(move || read_withheld_file(&path)),
        )
    }

    fn with_source(path: PathBuf, timeout: Duration, source: WithheldSource) -> Self {
        Self {
            shared: Arc::new(ReaderShared {
                path,
                source,
                progress: Mutex::default(),
                changed: Condvar::new(),
            }),
            timeout,
        }
    }

    pub(super) fn read(&self) -> Result<BTreeSet<String>, GpuProbeError> {
        self.read_within(self.timeout)
    }

    fn read_within(&self, timeout: Duration) -> Result<BTreeSet<String>, GpuProbeError> {
        let shared = &self.shared;
        let mut progress = lock(shared);
        if progress.reading && progress.overdue {
            return Err(unreadable(format!(
                "{}: an earlier read has not returned",
                shared.path.display()
            )));
        }
        if !progress.thread_running {
            let worker = Arc::clone(shared);
            if let Err(error) = std::thread::Builder::new()
                .name("gpu-withheld-reader".to_owned())
                .spawn(move || run_reader(&worker))
            {
                return Err(unreadable(format!(
                    "{}: the reader thread could not start: {error}",
                    shared.path.display()
                )));
            }
            progress.thread_running = true;
        }
        progress.asked = progress.asked.saturating_add(1);
        let ask = progress.asked;
        shared.changed.notify_all();
        let (mut progress, _) = shared
            .changed
            .wait_timeout_while(progress, timeout, |progress| progress.answered < ask)
            .unwrap_or_else(PoisonError::into_inner);
        if progress.answered >= ask {
            return match progress.answer.clone() {
                Some(Ok(withheld)) => Ok(withheld),
                Some(Err(reason)) => Err(unreadable(reason)),
                None => Err(unreadable(format!(
                    "{}: the read gave no answer",
                    shared.path.display()
                ))),
            };
        }
        // Unanswered in time: a read runs and is slow, or the reader has not
        // started this ask's read yet; either way the read that serves it is
        // overdue.
        progress.overdue = true;
        Err(unreadable(format!(
            "{}: no answer within {} ms",
            shared.path.display(),
            timeout.as_millis()
        )))
    }

    #[cfg(test)]
    fn wait_until(&self, done: impl Fn(&ReadProgress) -> bool) -> bool {
        let shared = &self.shared;
        let (progress, _) = shared
            .changed
            .wait_timeout_while(lock(shared), Duration::from_secs(10), |p| !done(p))
            .unwrap_or_else(PoisonError::into_inner);
        done(&progress)
    }
}

impl Drop for WithheldListReader {
    fn drop(&mut self) {
        let mut progress = lock(&self.shared);
        progress.closed = true;
        self.shared.changed.notify_all();
    }
}

fn run_reader(shared: &ReaderShared) {
    let mut progress = lock(shared);
    loop {
        progress = shared
            .changed
            .wait_while(progress, |progress| {
                !progress.closed && progress.started >= progress.asked
            })
            .unwrap_or_else(PoisonError::into_inner);
        if progress.closed {
            progress.thread_running = false;
            return;
        }
        progress.started = progress.asked;
        let serving = progress.started;
        progress.reading = true;
        shared.changed.notify_all();
        drop(progress);
        let answer = catch_unwind(AssertUnwindSafe(|| (shared.source)()))
            .unwrap_or_else(|_| Err(format!("{}: the read panicked", shared.path.display())));
        progress = lock(shared);
        progress.answered = serving;
        progress.answer = Some(answer);
        progress.reading = false;
        progress.overdue = false;
        shared.changed.notify_all();
    }
}

fn unreadable(reason: String) -> GpuProbeError {
    GpuProbeError::WithheldUnreadable { reason }
}

fn read_withheld_file(path: &Path) -> Result<BTreeSet<String>, String> {
    let unreadable = |error| format!("{}: {error}", path.display());
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.file_type().is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(unreadable)?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::super::{GpuDeviceOffer, GpuSlotRefusal, GpuSlotTable, Shared};
    use super::{
        Arc, BTreeSet, Duration, GpuProbeError, Mutex, PoisonError, WithheldListReader,
        WithheldSource,
    };
    use crate::gpu_execution_node::device::{GpuComputeProcess, GpuDevice, GpuDeviceProbe};

    const LOST: &str = "/lost-mount/gpu-withheld";
    const T0: u64 = 1_800_000_000_000;

    struct BlockingSource {
        started: mpsc::Receiver<()>,
        answers: mpsc::Sender<Result<BTreeSet<String>, String>>,
    }

    fn blocking_source() -> (WithheldSource, BlockingSource) {
        let (started_tx, started) = mpsc::channel();
        let (answers, answers_rx) = mpsc::channel();
        let answers_rx = Mutex::new(answers_rx);
        let source = Box::new(move || {
            let _ = started_tx.send(());
            answers_rx
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv()
                .unwrap_or_else(|_| Err("source closed".to_owned()))
        });
        (source, BlockingSource { started, answers })
    }

    fn ask(
        reader: &Arc<WithheldListReader>,
        timeout: Duration,
    ) -> mpsc::Receiver<Result<BTreeSet<String>, GpuProbeError>> {
        let (tx, rx) = mpsc::channel();
        let reader = Arc::clone(reader);
        let _ = std::thread::spawn(move || {
            let _ = tx.send(reader.read_within(timeout));
        });
        rx
    }

    fn answered(
        rx: &mpsc::Receiver<Result<BTreeSet<String>, GpuProbeError>>,
    ) -> Result<BTreeSet<String>, GpuProbeError> {
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the ask answered within 10 s")
    }

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().copied().map(str::to_owned).collect()
    }

    fn reason_of(result: Result<BTreeSet<String>, GpuProbeError>) -> String {
        match result {
            Err(GpuProbeError::WithheldUnreadable { reason }) => reason,
            other => panic!("expected WithheldUnreadable, got {other:?}"),
        }
    }

    #[test]
    fn a_read_that_never_returns_answers_unreadable_within_the_timeout_then_at_once() {
        let (source, blocking) = blocking_source();
        let reader = Arc::new(WithheldListReader::with_source(
            LOST.into(),
            Duration::from_millis(100),
            source,
        ));
        let first = ask(&reader, Duration::from_millis(100));
        assert_eq!(
            reason_of(answered(&first)),
            "/lost-mount/gpu-withheld: no answer within 100 ms"
        );
        // The read runs (and never returns): a later ask, even one willing to
        // wait 60 s, answers at once and starts no other read.
        blocking
            .started
            .recv_timeout(Duration::from_secs(10))
            .expect("the read started");
        let next = ask(&reader, Duration::from_secs(60));
        assert_eq!(
            reason_of(answered(&next)),
            "/lost-mount/gpu-withheld: an earlier read has not returned"
        );
        assert_eq!(blocking.started.try_recv(), Err(mpsc::TryRecvError::Empty));
    }

    #[test]
    fn a_read_that_returns_late_lets_the_next_ask_read_afresh() {
        let (source, blocking) = blocking_source();
        let reader = Arc::new(WithheldListReader::with_source(
            LOST.into(),
            Duration::from_millis(100),
            source,
        ));
        let first = ask(&reader, Duration::from_millis(100));
        assert_eq!(
            reason_of(answered(&first)),
            "/lost-mount/gpu-withheld: no answer within 100 ms"
        );
        blocking.answers.send(Ok(set(&["GPU-late"]))).unwrap();
        assert!(reader.wait_until(|p| !p.reading && p.answer.is_some()));
        blocking.answers.send(Ok(set(&["GPU-fresh"]))).unwrap();
        let next = ask(&reader, Duration::from_secs(10));
        assert_eq!(answered(&next), Ok(set(&["GPU-fresh"])));
    }

    #[test]
    fn an_ask_made_during_a_read_waits_for_a_read_that_starts_after_it() {
        let (source, blocking) = blocking_source();
        let reader = Arc::new(WithheldListReader::with_source(
            LOST.into(),
            Duration::from_secs(10),
            source,
        ));
        let a = ask(&reader, Duration::from_secs(10));
        blocking
            .started
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        let b = ask(&reader, Duration::from_secs(10));
        assert!(reader.wait_until(|p| p.asked >= 2));
        blocking.answers.send(Ok(set(&["first"]))).unwrap();
        assert_eq!(answered(&a), Ok(set(&["first"])));
        // Let A take the first answer before the reader replaces it.
        blocking.answers.send(Ok(set(&["second"]))).unwrap();
        assert_eq!(answered(&b), Ok(set(&["second"])));
        assert_eq!(blocking.started.try_recv(), Ok(()));
        assert_eq!(blocking.started.try_recv(), Err(mpsc::TryRecvError::Empty));
    }

    struct OneGpu;

    impl GpuDeviceProbe for OneGpu {
        fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError> {
            Ok(vec![GpuDevice {
                device_id: "GPU-aaaa".into(),
                model: "NVIDIA RTX A4000".into(),
                memory_total_mib: 16_376,
            }])
        }

        fn compute_processes(&self) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn a_withheld_list_that_never_answers_offers_nothing_and_the_table_answers_in_time() {
        let (source, blocking) = blocking_source();
        // The answers stay open to the test's end, so the read never returns.
        let BlockingSource {
            started,
            answers: _answers,
        } = blocking;
        let table = Arc::new(GpuSlotTable {
            shared: Arc::new(Shared {
                probe: Arc::new(OneGpu),
                offer: GpuDeviceOffer {
                    offered: set(&["GPU-aaaa"]),
                    withheld_file: Some(LOST.into()),
                    ..GpuDeviceOffer::default()
                },
                disk: None,
                withheld: Some(WithheldListReader::with_source(
                    LOST.into(),
                    Duration::from_millis(100),
                    source,
                )),
                state: Mutex::default(),
            }),
        });
        let (tx, rx) = mpsc::channel();
        let _ = std::thread::spawn(move || {
            let availability = table.availability(T0);
            let read_runs = started.recv_timeout(Duration::from_secs(10)).is_ok();
            let held = table.held_devices(T0);
            #[cfg(unix)]
            let booker = Some(table.booker_withheld());
            #[cfg(not(unix))]
            let booker = None;
            let _ = tx.send((availability, read_runs, held, booker));
        });
        let (availability, read_runs, held, booker) = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the table answered within 20 s");
        assert!(read_runs, "the withheld read started");
        match availability {
            Err(GpuProbeError::WithheldUnreadable { reason }) => {
                assert_eq!(reason, "/lost-mount/gpu-withheld: no answer within 100 ms");
            }
            other => panic!("expected WithheldUnreadable, got {other:?}"),
        }
        match held {
            Err(GpuSlotRefusal::Unmeasured { reason }) => {
                assert!(reason.contains("gpu_probe.withheld_unreadable"), "{reason}");
                assert!(
                    reason.contains("an earlier read has not returned"),
                    "{reason}"
                );
            }
            other => panic!("expected Unmeasured, got {other:?}"),
        }
        if let Some(booker) = booker {
            assert_eq!(
                reason_of(booker),
                "/lost-mount/gpu-withheld: an earlier read has not returned"
            );
        }
    }
}
