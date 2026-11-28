//! The withheld list's reader. One long-lived thread per withheld path reads
//! `[gpu_jobs.devices].withheld_file`, and each ask waits for a read that
//! starts after the ask, for at most [`WITHHELD_READ_TIMEOUT`]. An open on a
//! hard network mount whose server is lost blocks however it is flagged,
//! so the read runs off the asking thread (the node tick, placement, a
//! lease): an ask with no answer in time reads as unreadable, so nothing
//! is offered and readiness fails its device step. While that read has
//! still not returned, later asks answer the same at once and start no
//! other read. Every slot table built for one path holds the same reader,
//! so a table built again after an embedded stop and wake takes the read
//! its predecessor left stuck and never starts a second thread beside it
//! (review round 1 of #10610). The thread ends once no table holds its
//! reader and its read in flight has returned.
//!
//! An ask takes only an answer its read published by the ask's own
//! deadline, however late the asker wakes, and each published answer is
//! kept while an ask it serves still waits, so a later read never replaces
//! it (review round 2 of #10610).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

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
    /// The published answers an ask still waiting can take, in the order
    /// the reader published them (ascending `serving`).
    answers: VecDeque<Published>,
    /// The asks still waiting for an answer.
    waiting: BTreeSet<u64>,
    /// A read is in flight.
    reading: bool,
    /// An ask gave up waiting (on the read in flight, or on one not yet
    /// started): asks made while a read runs answer at once, until one
    /// returns.
    overdue: bool,
    /// The reader thread runs.
    thread_running: bool,
    /// The slot tables holding this reader. At none, the thread ends after
    /// its read in flight.
    holders: usize,
}

/// One read's answer, kept while an ask it serves still waits.
#[derive(Debug)]
struct Published {
    /// The newest ask the read serves: it started after every ask up to
    /// this one.
    serving: u64,
    /// When the reader published it.
    at: Instant,
    answer: Result<BTreeSet<String>, String>,
}

/// What one ask takes when it stops waiting.
#[derive(Debug, PartialEq, Eq)]
enum Taken {
    /// The answer of the read that serves it, published by its deadline.
    Answer(Result<BTreeSet<String>, String>),
    /// The read that serves it published after its deadline.
    Late,
    /// No read that serves it has published.
    Unanswered,
}

impl ReadProgress {
    /// The first published read that serves `ask`: one that started after it.
    fn serving(&self, ask: u64) -> Option<&Published> {
        self.answers
            .iter()
            .find(|published| published.serving >= ask)
    }

    /// What `ask` takes, by its `deadline` (`None`: no deadline), as it
    /// stops waiting; the answers no other waiting ask can take go.
    fn take(&mut self, ask: u64, deadline: Option<Instant>) -> Taken {
        let taken = match self.serving(ask) {
            Some(published) if deadline.is_none_or(|deadline| published.at <= deadline) => {
                Taken::Answer(published.answer.clone())
            }
            Some(_) => Taken::Late,
            None => Taken::Unanswered,
        };
        self.waiting.remove(&ask);
        self.prune();
        taken
    }

    /// Drops each kept answer no waiting ask can take any more. An ask takes
    /// the first answer whose `serving` reaches it, so an answer is kept for
    /// the waiting asks after the one before it, up to its own `serving`;
    /// an ask made later takes only a read that starts after it.
    fn prune(&mut self) {
        let waiting = &self.waiting;
        let mut after: u64 = 0;
        self.answers.retain(|published| {
            let first = after.saturating_add(1);
            let kept = first <= published.serving
                && waiting.range(first..=published.serving).next().is_some();
            after = published.serving;
            kept
        });
    }
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

impl ReaderShared {
    fn new(path: PathBuf, source: WithheldSource) -> Self {
        Self {
            path,
            source,
            progress: Mutex::default(),
            changed: Condvar::new(),
        }
    }
}

impl WithheldListReader {
    pub(super) fn new(path: PathBuf) -> Self {
        Self::registered(path, WITHHELD_READ_TIMEOUT, |path| {
            let path = path.to_path_buf();
            Box::new(move || read_withheld_file(&path))
        })
    }

    /// The process's one reader of `path`, built with `source` only when no
    /// table holds one and no read of it is in flight. A table built again
    /// for the path (an embedded stop and wake builds a new slot table)
    /// takes the reader its predecessor left, with any read still stuck on a
    /// lost mount, so it answers at once and starts no second thread.
    fn registered(
        path: PathBuf,
        timeout: Duration,
        source: impl FnOnce(&Path) -> WithheldSource,
    ) -> Self {
        static READERS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<ReaderShared>>>> = OnceLock::new();
        let mut readers = READERS
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        readers.retain(|_, reader| reader.strong_count() > 0);
        let shared = match readers.get(&path).and_then(Weak::upgrade) {
            Some(shared) => shared,
            None => {
                let shared = Arc::new(ReaderShared::new(path.clone(), source(path.as_path())));
                readers.insert(path, Arc::downgrade(&shared));
                shared
            }
        };
        drop(readers);
        Self::holding(shared, timeout)
    }

    #[cfg(test)]
    fn with_source(path: PathBuf, timeout: Duration, source: WithheldSource) -> Self {
        Self::holding(Arc::new(ReaderShared::new(path, source)), timeout)
    }

    fn holding(shared: Arc<ReaderShared>, timeout: Duration) -> Self {
        let mut progress = lock(&shared);
        progress.holders = progress.holders.saturating_add(1);
        drop(progress);
        Self { shared, timeout }
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
        // The ask's own deadline: an answer published after it never answers
        // this ask, even when the asker wakes after the reader publishes.
        let deadline = Instant::now().checked_add(timeout);
        progress.asked = progress.asked.saturating_add(1);
        let ask = progress.asked;
        progress.waiting.insert(ask);
        shared.changed.notify_all();
        let (mut progress, _) = shared
            .changed
            .wait_timeout_while(progress, timeout, |progress| {
                progress.serving(ask).is_none()
            })
            .unwrap_or_else(PoisonError::into_inner);
        let no_answer = || {
            unreadable(format!(
                "{}: no answer within {} ms",
                shared.path.display(),
                timeout.as_millis()
            ))
        };
        match progress.take(ask, deadline) {
            Taken::Answer(Ok(withheld)) => Ok(withheld),
            Taken::Answer(Err(reason)) => Err(unreadable(reason)),
            // Its read returned, after this ask's deadline: no read is
            // overdue.
            Taken::Late => Err(no_answer()),
            Taken::Unanswered => {
                // Unanswered in time: a read runs and is slow, or the reader
                // has not started this ask's read yet; either way the read
                // that serves it is overdue.
                progress.overdue = true;
                Err(no_answer())
            }
        }
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
        progress.holders = progress.holders.saturating_sub(1);
        self.shared.changed.notify_all();
    }
}

fn run_reader(shared: &ReaderShared) {
    let mut progress = lock(shared);
    loop {
        progress = shared
            .changed
            .wait_while(progress, |progress| {
                progress.holders > 0 && progress.started >= progress.asked
            })
            .unwrap_or_else(PoisonError::into_inner);
        if progress.holders == 0 {
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
        progress.answers.push_back(Published {
            serving,
            at: Instant::now(),
            answer,
        });
        progress.prune();
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
        Arc, BTreeSet, Duration, GpuProbeError, Instant, Mutex, PoisonError, Published,
        ReadProgress, Taken, WithheldListReader, WithheldSource,
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
        assert!(reader.wait_until(|p| !p.reading && p.started >= 1));
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

    /// Asks `waiting` and the answers published at `at_ms` after `t0`, each
    /// serving the ask named beside it.
    fn progress(t0: Instant, waiting: &[u64], published: &[(u64, u64, &str)]) -> ReadProgress {
        ReadProgress {
            waiting: waiting.iter().copied().collect(),
            answers: published
                .iter()
                .map(|&(serving, at_ms, id)| Published {
                    serving,
                    at: t0 + Duration::from_millis(at_ms),
                    answer: Ok(set(&[id])),
                })
                .collect(),
            ..ReadProgress::default()
        }
    }

    #[test]
    fn an_answer_published_after_an_asks_deadline_never_answers_it() {
        // The ask's 2 s ran out; the reader published 10 ms later, before the
        // asker took the lock again (review round 2 of #10610).
        // testkit-lint: allow(wall-clock) an origin for the instants below; nothing waits on it
        let t0 = Instant::now();
        let mut late = progress(t0, &[1], &[(1, 2_010, "GPU-late")]);
        assert_eq!(
            late.take(1, Some(t0 + Duration::from_secs(2))),
            Taken::Late,
            "an answer published after the deadline is late, never taken as the list"
        );
        assert!(late.answers.is_empty(), "no waiting ask keeps it");
        let mut timely = progress(t0, &[1], &[(1, 1_990, "GPU-held")]);
        assert_eq!(
            timely.take(1, Some(t0 + Duration::from_secs(2))),
            Taken::Answer(Ok(set(&["GPU-held"]))),
            "an answer published by the deadline answers"
        );
        assert_eq!(
            progress(t0, &[2], &[(1, 10, "old")]).take(2, Some(t0 + Duration::from_secs(2))),
            Taken::Unanswered,
            "a read that started before the ask never answers it"
        );
    }

    #[test]
    fn a_later_read_never_replaces_an_answer_a_waiting_ask_can_take() {
        // testkit-lint: allow(wall-clock) an origin for the instants below; nothing waits on it
        let t0 = Instant::now();
        // Ask 1's read published in time; ask 2's read published after ask
        // 1's deadline, before ask 1 woke.
        let mut both = progress(t0, &[1, 2], &[(1, 1_900, "first"), (2, 2_050, "second")]);
        assert_eq!(
            both.take(1, Some(t0 + Duration::from_secs(2))),
            Taken::Answer(Ok(set(&["first"]))),
            "ask 1 takes its own timely answer"
        );
        assert_eq!(
            both.answers.iter().map(|p| p.serving).collect::<Vec<_>>(),
            [2],
            "ask 1's answer goes; ask 2's stays for it"
        );
        assert_eq!(
            both.take(2, Some(t0 + Duration::from_secs(3))),
            Taken::Answer(Ok(set(&["second"]))),
            "ask 2 takes the read that started after it"
        );
        assert!(both.answers.is_empty(), "nothing waits");
    }

    #[test]
    fn a_reader_built_again_for_a_path_whose_read_is_stuck_starts_no_other_read() {
        const REBUILT: &str = "/lost-mount/gpu-withheld-rebuilt";
        let (source, blocking) = blocking_source();
        // The answers stay open to the test's end, so the read never returns.
        let BlockingSource {
            started,
            answers: _answers,
        } = blocking;
        let first = Arc::new(WithheldListReader::registered(
            REBUILT.into(),
            Duration::from_millis(100),
            |_| source,
        ));
        assert_eq!(
            reason_of(answered(&ask(&first, Duration::from_millis(100)))),
            format!("{REBUILT}: no answer within 100 ms")
        );
        started
            .recv_timeout(Duration::from_secs(10))
            .expect("the read started");
        // The table is dropped (an embedded stop) and built again (its wake).
        drop(first);
        let (again, unused) = blocking_source();
        let second = Arc::new(WithheldListReader::registered(
            REBUILT.into(),
            Duration::from_millis(100),
            |_| again,
        ));
        assert!(
            second.wait_until(|p| p.holders == 1),
            "the first table let go of the reader"
        );
        // Willing to wait 60 s, it answers at once: the stuck read is its own.
        let next = ask(&second, Duration::from_secs(60));
        assert_eq!(
            reason_of(answered(&next)),
            format!("{REBUILT}: an earlier read has not returned")
        );
        assert_eq!(started.try_recv(), Err(mpsc::TryRecvError::Empty));
        assert_eq!(unused.started.try_recv(), Err(mpsc::TryRecvError::Empty));
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
