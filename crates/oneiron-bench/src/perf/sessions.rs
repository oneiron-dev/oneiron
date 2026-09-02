//! ONE-1579 axis 3: the concurrent-session curve against ONE vault.
//!
//! The point of a 100- or 300-session row is that a hundred or three hundred
//! sessions were actually IN FLIGHT AT ONCE. Letting each worker start
//! querying the moment its thread exists does not measure that: with short
//! text queries the first workers can finish before the last ones are created,
//! so the row would report a staggered ramp plus the serial cost of creating
//! threads.
//!
//! Every worker is therefore created first and parked at a [`ReleaseGate`].
//! The parent opens the measurement window only once all of them have arrived,
//! and thread creation is reported beside the window as `spawn_ms` rather than
//! inside it. A point that could not assemble its full cohort says so through
//! `synchronized: false` instead of quietly reporting a smaller run.

use std::sync::{Condvar, Mutex, PoisonError};
use std::thread::{Builder, Result as ThreadResult};
use std::time::{Duration, Instant};

use oneiron::Vault;

use super::axes::SessionCurvePoint;
use super::cells::{Cell, Percentiles};
use super::corpus::Corpus;

/// How long the parent waits for every worker to reach the gate before it
/// releases whoever arrived and marks the point unsynchronized.
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Default)]
struct GateState {
    arrived: usize,
    released: bool,
}

/// A one-shot rendezvous: workers announce arrival and park; the parent waits
/// for the cohort and then releases every one of them at once.
///
/// Unlike a fixed-party barrier this cannot deadlock when a thread fails to
/// spawn — the parent decides how many it is waiting for, and gives up on a
/// deadline rather than blocking forever.
pub(crate) struct ReleaseGate {
    state: Mutex<GateState>,
    arrived: Condvar,
    released: Condvar,
}

impl ReleaseGate {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            arrived: Condvar::new(),
            released: Condvar::new(),
        }
    }

    /// Worker side: announce arrival, then block until the parent releases.
    pub(crate) fn arrive_and_wait(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.arrived += 1;
        self.arrived.notify_all();
        while !state.released {
            state = self
                .released
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Parent side: wait for `workers` arrivals, capture the measurement start
    /// while still holding the gate mutex, then release everyone at once.
    ///
    /// Capturing the instant AFTER this method returned would race the workers:
    /// once the mutex is released, a short query can start or even finish before
    /// the parent takes its timestamp, understating wall time and inflating QPS.
    pub(crate) fn release_all(&self, workers: usize, timeout: Duration) -> GateRelease {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let wait_started = Instant::now();
        let deadline = wait_started.checked_add(timeout);
        while state.arrived < workers {
            let Some(remaining) =
                deadline.and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            else {
                break;
            };
            let (guard, _) = self
                .arrived
                .wait_timeout(state, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            state = guard;
        }
        let release = GateRelease {
            arrived: state.arrived,
            window_started: Instant::now(),
        };
        state.released = true;
        self.released.notify_all();
        release
    }
}

/// Facts captured atomically with opening the worker gate. Workers cannot pass
/// `arrive_and_wait` before `window_started` because the parent still owns the
/// same mutex while this value is made.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GateRelease {
    pub(crate) arrived: usize,
    pub(crate) window_started: Instant,
}

/// One synchronized run: what every worker returned, plus the spawn cost that
/// was deliberately kept OUT of the measurement window.
pub(crate) struct SynchronizedRun<T> {
    pub(crate) results: Vec<ThreadResult<T>>,
    pub(crate) workers_released: usize,
    pub(crate) synchronized: bool,
    pub(crate) spawn_ms: f64,
    pub(crate) window_ms: f64,
    pub(crate) spawn_errors: Vec<String>,
}

/// Creates `workers` threads, holds every one of them at a release gate, and
/// times only the window that opens once the whole cohort has arrived.
pub(crate) fn run_synchronized<T, F>(workers: usize, work: F) -> SynchronizedRun<T>
where
    F: Fn(usize) -> T + Sync,
    T: Send,
{
    let gate = ReleaseGate::new();
    std::thread::scope(|scope| {
        let mut spawn_errors = Vec::new();
        let mut handles = Vec::with_capacity(workers);
        let spawn_started = Instant::now();
        for index in 0..workers {
            let gate = &gate;
            let work = &work;
            match Builder::new().spawn_scoped(scope, move || {
                gate.arrive_and_wait();
                work(index)
            }) {
                Ok(handle) => handles.push(handle),
                Err(error) => spawn_errors.push(format!(
                    "session worker {index} could not be spawned: {error}"
                )),
            }
        }
        let spawn_ms = spawn_started.elapsed().as_secs_f64() * 1e3;

        let expected = handles.len();
        let release = gate.release_all(expected, RENDEZVOUS_TIMEOUT);
        let mut results: Vec<ThreadResult<T>> = Vec::with_capacity(expected);
        for handle in handles {
            results.push(handle.join());
        }
        let window_ms = release.window_started.elapsed().as_secs_f64() * 1e3;

        SynchronizedRun {
            results,
            workers_released: release.arrived,
            synchronized: release.arrived == workers && spawn_errors.is_empty(),
            spawn_ms,
            window_ms,
            spawn_errors,
        }
    })
}

#[derive(Default)]
struct SessionOutcome {
    latency_ms: Vec<f64>,
    errors: usize,
}

/// Walks `curve`, running `sessions` concurrent readers against ONE vault.
pub(crate) fn measure_session_curve(
    vault: &Vault,
    corpus: &Corpus,
    k: usize,
    curve: &[usize],
    queries_per_session: usize,
) -> Vec<SessionCurvePoint> {
    curve
        .iter()
        .map(|sessions| session_point(vault, corpus, k, *sessions, queries_per_session))
        .collect()
}

fn session_point(
    vault: &Vault,
    corpus: &Corpus,
    k: usize,
    sessions: usize,
    queries_per_session: usize,
) -> SessionCurvePoint {
    let run = run_synchronized(sessions, |session| {
        session_worker(vault, corpus, k, queries_per_session, session)
    });

    let mut latency_ms = Vec::with_capacity(sessions * queries_per_session);
    let mut errors = run.spawn_errors.len() * queries_per_session;
    for outcome in run.results {
        match outcome {
            Ok(outcome) => {
                latency_ms.extend_from_slice(&outcome.latency_ms);
                errors += outcome.errors;
            }
            Err(_) => errors += queries_per_session,
        }
    }
    let completed = latency_ms.len();
    let wall_clock_ms = run.window_ms;
    SessionCurvePoint {
        sessions,
        workers_released: run.workers_released,
        synchronized: run.synchronized,
        queries: completed,
        spawn_ms: run.spawn_ms,
        wall_clock_ms,
        latency_ms: Cell::from_option(
            Percentiles::from_samples(&latency_ms),
            format!("no query completed at {sessions} concurrent session(s)"),
        ),
        throughput_qps: if wall_clock_ms > 0.0 && completed > 0 {
            Cell::measured(completed as f64 / (wall_clock_ms / 1e3))
        } else {
            Cell::not_ready(format!(
                "no completed query at {sessions} concurrent session(s) to derive throughput from"
            ))
        },
        errors,
    }
}

fn session_worker(
    vault: &Vault,
    corpus: &Corpus,
    k: usize,
    queries_per_session: usize,
    session: usize,
) -> SessionOutcome {
    let mut outcome = SessionOutcome::default();
    if corpus.queries.is_empty() {
        return outcome;
    }
    for step in 0..queries_per_session {
        let query = &corpus.queries[(session + step) % corpus.queries.len()];
        let started = Instant::now();
        let result = vault.search_text_with_telemetry(&query.text, k);
        let elapsed_ms = started.elapsed().as_secs_f64() * 1e3;
        match result {
            Ok(_) => outcome.latency_ms.push(elapsed_ms),
            Err(_) => outcome.errors += 1,
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::corpus::{generate_corpus, index_corpus, perf_vault_config};
    use super::*;

    /// Runs `workers` deliberately STAGGERED arrivals and reports, for each
    /// worker, how many peers had arrived by the time it started working.
    ///
    /// Worker 0 arrives immediately; worker `n` sleeps `n * stagger` first. A
    /// run that does not hold the cohort therefore lets worker 0 start while
    /// the others are still sleeping, and it observes almost no peers.
    fn staggered_arrivals(workers: usize, stagger: Duration, gated: bool) -> Vec<usize> {
        let arrived = AtomicUsize::new(0);
        let gate = ReleaseGate::new();
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for index in 0..workers {
                let arrived = &arrived;
                let gate = &gate;
                handles.push(scope.spawn(move || {
                    std::thread::sleep(stagger * u32::try_from(index).unwrap_or(0));
                    arrived.fetch_add(1, Ordering::SeqCst);
                    if gated {
                        gate.arrive_and_wait();
                    }
                    arrived.load(Ordering::SeqCst)
                }));
            }
            if gated {
                gate.release_all(workers, RENDEZVOUS_TIMEOUT);
            }
            let mut observed = Vec::with_capacity(workers);
            for handle in handles {
                observed.push(handle.join().unwrap_or(0));
            }
            observed
        })
    }

    /// The gate — and only the gate — is what makes every worker start with
    /// the whole cohort present. The ungated control is the shape the session
    /// curve had before: early workers run while later ones are still coming
    /// up, so a curve point does not measure the concurrency it advertises.
    #[test]
    fn workers_start_together_only_when_the_gate_releases_them() {
        let workers = 6;
        let stagger = Duration::from_millis(40);

        let ungated = staggered_arrivals(workers, stagger, false);
        assert_eq!(ungated.len(), workers);
        assert!(
            ungated[0] < workers,
            "without a gate the first worker starts while its peers are still arriving, but it \
             observed {} of {workers} present",
            ungated[0]
        );

        let gated = staggered_arrivals(workers, stagger, true);
        assert_eq!(gated.len(), workers);
        for (index, observed) in gated.iter().enumerate() {
            assert_eq!(
                *observed, workers,
                "worker {index} was released before the whole cohort arrived: it saw {observed} \
                 of {workers}"
            );
        }
    }

    /// A synchronized run reports the cohort it released and keeps thread
    /// creation out of the measurement window.
    #[test]
    fn a_synchronized_run_reports_its_cohort_and_splits_spawn_from_window() {
        let workers = 8;
        let run = run_synchronized(workers, |index| index * 2);
        assert_eq!(run.results.len(), workers);
        assert_eq!(run.workers_released, workers);
        assert!(run.synchronized);
        assert!(run.spawn_errors.is_empty());
        assert!(run.spawn_ms >= 0.0 && run.window_ms >= 0.0);
        for (index, result) in run.results.into_iter().enumerate() {
            assert_eq!(result.unwrap_or(usize::MAX), index * 2);
        }
    }

    /// The clock starts while the release mutex is still held. A worker can
    /// never begin before the timestamp used as the QPS denominator, even when
    /// its work is much shorter than a scheduler quantum.
    #[test]
    fn the_measurement_clock_precedes_every_released_worker() {
        let gate = ReleaseGate::new();
        let observed = Mutex::new(None::<Instant>);
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                gate.arrive_and_wait();
                *observed.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
            });
            let release = gate.release_all(1, RENDEZVOUS_TIMEOUT);
            handle.join().expect("worker joins");
            let worker_started = observed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .expect("worker recorded its start");
            assert_eq!(release.arrived, 1);
            assert!(
                worker_started >= release.window_started,
                "the QPS window must open before a released worker starts"
            );
        });
    }

    /// The curve itself must carry the synchronization evidence, so a reader
    /// can tell an assembled cohort from a partial one.
    #[test]
    fn every_curve_point_records_that_its_cohort_was_released_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let corpus = generate_corpus(9, 32, 8, 4).expect("corpus");
        let config = perf_vault_config(32, 4);
        {
            let vault = Vault::open(dir.path(), config.clone()).expect("vault opens");
            index_corpus(&vault, &corpus).expect("corpus indexes");
        }
        let vault = Vault::open(dir.path(), config).expect("vault reopens");

        let curve = measure_session_curve(&vault, &corpus, 5, &[1, 4], 3);
        assert_eq!(curve.len(), 2);
        for point in &curve {
            assert_eq!(
                point.workers_released, point.sessions,
                "every worker at the {}-session point must reach the gate",
                point.sessions
            );
            assert!(point.synchronized, "{}-session point", point.sessions);
            assert_eq!(point.queries, point.sessions * 3);
            assert_eq!(point.errors, 0);
            assert!(point.latency_ms.is_measured());
            assert!(point.throughput_qps.is_measured());
            assert!(point.spawn_ms >= 0.0);
        }
    }
}
