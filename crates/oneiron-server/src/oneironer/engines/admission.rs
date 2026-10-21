//! The background admission of a slot's platform runtimes (FIX 6755 slice
//! 3, Engine calls 3-5): on a Mac, the bundle's managed MLX worker joins the
//! Candle baseline once its answers clear the bundle's reference here.
//!
//! It runs once per slot, on a thread of its own that the serving build
//! starts, so nothing it does holds back the listener. Candle serves
//! meanwhile, and a missing platform, an unsupported host or an invalid
//! installation leaves Candle serving alone; nothing here repairs a bundle.
//! `runtime = "candle"` or a named device never starts it.
//!
//! The worker is admitted in order. Its row is found, its OS admitted and
//! its extraction verified ([`super::candidate`]). Its session is spawned
//! and handshaken. Then this host's held reference cases, those whose
//! window fits the row's 512 tokens, run on it directly
//! ([`measure_loaded`]), never through the dispatcher, and only a clearing
//! row lets it be Ready. Its rank is contested against Candle timed on the
//! same cohort, measured here on a Candle engine of its own; Candle's
//! full-window parity row stays as the survey keeps it. One owner writes
//! every row this admission keeps ([`RowBook`]).
//!
//! Each server process owns its workers (Engine call 5). Within one, a
//! bundle's canonical directory and stack hold one session, and another
//! slot of the same bundle serves Candle alone; several server processes on
//! one Mac each run their own. That rewrites contract A1's "one process per
//! bundle per Mac".

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::super::bundle::{ReadManifest, read_manifest};
use super::super::dispatcher::{
    DispatcherHandle, Fault, Restart, Worker, WorkerDescriptor, WorkerId, WorkerSpec,
};
use super::super::endpoint::ModelCard;
use super::super::local::WindowCounter;
use super::super::mlx::{self, Expected, Launch};
use super::calibration::{Reference, Timing, measure, measure_loaded, prefers};
use super::candidate::{self, Candidate};
use super::rows::{Row, RowKey, WindowRules, build_id, os_build, read_rows, rows_path, write_rows};
use super::{Pick, Serving};
use crate::config::oneironer::OneironerRuntime;
use crate::config::{EmbedderDevice, OneironerConfig};

/// The down reason of a worker whose answers do not clear here, or that
/// holds no reference case.
const PARITY_FAILED: &str = "parity_failed";

/// The bundles a slot of this process holds a session of: canonical
/// directory and stack. Keys, never a worker.
static OWNED: Mutex<BTreeSet<(PathBuf, String)>> = Mutex::new(BTreeSet::new());

/// A slot's platform admission, prepared as the slot is built and started
/// once by the serving build.
pub(crate) struct Admission {
    config: OneironerConfig,
    rows_location: Option<PathBuf>,
    dispatcher: DispatcherHandle,
    /// The Candle engine the slot serves, and its worker.
    baseline: Serving,
    baseline_worker: WorkerId,
    /// The slot's card, which the worker must answer as.
    card: ModelCard,
}

impl Admission {
    /// The admission of a slot that pools its workers: `runtime = "auto"`
    /// with `device = "auto"`, its Candle baseline measured against the
    /// bundle's reference. `None` for a slot pinned to Candle, or one whose
    /// bundle ships no reference to hold a worker to.
    pub(crate) fn new(
        config: &OneironerConfig,
        rows_location: Option<&Path>,
        dispatcher: DispatcherHandle,
        baseline: Serving,
        baseline_worker: WorkerId,
        card: ModelCard,
    ) -> Option<Self> {
        let pooled = config.runtime == OneironerRuntime::Auto
            && config.device == EmbedderDevice::Auto
            && baseline.pick == Pick::Measured;
        pooled.then(|| Self {
            config: config.clone(),
            rows_location: rows_location.map(Path::to_path_buf),
            dispatcher,
            baseline,
            baseline_worker,
            card,
        })
    }

    /// Starts it on its own thread, which ends once the worker is added to
    /// the dispatcher or found absent.
    pub(crate) fn start(self) {
        let spawned = std::thread::Builder::new()
            .name("oneironer admission".to_owned())
            .spawn(move || self.run());
        if let Err(error) = spawned {
            tracing::warn!(%error, "oneironer platform admission did not start; Candle serves");
        }
    }

    fn run(self) {
        let Some(dir) = self.config.model_dir.clone() else {
            return;
        };
        let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
        let read = match read_manifest(&dir) {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(%error, "oneironer platform admission could not read the bundle");
                return;
            }
        };
        let candidate = match candidate::discover(&dir, &read.manifest) {
            Ok(candidate) => candidate,
            Err(absent) => {
                absent.log();
                return;
            }
        };
        let Some(claim) = Claim::take(&dir, &read.stack_sha16) else {
            tracing::info!(
                "oneironer mlx worker not started: another slot of this process owns its session"
            );
            return;
        };
        match self.spec(&dir, &read, &candidate, claim) {
            Ok(spec) => match self.dispatcher.add(spec) {
                Ok(_) => tracing::info!("oneironer mlx worker added; Candle serves meanwhile"),
                Err(error) => tracing::warn!(%error, "oneironer mlx worker not added"),
            },
            Err(error) => tracing::warn!(%error, "oneironer mlx worker not started; Candle serves"),
        }
    }

    /// The worker's spec, once Candle is timed on its cohort: each session
    /// started from the row's launch and admitted by its [`Calibration`].
    fn spec(
        &self,
        dir: &Path,
        read: &ReadManifest,
        candidate: &Candidate<'_>,
        claim: Claim,
    ) -> anyhow::Result<WorkerSpec> {
        let (manifest, stack) = (&read.manifest, read.stack_sha16.as_str());
        let reference = Reference::read(dir, stack)?
            .ok_or_else(|| anyhow::anyhow!("the bundle ships no reference to hold it to"))?;
        let windows = Arc::new(WindowCounter::load(&self.config, manifest)?);
        let rows = RowBook::new(rows_path(self.rows_location.as_deref()));
        let descriptor = candidate.descriptor();
        let window = WindowRules {
            max_input_tokens: self.config.max_input_tokens,
            live_window_tokens: self.config.live_window_tokens,
        };
        let (build, os_build) = (build_id(), os_build());
        // Both contestants are timed on the cases the row's window holds.
        let cohort = descriptor.max_window_tokens();
        let key = |worker: &WorkerDescriptor| {
            RowKey::new(stack, &reference.sha16, worker, build, &os_build, window, cohort)
        };
        let max_input_tokens = self.config.max_input_tokens;
        let candle = WorkerDescriptor::candle(self.baseline.engine, stack, max_input_tokens);
        let candle = self.candle_timing(&rows, &reference, &candle, &key(&candle));
        let (row, checkpoint) = (candidate.row, &manifest.trunk.sha256);
        let expected = Expected {
            version: row.version().to_owned(),
            lock_sha256: row.lock_sha256().to_owned(),
            checkpoint_sha16: checkpoint.get(..16).unwrap_or_default().to_owned(),
            stack_sha16: stack.to_owned(),
            label_count: u32::try_from(manifest.ner_labels.len())?,
            // The bytes WindowCounter::load read and verified hash to it.
            tokenizer_sha256: manifest.tokenizer.sha256.clone(),
            char_head: manifest.characters.is_some(),
            max_input_tokens,
            max_window_tokens: row.max_window_tokens(),
        };
        let labels: BTreeSet<String> = manifest
            .ner_labels
            .iter()
            .filter_map(|label| label.split_once('-'))
            .map(|(_, kind)| kind.to_owned())
            .collect();
        let launch = Launch {
            program: candidate.program.clone(),
            args: candidate.args(dir, max_input_tokens),
            expected,
            card: self.card.clone(),
            windows: Arc::clone(&windows),
            labels: Arc::new(labels),
            timeout: Duration::from_millis(self.config.timeout_ms),
        };
        let key = key(&descriptor);
        let mut calibration = Calibration {
            rows,
            windows,
            key,
            descriptor: descriptor.clone(),
            reference,
            candle,
            dispatcher: self.dispatcher.clone(),
            baseline: self.baseline_worker,
            admitted: None,
            _claim: claim,
        };
        let admit = move |worker: &mut dyn Worker| calibration.admit(worker);
        let restart = Restart::new(
            self.config.retry_backoff_secs,
            self.config.max_retry_backoff_secs,
        );
        Ok(mlx::spec(descriptor, launch, admit, restart))
    }

    /// Candle's timing on the MLX row's cohort: its kept row's, else
    /// measured now on a Candle engine loaded for it and dropped after.
    /// `None` when it does not clear or could not be measured.
    fn candle_timing(
        &self,
        rows: &RowBook,
        reference: &Reference,
        candle: &WorkerDescriptor,
        key: &RowKey,
    ) -> Option<Timing> {
        if let Some(row) = rows.find(key) {
            return row.clearing();
        }
        let run = measure(&self.config, self.baseline.engine, candle, key, reference);
        log_row(&run.row, run.keep);
        if run.keep && key.reusable() {
            rows.keep(key, &run.row);
        }
        run.row.clearing()
    }
}

/// The MLX worker's admission of each started session. Its first outcome
/// is kept for the process: a restarted session is handshaken again and
/// joins on it without measuring again. It holds the bundle's claim for the
/// worker's life.
struct Calibration {
    rows: RowBook,
    windows: Arc<WindowCounter>,
    descriptor: WorkerDescriptor,
    key: RowKey,
    reference: Reference,
    /// Candle timed on the same cohort.
    candle: Option<Timing>,
    dispatcher: DispatcherHandle,
    baseline: WorkerId,
    admitted: Option<usize>,
    _claim: Claim,
}

impl Calibration {
    /// The worker's rank, once its row for its key, kept or measured on
    /// `worker` now, clears; Candle's rank is published beside it. A row
    /// that does not clear, or holds no case, is down; a call that failed
    /// is a crash, and the next session measures again.
    fn admit(&mut self, worker: &mut dyn Worker) -> Result<usize, Fault> {
        if let Some(rank) = self.admitted {
            return Ok(rank);
        }
        let row = match self.rows.find(&self.key) {
            Some(row) => row,
            None => {
                let run = measure_loaded(
                    &self.windows,
                    &self.descriptor,
                    worker,
                    &self.key,
                    &self.reference,
                );
                log_row(&run.row, run.keep);
                if !run.keep {
                    return Err(if run.row.cases == 0 {
                        Fault::Down(PARITY_FAILED.to_owned())
                    } else {
                        Fault::Crash("calibration_failed")
                    });
                }
                if self.key.reusable() {
                    self.rows.keep(&self.key, &run.row);
                }
                run.row
            }
        };
        let Some(timing) = row.clearing() else {
            return Err(Fault::Down(PARITY_FAILED.to_owned()));
        };
        let (rank, candle) = match self.candle {
            Some(candle) if prefers(timing, candle) => (0, 1),
            _ => (1, 0),
        };
        self.dispatcher.publish_rank(self.baseline, candle);
        tracing::info!(
            engine = row.engine.as_str(),
            rank,
            candle_rank = candle,
            "oneironer platform worker admitted"
        );
        self.admitted = Some(rank);
        Ok(rank)
    }
}

/// The one writer of the rows this admission keeps. Each read and each
/// update takes its lock; an update reads the file afresh, replaces its
/// key's row and writes the file whole, so no write drops another's row.
struct RowBook {
    path: Mutex<Option<PathBuf>>,
}

impl RowBook {
    const fn new(path: Option<PathBuf>) -> Self {
        Self {
            path: Mutex::new(path),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<PathBuf>> {
        self.path.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The kept row for `key`, if the file holds one.
    fn find(&self, key: &RowKey) -> Option<Row> {
        let path = self.lock();
        read_rows(path.as_deref()?)
            .into_iter()
            .find(|row| row.is_for(key))
    }

    /// Keeps `row` as `key`'s.
    fn keep(&self, key: &RowKey, row: &Row) {
        let path = self.lock();
        let Some(path) = path.as_deref() else {
            return;
        };
        let mut rows = read_rows(path);
        rows.retain(|old| !old.is_for(key));
        rows.push(row.clone());
        write_rows(path, &rows);
    }
}

/// This process's claim on one bundle's session, released as it drops.
struct Claim((PathBuf, String));

impl Claim {
    /// The claim on `dir` and `stack`; `None` when a slot of this process
    /// holds it.
    fn take(dir: &Path, stack: &str) -> Option<Self> {
        let key = (dir.to_path_buf(), stack.to_owned());
        let mut owned = OWNED.lock().unwrap_or_else(PoisonError::into_inner);
        if !owned.insert(key.clone()) {
            return None;
        }
        Some(Self(key))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut owned = OWNED.lock().unwrap_or_else(PoisonError::into_inner);
        owned.remove(&self.0);
    }
}

fn log_row(row: &Row, kept: bool) {
    tracing::info!(
        engine = row.engine.as_str(),
        clears = row.clears,
        p50_ms = row.p50_ms,
        p95_ms = row.p95_ms,
        cases = row.cases,
        timing_cases = row.timing_cases,
        timing_max_window_tokens = row.timing_max_window_tokens,
        kept,
        "oneironer engine measured"
    );
}
