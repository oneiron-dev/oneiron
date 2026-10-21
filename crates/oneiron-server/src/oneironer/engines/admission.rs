//! The background admission of a slot's platform runtimes (FIX 6755
//! slices 3 and 2c, Engine calls 3-5): on a Mac, the bundle's managed MLX
//! worker and its native Core ML worker each join the Candle baseline once
//! their answers clear the bundle's reference here.
//!
//! It runs once per slot, on a thread of its own that the serving build
//! starts, so nothing it does holds back the listener. Candle serves
//! meanwhile, and a missing platform, an unsupported host or an invalid
//! installation leaves Candle serving alone; nothing here repairs a bundle.
//! `runtime = "candle"` or a named device never starts it.
//!
//! Each worker is admitted in order, MLX's first. Its row is found, its OS
//! admitted and its extraction verified ([`super::candidate`]). Its session
//! is started: the MLX worker's process spawned and handshaken, the Core ML
//! worker's functions compiled, checked and warmed on its own thread, with
//! no deadline. Then this host's held reference cases, those whose window
//! fits the row's 512 tokens, run on it directly ([`measure_loaded`]),
//! never through the dispatcher, and only a clearing row lets it be Ready.
//! Its rank is contested against Candle timed on the same cohort, measured
//! here on a Candle engine of its own; Candle's full-window parity row stays
//! as the survey keeps it. Candle ranks after the platform workers once any
//! of them is preferred over it. One owner writes every row this admission
//! keeps ([`RowBook`]).
//!
//! Each server process owns its workers (Engine call 5). Within one, a
//! bundle's canonical directory and stack hold one session of each runtime,
//! and another slot of the same bundle serves Candle alone; several server
//! processes on one Mac each run their own. That rewrites contract A1's
//! "one process per bundle per Mac".

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::super::bundle::{COREML_ROW, MLX_ROW, ReadManifest, read_manifest};
use super::super::coreml;
use super::super::dispatcher::{
    DispatcherHandle, Fault, Restart, Worker, WorkerDescriptor, WorkerId, WorkerSpec,
};
use super::super::endpoint::ModelCard;
use super::super::local::WindowCounter;
use super::super::mlx::{self, Expected, Launch};
use super::calibration::{Reference, Timing, measure, measure_loaded, prefers};
use super::candidate::{self, Candidate, CoreMlCandidate};
use super::rows::{Row, RowKey, WindowRules, build_id, os_build, read_rows, rows_path, write_rows};
use super::{Pick, Serving};
use crate::config::oneironer::OneironerRuntime;
use crate::config::{EmbedderDevice, OneironerConfig};

/// The down reason of a worker whose answers do not clear here, or that
/// holds no reference case.
const PARITY_FAILED: &str = "parity_failed";

/// The bundle sessions a slot of this process holds: canonical directory,
/// stack and platform row. Keys, never a worker.
static OWNED: Mutex<BTreeSet<(PathBuf, String, &'static str)>> = Mutex::new(BTreeSet::new());

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

/// What the platform workers of one admission share: the one owner of its
/// rows, and Candle's published rank, which only grows.
struct Contest {
    rows: Arc<RowBook>,
    candle_rank: Arc<Mutex<usize>>,
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

    /// Starts it on its own thread, which ends once each worker is added to
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
        let contest = Contest {
            rows: Arc::new(RowBook::new(rows_path(self.rows_location.as_deref()))),
            candle_rank: Arc::new(Mutex::new(0)),
        };
        match candidate::discover(&dir, &read.manifest) {
            Ok(candidate) => {
                let spec = |claim| self.mlx_spec(&dir, &read, &candidate, &contest, claim);
                self.add(MLX_ROW, &dir, &read.stack_sha16, spec);
            }
            Err(absent) => absent.log(MLX_ROW),
        }
        match candidate::discover_coreml(&dir, &read.manifest) {
            Ok(candidate) => {
                let spec = |claim| self.coreml_spec(&dir, &read, &candidate, &contest, claim);
                self.add(COREML_ROW, &dir, &read.stack_sha16, spec);
            }
            Err(absent) => absent.log(COREML_ROW),
        }
    }

    /// Claims the bundle's `row` session for this process, then adds the
    /// worker `spec` builds. Candle serves alone when another slot of this
    /// process holds the claim or the spec cannot be built.
    fn add(
        &self,
        row: &'static str,
        dir: &Path,
        stack: &str,
        spec: impl FnOnce(Claim) -> anyhow::Result<WorkerSpec>,
    ) {
        let Some(claim) = Claim::take(dir, stack, row) else {
            tracing::info!(
                row,
                "oneironer platform worker not started: another slot owns its session"
            );
            return;
        };
        match spec(claim).and_then(|spec| self.dispatcher.add(spec)) {
            Ok(_) => tracing::info!(row, "oneironer platform worker added"),
            Err(error) => tracing::warn!(row, %error, "oneironer platform worker not started"),
        }
    }

    /// The MLX worker's spec: each session started from the row's launch
    /// and admitted by its [`Calibration`].
    fn mlx_spec(
        &self,
        dir: &Path,
        read: &ReadManifest,
        candidate: &Candidate<'_>,
        contest: &Contest,
        claim: Claim,
    ) -> anyhow::Result<WorkerSpec> {
        let (manifest, stack) = (&read.manifest, read.stack_sha16.as_str());
        let windows = Arc::new(WindowCounter::load(&self.config, manifest)?);
        let descriptor = candidate.descriptor();
        let mut calibration =
            self.calibration(dir, stack, &descriptor, contest, &windows, claim)?;
        let max_input_tokens = self.config.max_input_tokens;
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
            windows,
            labels: Arc::new(labels),
            timeout: Duration::from_millis(self.config.timeout_ms),
        };
        let admit = move |worker: &mut dyn Worker| calibration.admit(worker);
        Ok(mlx::spec(descriptor, launch, admit, self.restart()))
    }

    /// The Core ML worker's spec: each session loaded from the row's
    /// verified extraction on the worker's own thread, then admitted by its
    /// [`Calibration`].
    fn coreml_spec(
        &self,
        dir: &Path,
        read: &ReadManifest,
        candidate: &CoreMlCandidate<'_>,
        contest: &Contest,
        claim: Claim,
    ) -> anyhow::Result<WorkerSpec> {
        let stack = read.stack_sha16.as_str();
        let windows = Arc::new(WindowCounter::load(&self.config, &read.manifest)?);
        let descriptor = candidate.descriptor();
        let mut calibration =
            self.calibration(dir, stack, &descriptor, contest, &windows, claim)?;
        let load = coreml::Load {
            bundle: dir.to_path_buf(),
            model: candidate.model.clone(),
            stack: stack.to_owned(),
            windows,
        };
        let admit = move |worker: &mut dyn Worker| calibration.admit(worker);
        Ok(coreml::spec(descriptor, load, admit, self.restart()))
    }

    /// The admission of `descriptor`'s sessions, once Candle is timed on its
    /// cohort: the bundle's reference cases, the key of its row and the
    /// contest it ranks in. It holds `claim` for the worker's life.
    fn calibration(
        &self,
        dir: &Path,
        stack: &str,
        descriptor: &WorkerDescriptor,
        contest: &Contest,
        windows: &Arc<WindowCounter>,
        claim: Claim,
    ) -> anyhow::Result<Calibration> {
        let reference = Reference::read(dir, stack)?
            .ok_or_else(|| anyhow::anyhow!("the bundle ships no reference to hold it to"))?;
        let window = WindowRules {
            max_input_tokens: self.config.max_input_tokens,
            live_window_tokens: self.config.live_window_tokens,
        };
        let (build, os_build) = (build_id(), os_build());
        // Both contestants are timed on the cases the row's window holds.
        let cohort = descriptor.max_window_tokens();
        let key = |worker: &WorkerDescriptor| {
            RowKey::new(
                stack,
                &reference.sha16,
                worker,
                build,
                &os_build,
                window,
                cohort,
            )
        };
        let max_input_tokens = self.config.max_input_tokens;
        let candle = WorkerDescriptor::candle(self.baseline.engine, stack, max_input_tokens);
        let candle = self.candle_timing(&contest.rows, &reference, &candle, &key(&candle));
        let key = key(descriptor);
        Ok(Calibration {
            rows: Arc::clone(&contest.rows),
            windows: Arc::clone(windows),
            key,
            descriptor: descriptor.clone(),
            reference,
            candle,
            candle_rank: Arc::clone(&contest.candle_rank),
            dispatcher: self.dispatcher.clone(),
            baseline: self.baseline_worker,
            admitted: None,
            _claim: claim,
        })
    }

    /// A crashed session's backoff: the section's marker retry settings.
    fn restart(&self) -> Restart {
        Restart::new(
            self.config.retry_backoff_secs,
            self.config.max_retry_backoff_secs,
        )
    }

    /// Candle's timing on a platform row's cohort: its kept row's, else
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

/// A platform worker's admission of each started session. Its first
/// outcome is kept for the process: a restarted session is started again and
/// joins on it without measuring again. It holds the bundle's claim for the
/// worker's life.
struct Calibration {
    rows: Arc<RowBook>,
    windows: Arc<WindowCounter>,
    descriptor: WorkerDescriptor,
    key: RowKey,
    reference: Reference,
    /// Candle timed on the same cohort.
    candle: Option<Timing>,
    /// Candle's rank as the admission's workers have published it.
    candle_rank: Arc<Mutex<usize>>,
    dispatcher: DispatcherHandle,
    baseline: WorkerId,
    admitted: Option<usize>,
    _claim: Claim,
}

impl Calibration {
    /// The worker's rank, once its row for its key, kept or measured on
    /// `worker` now, clears: 0 when it is preferred over Candle, else 1.
    /// Candle's rank is published beside it, 1 once any platform worker of
    /// the slot is preferred, so a second worker's admission never ranks
    /// Candle back above the first. A row that does not clear, or holds no
    /// case, is down; a call that failed is a crash, and the next session
    /// measures again.
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
        let preferred = self.candle.is_some_and(|candle| prefers(timing, candle));
        let rank = usize::from(!preferred);
        let candle = {
            let mut candle = self
                .candle_rank
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *candle = (*candle).max(usize::from(preferred));
            self.dispatcher.publish_rank(self.baseline, *candle);
            *candle
        };
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

/// This process's claim on one bundle's session of one platform row,
/// released as it drops.
struct Claim((PathBuf, String, &'static str));

impl Claim {
    /// The claim on `dir`, `stack` and `row`; `None` when a slot of this
    /// process holds it.
    fn take(dir: &Path, stack: &str, row: &'static str) -> Option<Self> {
        let key = (dir.to_path_buf(), stack.to_owned(), row);
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
