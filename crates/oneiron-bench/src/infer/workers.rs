//! The measured session's calls: `--concurrency` worker tasks on one arm,
//! one backend and one meter, all driven by one outer `block_on`, and one row
//! writer.
//!
//! A sequential run is one worker taking the pending (case, rep) list in
//! order, each call its own cohort of one, as before. A concurrent run takes
//! one cohort per rep: the whole selected packet, in file order. Its first
//! wave is assigned before any call starts. Worker k takes entry k and starts
//! it k × `--stagger-ms` after the cohort's start, so wake order cannot
//! reorder the arrivals. Later entries go, in order, to whichever worker
//! frees first. A cohort ends before the next one starts, so every rep
//! repeats the same arrival pattern.
//!
//! The warmup runs the same way, per arm and per concurrency: each round is
//! `--concurrency` warmup calls at once, so a batched path is warm too.
//!
//! Each call leases from the shared meter on its own and opens its own VRAM
//! window. No lock is held across a call. Workers hand owned completion
//! records to one writer thread, which scores each one, appends and fsyncs
//! its row in completion order, off the workers' path.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use oneiron::{BudgetGuard, LlmRequest};

use super::arms::Arm;
use super::cases::Case;
use super::measure::{self, Failed, Measured, Timing};
use super::request::{Sent, Shape};
use super::rows::{self, RunIdentity};
use super::vram::Vram;
use super::{keep_output, scoring, shown};

/// One measured call to make.
pub(super) struct Entry {
    /// The case's place in the selected packet.
    pub(super) queue_index: usize,
    pub(super) rep: u32,
    pub(super) cohort_id: String,
    pub(super) cohort_size: usize,
}

/// The arm and meter every call of a session uses.
pub(super) struct Caller<'a> {
    pub(super) arm: &'a Arm,
    pub(super) budget: &'a BudgetGuard,
}

impl Caller<'_> {
    /// One call under its own lease from the caller's meter, settled on its
    /// usage or released on failure.
    async fn call(&self, request: LlmRequest) -> Result<Measured, Failed> {
        let lease = self
            .budget
            .admit_for_request(&request)
            .map_err(|e| Failed {
                error: format!("the caller's meter refused the call: {e}"),
                wall_ms: 0.0,
                started: Instant::now(),
            })?
            .lease;
        let outcome = measure::drive(self.arm.backend.as_ref(), request, &lease).await;
        let refused = match &outcome {
            Ok(measured) => self.budget.settle_per_call(&lease, &measured.usage).err(),
            Err(_) => self.budget.abort(&lease).err(),
        };
        if let Some(e) = refused {
            eprintln!("infer: settling a call's lease failed: {e}");
        }
        outcome
    }
}

/// What every worker of a session shares.
pub(super) struct Session<'a> {
    pub(super) caller: Caller<'a>,
    pub(super) shape: &'a Shape,
    pub(super) vram: &'a Vram,
    /// The selected cases, in packet order; an entry's `queue_index` points
    /// here.
    pub(super) packet: &'a [&'a Case],
    pub(super) concurrency: usize,
    pub(super) stagger: Duration,
    pub(super) warmup: u32,
}

/// What the row writer needs beside each completion.
pub(super) struct RowSink<'a> {
    pub(super) identity: &'a RunIdentity,
    pub(super) packet: &'a [&'a Case],
    pub(super) keep_outputs: Option<&'a Path>,
}

/// One finished call, owned, on its way to the writer.
struct Completion {
    queue_index: usize,
    rep: u32,
    cohort_id: String,
    cohort_size: usize,
    worker_id: usize,
    started_at: String,
    sent: Sent,
    outcome: Result<Measured, Failed>,
    vram_case_peak_mib: Option<u64>,
    start_offset_ms: f64,
    end_offset_ms: f64,
}

/// Warms the arm, then measures `batches` one after another, a row for each
/// call as it lands. The error is the writer's; a call's own failure is its
/// row.
pub(super) fn run(
    rt: &tokio::runtime::Runtime,
    session: &Session<'_>,
    sink: &RowSink<'_>,
    writer: rows::Writer,
    batches: &[Vec<Entry>],
) -> Result<(), String> {
    let stop = AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::channel::<Completion>();
    std::thread::scope(|scope| {
        let written = scope.spawn(|| write_rows(sink, writer, rx, &stop));
        rt.block_on(async {
            session.warm().await;
            // Every row's offsets count from here.
            let epoch = Instant::now();
            for batch in batches {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                session.batch(batch, epoch, &tx, &stop).await;
            }
        });
        drop(tx);
        written
            .join()
            .unwrap_or_else(|_| Err("the row writer panicked".to_owned()))
    })
}

impl Session<'_> {
    /// `warmup` rounds of `concurrency` unrecorded calls at once.
    async fn warm(&self) {
        for round in 0..self.warmup {
            let calls = (0..self.concurrency).map(|_| self.caller.call(self.shape.warmup()));
            for (worker, outcome) in join_all(calls).await.into_iter().enumerate() {
                match outcome {
                    Ok(measured) => println!(
                        "warmup {round}.{worker}: {} ms (not recorded)",
                        shown(measured.timing.wall_ms)
                    ),
                    Err(failed) => eprintln!(
                        "warmup {round}.{worker} failed after {:.0} ms: {}",
                        failed.wall_ms, failed.error
                    ),
                }
            }
        }
    }

    /// Runs one batch to its end: the first wave pre-assigned and staggered
    /// from one start, then the rest first in, first out.
    async fn batch(
        &self,
        batch: &[Entry],
        epoch: Instant,
        tx: &Sender<Completion>,
        stop: &AtomicBool,
    ) {
        let (first, rest) = batch.split_at(self.concurrency.min(batch.len()));
        let queue: Mutex<VecDeque<&Entry>> = Mutex::new(rest.iter().collect());
        let queue = &queue;
        let start = Instant::now();
        let workers = first.iter().enumerate().map(|(worker, entry)| async move {
            let delay = self
                .stagger
                .saturating_mul(u32::try_from(worker).unwrap_or(u32::MAX));
            tokio::time::sleep_until(tokio::time::Instant::from_std(start + delay)).await;
            let mut next = Some(entry);
            while let Some(entry) = next {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                self.call(worker, entry, epoch, tx, stop).await;
                next = queue
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .pop_front();
            }
        });
        join_all(workers).await;
    }

    /// One call of `entry` by `worker_id`, sent to the writer when it ends.
    async fn call(
        &self,
        worker_id: usize,
        entry: &Entry,
        epoch: Instant,
        tx: &Sender<Completion>,
        stop: &AtomicBool,
    ) {
        let case = self.packet[entry.queue_index];
        let (request, sent) = self.shape.case(case);
        let started_at = rows::now_rfc3339();
        let window = self.vram.open_window();
        let outcome = self.caller.call(request).await;
        let vram_case_peak_mib = self.vram.close_window(window);
        let (started, wall_ms) = match &outcome {
            Ok(measured) => (
                measured.started,
                measured.timing.wall_ms.unwrap_or_default(),
            ),
            Err(failed) => (failed.started, failed.wall_ms),
        };
        let start_offset_ms = started.saturating_duration_since(epoch).as_secs_f64() * 1000.0;
        let completion = Completion {
            queue_index: entry.queue_index,
            rep: entry.rep,
            cohort_id: entry.cohort_id.clone(),
            cohort_size: entry.cohort_size,
            worker_id,
            started_at,
            sent,
            outcome,
            vram_case_peak_mib,
            start_offset_ms,
            end_offset_ms: start_offset_ms + wall_ms,
        };
        if tx.send(completion).is_err() {
            // The writer has stopped: start no more calls.
            stop.store(true, Ordering::Relaxed);
        }
    }
}

/// Scores, writes and reports each completion as it comes, in completion
/// order, until the workers are done or a write fails.
fn write_rows(
    sink: &RowSink<'_>,
    mut writer: rows::Writer,
    completions: Receiver<Completion>,
    stop: &AtomicBool,
) -> Result<(), String> {
    for done in completions {
        let case = sink.packet[done.queue_index];
        let rep = done.rep;
        let (status, error, timing, quality) = match done.outcome {
            Ok(measured) => {
                keep_output(sink.keep_outputs, case, rep, &measured.text);
                let quality = scoring::score(case, &measured.text);
                ("ok", None, measured.timing, Some(quality))
            }
            Err(failed) => (
                "error",
                Some(failed.error),
                Timing {
                    wall_ms: Some(failed.wall_ms),
                    ..Timing::default()
                },
                None,
            ),
        };
        let row = rows::Row {
            schema: rows::SCHEMA,
            run: sink.identity,
            case_id: &case.id,
            case_kind: &case.kind,
            scorer: case.scorer,
            case_digest: &case.digest,
            case_prompt_tokens: case.prompt_tokens,
            case_approx_input_tokens: case.approx_input_tokens,
            rep,
            worker_id: done.worker_id,
            queue_index: done.queue_index,
            cohort_id: &done.cohort_id,
            cohort_size: done.cohort_size,
            start_offset_ms: done.start_offset_ms,
            end_offset_ms: done.end_offset_ms,
            started_at: done.started_at,
            status,
            error,
            sent: &done.sent,
            timing,
            vram_case_peak_mib: done.vram_case_peak_mib,
            quality,
        };
        if let Err(e) = writer.append(&row) {
            stop.store(true, Ordering::Relaxed);
            return Err(e);
        }
        match &row.error {
            None => println!(
                "{} rep {rep}: ok, ttft_any {} ms, ttft_text {} ms, out {} tok, decode_e2e {} tok/s, score {}",
                case.id,
                shown(row.timing.ttft_any_ms),
                shown(row.timing.ttft_text_ms),
                row.timing.output_tokens.unwrap_or(0),
                shown(row.timing.decode_tps_e2e),
                shown(row.quality.as_ref().map(|quality| quality.score)),
            ),
            Some(error) => println!("{} rep {rep}: error: {error}", case.id),
        }
    }
    Ok(())
}
