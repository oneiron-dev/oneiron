//! The bundle's reference cases, the bar an engine's answers must clear, the
//! measurement of one engine against them, and the rule that prefers one
//! clearing engine over another (Engine 10-21, FIX 6755 ruling 6).
//!
//! Each case is timed after an idle, as a chat spaces its turns: a device
//! whose clocks fall between turns pays for waking on every one, which cases
//! run back to back would hide. A live call keeps exact span parity: the bar
//! moves scores only. An engine is held to the cases whose live window fits
//! its row's max window, and only those are warmed on and checked (FIX
//! 6755); a longer case is skipped, never failed, and that is the only skip.
//! Of those, the cases whose window fits the row's timing cohort are timed,
//! and two engines contest only on one cohort.
//!
//! A worker is measured as it is loaded, on its own thread, by
//! [`measure_loaded`]: whatever its runtime, it answers directly, never
//! through the dispatcher. [`measure`] loads a Candle engine for it.

use std::path::Path;
use std::time::{Duration, Instant};

use oneiron::memory::extraction::{
    EncoderInput, EncoderMessage, EncoderOutput, EncoderTurn, SpeakerRole,
};
use serde::Deserialize;

use super::super::dispatcher::{Worker, WorkerDescriptor};
use super::super::local::{LocalTagger, WindowCounter};
use super::Engine;
use super::rows::{Row, RowKey, sha16};
use crate::config::OneironerConfig;

/// The bundle's reference cases and the bar an engine's answers must clear.
const PARITY_FILE: &str = "parity.json";

/// The idle before each timed reference case: one turn's spacing.
pub(crate) const CALIBRATION_IDLE: Duration = Duration::from_millis(250);
/// How much faster a candidate's median must be than the engine it would
/// replace, as a fraction of the incumbent's.
pub(crate) const PREFERRED_P50_GAIN: f64 = 0.03;
/// How much slower its 95th percentile may be, as a fraction of the
/// incumbent's.
pub(crate) const PREFERRED_P95_SLACK: f64 = 0.05;

/// How far an engine's answer may sit from the reference and still clear it.
/// Spans, labels and links must be the reference's own; only the scores move.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bar {
    /// Largest difference allowed in any span or link confidence.
    pub(crate) max_confidence_delta: f32,
    /// Largest difference allowed in any mood coordinate.
    pub(crate) max_vad_delta: f32,
}

/// `parity.json`: the bar, and inputs with the reference runtime's answers.
/// `reference` and `checked` are the publisher's notes on how the answers
/// were made and what it measured: parsed, dropped and never compared.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityFile {
    bar: Bar,
    cases: Vec<Case>,
    #[serde(default)]
    #[expect(
        dead_code,
        reason = "informational: parsed, then dropped, never compared"
    )]
    reference: Option<serde_json::Value>,
    #[serde(default)]
    #[expect(
        dead_code,
        reason = "informational: parsed, then dropped, never compared"
    )]
    checked: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    input: WireInput,
    output: EncoderOutput,
}

/// An [`EncoderInput`] as a reference case writes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInput {
    turn: String,
    messages: Vec<WireMessage>,
    #[serde(default)]
    context: Vec<WireTurn>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    speaker: Option<SpeakerRole>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMessage {
    id: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTurn {
    turn: String,
    messages: Vec<WireMessage>,
    #[serde(default)]
    speaker: Option<SpeakerRole>,
}

fn messages(wire: Vec<WireMessage>) -> Vec<EncoderMessage> {
    wire.into_iter()
        .map(|message| EncoderMessage {
            id: message.id,
            text: message.text,
        })
        .collect()
}

impl From<WireInput> for EncoderInput {
    fn from(wire: WireInput) -> Self {
        Self {
            turn: wire.turn,
            messages: messages(wire.messages),
            context: wire
                .context
                .into_iter()
                .map(|turn| EncoderTurn {
                    turn: turn.turn,
                    messages: messages(turn.messages),
                    speaker: turn.speaker,
                })
                .collect(),
            language: wire.language,
            speaker: wire.speaker,
        }
    }
}

/// The bundle's reference, read and bound to its bytes.
pub(super) struct Reference {
    bar: Bar,
    cases: Vec<(EncoderInput, EncoderOutput)>,
    /// SHA-256 prefix of `parity.json`: a row measured against another
    /// reference or bar is measured again.
    pub(super) sha16: String,
}

impl Reference {
    /// `None` when the bundle ships no `parity.json`.
    pub(super) fn read(dir: &Path, stack: &str) -> anyhow::Result<Option<Self>> {
        let bytes = match std::fs::read(dir.join(PARITY_FILE)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => anyhow::bail!("oneironer {PARITY_FILE} could not be read: {error}"),
        };
        // The cases are the bundle's own text, never a vault's, but serde's
        // message can quote them; the refusal names the file only.
        let file: ParityFile = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("oneironer {PARITY_FILE} is not a parity file"))?;
        let bar = file.bar;
        anyhow::ensure!(
            [bar.max_confidence_delta, bar.max_vad_delta]
                .iter()
                .all(|delta| delta.is_finite() && *delta >= 0.0),
            "oneironer {PARITY_FILE} bar must be finite and not negative"
        );
        anyhow::ensure!(
            !file.cases.is_empty(),
            "oneironer {PARITY_FILE} holds no reference case"
        );
        anyhow::ensure!(
            file.cases.iter().all(|case| case
                .output
                .stack_sha16
                .as_deref()
                .is_none_or(|named| named == stack)),
            "oneironer {PARITY_FILE} answers for another stack than the bundle's {stack}"
        );
        Ok(Some(Self {
            bar,
            cases: file
                .cases
                .into_iter()
                .map(|case| (case.input.into(), case.output))
                .collect(),
            sha16: sha16(&bytes),
        }))
    }
}

/// Whether `got` clears the bar against `reference`: the same spans with the
/// same labels, the same links of every kind, and each confidence and mood
/// coordinate within the bar. The stack is identity, checked elsewhere.
fn clears(bar: Bar, reference: &EncoderOutput, got: &EncoderOutput) -> bool {
    let near = |a: f32, b: f32, delta: f32| (a - b).abs() <= delta;
    let score = |a: f32, b: f32| near(a, b, bar.max_confidence_delta);
    pairs(&reference.spans, &got.spans, |r, g| {
        r.message == g.message
            && r.start == g.start
            && r.end == g.end
            && r.label == g.label
            && score(r.confidence, g.confidence)
    }) && pairs(&reference.links, &got.links, |r, g| {
        r.span == g.span
            && r.antecedent == g.antecedent
            && match (r.confidence, g.confidence) {
                (Some(r), Some(g)) => score(r, g),
                (None, None) => true,
                _ => false,
            }
    }) && pairs(&reference.context_links, &got.context_links, |r, g| {
        r.span == g.span
            && r.turn == g.turn
            && r.message == g.message
            && r.start == g.start
            && r.end == g.end
            && score(r.confidence, g.confidence)
    }) && pairs(&reference.speaker_links, &got.speaker_links, |r, g| {
        r.span == g.span && r.target == g.target && score(r.confidence, g.confidence)
    }) && match (&reference.vad, &got.vad) {
        (Some(r), Some(g)) => [
            (r.valence, g.valence),
            (r.arousal, g.arousal),
            (r.dominance, g.dominance),
        ]
        .iter()
        .all(|(r, g)| near(*r, *g, bar.max_vad_delta)),
        (None, None) => true,
        _ => false,
    }
}

/// Two lists of the same length whose items pair off in order.
fn pairs<T>(a: &[T], b: &[T], same: impl Fn(&T, &T) -> bool) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
}

/// The reference cases a timing was taken on: the held cases whose window
/// fits `max_window_tokens`, `cases` of them. Timings of two cohorts are two
/// workloads and never contest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Cohort {
    pub(super) max_window_tokens: usize,
    pub(super) cases: usize,
}

/// An engine's latency on its cohort's reference cases, each timed after
/// [`CALIBRATION_IDLE`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Timing {
    pub(super) mean_ms: f64,
    pub(super) p50_ms: f64,
    pub(super) p95_ms: f64,
    pub(super) cohort: Cohort,
}

impl Timing {
    /// The mean and the nearest-rank median and 95th percentile of the
    /// cases of windows up to `max_window_tokens`; `None` for no sample.
    fn of(mut samples: Vec<f64>, max_window_tokens: usize) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        samples.sort_by(f64::total_cmp);
        let count = samples.len();
        let at = |fraction: f64| {
            let rank = (fraction * count as f64).ceil() as usize;
            samples[rank.clamp(1, count) - 1]
        };
        Some(Self {
            mean_ms: samples.iter().sum::<f64>() / count as f64,
            p50_ms: at(0.5),
            p95_ms: at(0.95),
            cohort: Cohort {
                max_window_tokens,
                cases: count,
            },
        })
    }
}

/// Whether `candidate` is preferred over `incumbent`: timed on the same
/// cohort, its median at least [`PREFERRED_P50_GAIN`] faster AND its 95th
/// percentile at most [`PREFERRED_P95_SLACK`] slower. A candidate that is
/// faster only in the median, and slower in the tail, does not replace the
/// incumbent, and neither does one timed on other cases.
pub(super) fn prefers(candidate: Timing, incumbent: Timing) -> bool {
    candidate.cohort == incumbent.cohort
        && candidate.p50_ms <= incumbent.p50_ms * (1.0 - PREFERRED_P50_GAIN)
        && candidate.p95_ms <= incumbent.p95_ms * (1.0 + PREFERRED_P95_SLACK)
}

/// What measuring one worker left.
pub(super) struct MeasuredRow {
    pub(super) row: Row,
    /// Whether the rows file keeps the row: only a measurement that answered
    /// every case. A cold or broken load, or a call that failed, is no
    /// parity result, and the next start measures again.
    pub(super) keep: bool,
}

/// What measuring one Candle engine left.
pub(super) struct Measured {
    pub(super) row: Row,
    /// As [`MeasuredRow::keep`].
    pub(super) keep: bool,
    /// The engine's tagger, once it answered every case.
    pub(super) tagger: Option<LocalTagger>,
}

/// Loads the bundle on one Candle engine, `candidate`, and measures it
/// ([`measure_loaded`]). A load that fails keeps no row.
pub(super) fn measure(
    config: &OneironerConfig,
    engine: Engine,
    candidate: &WorkerDescriptor,
    key: &RowKey,
    reference: &Reference,
) -> Measured {
    let mut tagger = match LocalTagger::load(&engine.configured(config)) {
        Ok(tagger) => tagger,
        Err(error) => {
            let row = Row::unmeasured(key, 0, 0);
            tracing::warn!(engine = %row.engine, %error, "oneironer engine could not load the bundle");
            return Measured {
                row,
                keep: false,
                tagger: None,
            };
        }
    };
    let windows = tagger.window_counter();
    let MeasuredRow { row, keep } =
        measure_loaded(&windows, candidate, &mut tagger, key, reference);
    Measured {
        row,
        keep,
        tagger: keep.then_some(tagger),
    }
}

/// Measures a loaded `worker`, `candidate`, against the reference cases its
/// row holds, calling it directly on this thread, never through the
/// dispatcher. A case is held when its live window, tokens with specials,
/// counted by `windows` as every runtime of the slot builds it, fits the
/// candidate's qualified window; a longer one is skipped. Each held case is
/// checked against the bar; those whose window fits the key's timing cohort
/// are timed, each after [`CALIBRATION_IDLE`]. A case whose window cannot be
/// built fails the measurement, and a row that holds no case is never kept
/// and never clears.
pub(super) fn measure_loaded(
    windows: &WindowCounter,
    candidate: &WorkerDescriptor,
    worker: &mut dyn Worker,
    key: &RowKey,
    reference: &Reference,
) -> MeasuredRow {
    let unkept = |row: Row| MeasuredRow { row, keep: false };
    let mut held = Vec::with_capacity(reference.cases.len());
    for (input, expected) in &reference.cases {
        match windows.count(input) {
            Ok(tokens) if tokens <= candidate.max_window_tokens() => {
                let timed = tokens <= key.timing_max_window_tokens();
                held.push((input, expected, timed));
            }
            // Longer than the worker's window: skipped, the only skip.
            Ok(_) => {}
            Err(_) => {
                let row = Row::unmeasured(key, 0, 0);
                tracing::warn!(engine = %row.engine, "oneironer engine could not window a reference case");
                return unkept(row);
            }
        }
    }
    let mut row = Row::unmeasured(key, held.len(), reference.cases.len() - held.len());
    // One warm-up call, untimed, on a held case: the first forward pays for
    // kernels and caches no later call does.
    let Some(&(first, _, _)) = held.first() else {
        tracing::warn!(engine = %row.engine, "no oneironer reference case fits the engine's window");
        return unkept(row);
    };
    if worker.run(first).is_err() {
        tracing::warn!(engine = %row.engine, "oneironer engine failed a reference case");
        return unkept(row);
    }
    let mut clear = true;
    let mut samples = Vec::with_capacity(held.len());
    for (input, expected, timed) in held {
        // A case outside the cohort is checked, untimed, with no idle.
        if timed {
            std::thread::sleep(CALIBRATION_IDLE);
        }
        let started = Instant::now();
        let answer = worker.run(input);
        if timed {
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        match answer {
            Ok(answer) => clear &= clears(reference.bar, expected, &answer),
            Err(_) => {
                tracing::warn!(engine = %row.engine, "oneironer engine failed a reference case");
                return unkept(row);
            }
        }
    }
    row.timing_cases = samples.len();
    if let Some(timing) = Timing::of(samples, key.timing_max_window_tokens()) {
        row.mean_ms = Some(timing.mean_ms);
        row.p50_ms = Some(timing.p50_ms);
        row.p95_ms = Some(timing.p95_ms);
    }
    row.clears = clear;
    MeasuredRow { row, keep: true }
}
