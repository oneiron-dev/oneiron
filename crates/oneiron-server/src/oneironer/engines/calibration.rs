//! The bundle's reference cases, the bar an engine's answers must clear,
//! and the measurement of one engine against them.

use std::path::Path;
use std::time::Instant;

use oneiron::memory::extraction::{
    EncoderInput, EncoderMessage, EncoderOutput, EncoderTurn, ExtractionEncoder, SpeakerRole,
};
use serde::Deserialize;

use super::super::local::LocalTagger;
use super::Engine;
use super::rows::{Row, sha16, unix_now};
use crate::config::OneironerConfig;

/// The bundle's reference cases and the bar an engine's answers must clear.
const PARITY_FILE: &str = "parity.json";

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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityFile {
    bar: Bar,
    cases: Vec<Case>,
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

/// Loads the bundle on one engine and times the reference cases on it.
pub(super) fn measure(
    config: &OneironerConfig,
    engine: Engine,
    stack: &str,
    reference: &Reference,
    build: &str,
) -> (Row, Option<LocalTagger>) {
    let mut row = Row {
        stack_sha16: stack.to_owned(),
        reference_sha16: reference.sha16.clone(),
        engine: engine.id(),
        build: build.to_owned(),
        clears: false,
        mean_ms: None,
        cases: reference.cases.len(),
        measured_at: unix_now(),
    };
    let tagger = match LocalTagger::load(&engine.configured(config)) {
        Ok(tagger) => tagger,
        Err(error) => {
            tracing::warn!(engine = %row.engine, %error, "oneironer engine could not load the bundle");
            return (row, None);
        }
    };
    // One warm-up call, untimed: the first forward pays for kernels and
    // caches no later call does.
    if let Some((input, _)) = reference.cases.first()
        && tagger.infer(input).is_err()
    {
        tracing::warn!(engine = %row.engine, "oneironer engine failed a reference case");
        return (row, None);
    }
    let mut clear = true;
    let started = Instant::now();
    for (input, expected) in &reference.cases {
        match tagger.infer(input) {
            Ok(answer) => clear &= clears(reference.bar, expected, &answer),
            Err(_) => {
                tracing::warn!(engine = %row.engine, "oneironer engine failed a reference case");
                return (row, None);
            }
        }
    }
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    row.mean_ms = Some(elapsed / reference.cases.len() as f64);
    row.clears = clear;
    (row, Some(tagger))
}
