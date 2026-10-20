//! The slot's engines, and which one serves on this machine (ARCH-0036,
//! "Several engines, one default per machine").
//!
//! An engine is a runtime on a device. The slot holds the list of them; the
//! CPU engine is built in on every platform and needs no second runtime.
//! `device = "auto"` serves the fastest engine this machine runs whose answers
//! clear the bundle's parity bar against its reference outputs. A named device
//! is the user's pick: it serves when this machine runs it, whatever it
//! measured.
//!
//! No bar and no speed sits in this file. The bar and the reference cases
//! ship in the bundle's `parity.json`; the measured speeds are rows in this
//! machine's engine file, and a row is measured again only when the stack, the
//! reference or the server build moves. A bundle with no reference holds no
//! engine to a bar, so the built-in one serves.

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oneiron::memory::extraction::{
    EncoderInput, EncoderMessage, EncoderOutput, EncoderTurn, ExtractionEncoder, SpeakerRole,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::local::LocalTagger;
use crate::config::oneironer::OneironerRuntime;
use crate::config::{EmbedderDevice, OneironerConfig};

/// The bundle file the local tagger loads; its SHA-256 prefix is the stack.
const MANIFEST_FILE: &str = "oneironer.json";
/// The bundle's reference cases and the bar an engine's answers must clear.
const PARITY_FILE: &str = "parity.json";
/// This machine's measured rows, under its data directory.
const ROWS_FILE: &str = "engines.json";

/// One runtime on one device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Engine {
    pub(crate) runtime: OneironerRuntime,
    pub(crate) device: EmbedderDevice,
}

/// Every engine this build carries, the built-in one first.
pub(crate) const ENGINES: &[Engine] = &[
    Engine {
        runtime: OneironerRuntime::Candle,
        device: EmbedderDevice::Cpu,
    },
    Engine {
        runtime: OneironerRuntime::Candle,
        device: EmbedderDevice::Metal,
    },
    Engine {
        runtime: OneironerRuntime::Candle,
        device: EmbedderDevice::Cuda,
    },
];

impl Engine {
    /// `runtime/device`, as rows and logs name it.
    pub(crate) fn id(self) -> String {
        format!("{}/{}", self.runtime.as_str(), self.device.as_str())
    }

    /// The engine every platform runs with no second runtime.
    pub(crate) const fn built_in(self) -> bool {
        matches!(self.device, EmbedderDevice::Cpu)
    }

    /// Whether this machine runs it: its device opens in this build.
    pub(crate) fn runs_here(self) -> bool {
        match self.device {
            EmbedderDevice::Cpu => true,
            EmbedderDevice::Metal => candle_core::Device::new_metal(0).is_ok(),
            EmbedderDevice::Cuda => candle_core::Device::new_cuda(0).is_ok(),
            EmbedderDevice::Auto => false,
        }
    }

    /// The section with this engine named in it.
    fn configured(self, config: &OneironerConfig) -> OneironerConfig {
        OneironerConfig {
            runtime: self.runtime,
            device: self.device,
            ..config.clone()
        }
    }
}

/// The engines of one runtime this machine runs, the built-in one first.
pub(crate) fn engines_here(runtime: OneironerRuntime) -> Vec<Engine> {
    ENGINES
        .iter()
        .copied()
        .filter(|engine| engine.runtime == runtime && engine.runs_here())
        .collect()
}

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
struct Reference {
    bar: Bar,
    cases: Vec<(EncoderInput, EncoderOutput)>,
    /// SHA-256 prefix of `parity.json`: a row measured against another
    /// reference or bar is measured again.
    sha16: String,
}

impl Reference {
    /// `None` when the bundle ships no `parity.json`.
    fn read(dir: &Path, stack: &str) -> anyhow::Result<Option<Self>> {
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

/// One engine measured on this machine against one bundle's reference.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub(crate) stack_sha16: String,
    pub(crate) reference_sha16: String,
    pub(crate) engine: String,
    /// The server build that measured it: another build may run other kernels.
    pub(crate) build: String,
    /// Whether every reference answer cleared the bar.
    pub(crate) clears: bool,
    /// Mean wall-clock milliseconds per reference case after one warm-up
    /// call; `None` when the engine could not load the bundle or answer.
    pub(crate) mean_ms: Option<f64>,
    pub(crate) cases: usize,
    /// Unix seconds.
    pub(crate) measured_at: u64,
}

impl Row {
    fn is_for(&self, stack: &str, reference: &str, engine: &str, build: &str) -> bool {
        self.stack_sha16 == stack
            && self.reference_sha16 == reference
            && self.engine == engine
            && self.build == build
    }

    /// Its speed, when it clears the bar and was timed.
    fn clearing_ms(&self) -> Option<f64> {
        self.clears.then_some(self.mean_ms).flatten()
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RowsFile {
    rows: Vec<Row>,
}

/// The server build a row is measured under.
fn build_id() -> String {
    format!(
        "{}+{}-{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS
    )
}

/// The rows file: `rows_location` when the caller names one, and then no
/// environment is read; else `<data>/oneiron/oneironer/engines.json`, the
/// data directory found the way the embedder's model root is:
/// `XDG_DATA_HOME`, then the home share tree. `None` when nothing is named
/// and neither names an absolute directory; rows are then measured and kept
/// for this process only.
///
/// A managed vault names its own, under its data directory: it reads no HOME
/// or XDG, and its rows never go under a shared model root or a bundle.
fn rows_path(rows_location: Option<&Path>) -> Option<PathBuf> {
    if let Some(rows_location) = rows_location {
        return Some(rows_location.to_path_buf());
    }
    let absolute = |key: &str| {
        let path = PathBuf::from(std::env::var_os(key)?);
        path.is_absolute().then_some(path)
    };
    let data = absolute("XDG_DATA_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".local").join("share")))?;
    Some(data.join("oneiron").join("oneironer").join(ROWS_FILE))
}

/// The rows file, empty when absent; an unreadable one is measured over.
fn read_rows(path: &Path) -> Vec<Row> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<RowsFile>(&bytes) {
            Ok(file) => file.rows,
            Err(_) => {
                tracing::warn!(path = %path.display(), "oneironer engine rows unreadable; measuring again");
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

/// Writes the rows whole, through a sibling file and a rename.
fn write_rows(path: &Path, rows: &[Row]) {
    let written = (|| -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let staged = path.with_extension("json.tmp");
        std::fs::write(
            &staged,
            serde_json::to_vec_pretty(&RowsFile {
                rows: rows.to_vec(),
            })?,
        )?;
        std::fs::rename(&staged, path)?;
        Ok(())
    })();
    if let Err(error) = written {
        tracing::warn!(path = %path.display(), %error, "oneironer engine rows not saved; the next start measures again");
    }
}

fn sha16(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))[..16].to_owned()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The bundle's identity as its manifest states it, read without loading a
/// weight: what `init` writes into the section and rows are keyed by.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BundleIdentity {
    /// The trunk's SHA-256 prefix: the section's `checkpoint_sha16`.
    pub(crate) checkpoint_sha16: String,
    /// The manifest's SHA-256 prefix: the served stack.
    pub(crate) stack_sha16: String,
    pub(crate) label_count: u32,
}

/// The two manifest fields the identity needs. The local tagger reads the
/// manifest whole, strictly, when it loads.
#[derive(Deserialize)]
struct ManifestIdentity {
    trunk: TrunkIdentity,
    ner_labels: Vec<String>,
}

#[derive(Deserialize)]
struct TrunkIdentity {
    sha256: String,
}

pub(crate) fn bundle_identity(dir: &Path) -> anyhow::Result<BundleIdentity> {
    let bytes = std::fs::read(dir.join(MANIFEST_FILE)).map_err(|error| {
        anyhow::anyhow!(
            "oneironer model_dir {} holds no readable {MANIFEST_FILE}: {error}",
            dir.display()
        )
    })?;
    let manifest: ManifestIdentity = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("oneironer {MANIFEST_FILE} is not a bundle manifest"))?;
    let trunk = manifest.trunk.sha256;
    anyhow::ensure!(
        trunk.len() == 64
            && trunk
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "oneironer {MANIFEST_FILE} trunk sha256 is not 64 lowercase hex digits"
    );
    Ok(BundleIdentity {
        checkpoint_sha16: trunk[..16].to_owned(),
        stack_sha16: sha16(&bytes),
        label_count: u32::try_from(manifest.ner_labels.len())?,
    })
}

/// How the serving engine was chosen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pick {
    /// The user named its device.
    Named,
    /// The fastest engine here that clears the bundle's bar.
    Measured,
    /// The bundle ships no reference to hold an engine to, so the built-in
    /// engine serves.
    BuiltIn,
}

impl Pick {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Named => "named",
            Self::Measured => "measured",
            Self::BuiltIn => "built-in",
        }
    }
}

/// What this machine knows about the slot's engines for one bundle.
pub(crate) struct Survey {
    /// Every engine this machine runs for the runtime, with its row when the
    /// bundle ships a reference.
    pub(crate) engines: Vec<(Engine, Option<Row>)>,
    /// The engine `auto` serves; `None` when the bundle ships a reference
    /// and no engine here clears it.
    pub(crate) default: Option<Engine>,
    pub(crate) pick: Pick,
    /// The default's tagger, when measuring it left it loaded.
    loaded: Option<LocalTagger>,
}

/// Measures the engines this machine runs for the section's bundle, reading
/// each row from this machine's file when one is there for the stack, the
/// reference and this build.
///
/// An engine that cannot load the bundle or answer a case gets a row that
/// does not clear, so it is not tried again until something moves. When no
/// engine clears, the survey has no default and `auto` is refused: it would
/// serve answers the reference disowns. A named device still serves.
///
/// `rows_location` names the rows file; `None` keeps the XDG/HOME default
/// ([`rows_path`]).
pub(crate) fn survey(
    config: &OneironerConfig,
    rows_location: Option<&Path>,
) -> anyhow::Result<Survey> {
    let dir = config
        .model_dir
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("local oneironer requires oneironer.model_dir"))?;
    let identity = bundle_identity(dir)?;
    let stack = identity.stack_sha16.as_str();
    let here = engines_here(config.runtime);
    let Some(reference) = Reference::read(dir, stack)? else {
        let default = here
            .iter()
            .copied()
            .find(|engine| engine.built_in())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "oneironer runtime {} has no built-in engine",
                    config.runtime.as_str()
                )
            })?;
        return Ok(Survey {
            engines: here.into_iter().map(|engine| (engine, None)).collect(),
            default: Some(default),
            pick: Pick::BuiltIn,
            loaded: None,
        });
    };
    let path = rows_path(rows_location);
    let mut rows = path.as_deref().map(read_rows).unwrap_or_default();
    let build = build_id();
    let mut engines = Vec::with_capacity(here.len());
    let mut fastest: Option<(Engine, f64)> = None;
    let mut loaded: Option<(Engine, LocalTagger)> = None;
    let mut measured = false;
    for engine in here {
        let id = engine.id();
        let kept = rows
            .iter()
            .find(|row| row.is_for(stack, &reference.sha16, &id, &build))
            .cloned();
        let row = match kept {
            Some(row) => row,
            None => {
                measured = true;
                let (row, tagger) = measure(config, engine, stack, &reference, &build);
                tracing::info!(
                    engine = %id,
                    clears = row.clears,
                    mean_ms = row.mean_ms,
                    cases = row.cases,
                    "oneironer engine measured"
                );
                // Only the fastest clearing engine stays loaded.
                if let (Some(tagger), Some(ms)) = (tagger, row.clearing_ms())
                    && fastest.is_none_or(|(_, best)| ms < best)
                {
                    loaded = Some((engine, tagger));
                }
                rows.retain(|old| !old.is_for(stack, &reference.sha16, &id, &build));
                rows.push(row.clone());
                row
            }
        };
        if let Some(ms) = row.clearing_ms()
            && fastest.is_none_or(|(_, best)| ms < best)
        {
            fastest = Some((engine, ms));
        }
        engines.push((engine, Some(row)));
    }
    if measured && let Some(path) = path.as_deref() {
        write_rows(path, &rows);
    }
    let default = fastest.map(|(engine, _)| engine);
    Ok(Survey {
        engines,
        default,
        pick: Pick::Measured,
        loaded: loaded
            .filter(|(engine, _)| Some(*engine) == default)
            .map(|(_, tagger)| tagger),
    })
}

/// Loads the bundle on one engine and times the reference cases on it.
fn measure(
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

/// The engine the slot serves and how it was chosen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Serving {
    pub(crate) engine: Engine,
    pub(crate) pick: Pick,
}

/// Loads the local tagger on the engine the section picks: the named device
/// when there is one, else the survey's default, whose rows live in
/// `rows_location` ([`survey`]).
pub(crate) fn load(
    config: &OneironerConfig,
    rows_location: Option<&Path>,
) -> anyhow::Result<(LocalTagger, Serving)> {
    if config.device != EmbedderDevice::Auto {
        let engine = Engine {
            runtime: config.runtime,
            device: config.device,
        };
        // A named engine this machine cannot run is a refusal rather than a
        // quiet fallback: an operator who named metal and got the CPU would
        // read the throughput as a model problem.
        anyhow::ensure!(
            engine.runs_here(),
            "oneironer engine {} does not run on this machine",
            engine.id()
        );
        let tagger = LocalTagger::load(config)?;
        return Ok((
            tagger,
            Serving {
                engine,
                pick: Pick::Named,
            },
        ));
    }
    let survey = survey(config, rows_location)?;
    let Some(engine) = survey.default else {
        anyhow::bail!(
            "no oneironer engine on this machine clears the bundle's parity bar; name one with oneironer.device"
        );
    };
    let tagger = match survey.loaded {
        Some(tagger) => tagger,
        None => LocalTagger::load(&engine.configured(config))?,
    };
    Ok((
        tagger,
        Serving {
            engine,
            pick: survey.pick,
        },
    ))
}
