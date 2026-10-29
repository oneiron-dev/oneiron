//! The slot's engines, and which one serves on this machine (ARCH-0036,
//! "Several engines, one default per machine").
//!
//! An engine is a runtime on a device. The slot holds the list of them; the
//! CPU engine is built in on every platform and needs no second runtime.
//! `device = "auto"` serves the preferred engine this machine runs whose
//! answers clear the bundle's parity bar against its reference outputs
//! ([`calibration`]: a candidate replaces the incumbent only when its median
//! is faster AND its tail no slower than the margins allow). A named device
//! is the user's pick: it serves when this machine runs it, whatever it
//! measured. Whichever serves, it is a worker of the slot's dispatcher, and
//! each call's receipt names the worker that ran it.
//!
//! No bar and no speed sits in this file. The bar and the reference cases
//! ship in the bundle's `parity.json`; the measured speeds are rows in this
//! machine's engine file, and a row is measured again when the stack, the
//! reference, the runtime, its artifact, the server build, the OS build, the
//! calibration idle, the window rules or the timing cohort move. A row holds
//! an engine to the reference cases whose live window fits its max window; a
//! longer case is skipped, the only skip. A bundle with no reference holds no
//! engine to a bar, so the built-in one serves.
//!
//! These engines are the Candle baseline (FIX 6755, Engine call 4): the
//! default `runtime = "auto"` and an explicit `candle` both load, survey and
//! qualify on Candle here, and neither is recorded as anything else. Each
//! Candle engine's window is the configured `max_input_tokens`, and its row
//! is timed on every case it holds.
//!
//! The serving build measures nothing before the listener binds (FIX 7108):
//! an engine with no row here is measured after the slot is built, in the
//! background ([`baseline`]), and the built-in engine serves meanwhile, as it
//! does for a bundle with no reference. A start whose every engine has its
//! row picks as it always did, with nothing to measure.
//!
//! A platform runtime is admitted beside the baseline after the slot is
//! built, in the background ([`admission`], FIX 6755 slices 3 and 2c): on a
//! Mac, the bundle's managed MLX worker and its native Core ML worker, each
//! once its installation verifies ([`candidate`]) and its answers clear the
//! reference here.

use std::path::Path;

use super::bundle::read_manifest;
use super::dispatcher::WorkerDescriptor;
use super::local::LocalTagger;
use crate::config::oneironer::OneironerRuntime;
use crate::config::{EmbedderDevice, OneironerConfig};

mod admission;
mod baseline;
mod calibration;
mod candidate;
mod rows;

use calibration::{Reference, Timing, measure, prefers};
use rows::{RowKey, WindowRules, build_id, os_build, read_rows, rows_path, write_rows};

pub(crate) use admission::Admission;
pub(crate) use baseline::BaselineCalibration;
pub(crate) use rows::Row;

/// One runtime on one device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Engine {
    pub(crate) runtime: OneironerRuntime,
    pub(crate) device: EmbedderDevice,
}

/// Every engine this build carries, the built-in one first: the Candle
/// baseline's.
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

/// Reads the identity through the strict reader every runtime loads by, so
/// a bundle of another format is the same typed refusal here
/// ([`super::bundle::BundleFormat`]).
pub(crate) fn bundle_identity(dir: &Path) -> anyhow::Result<BundleIdentity> {
    let read = read_manifest(dir)?;
    Ok(BundleIdentity {
        // 64 lowercase hex digits: the parse checked them.
        checkpoint_sha16: read.manifest.trunk.sha256[..16].to_owned(),
        stack_sha16: read.stack_sha16,
        label_count: u32::try_from(read.manifest.ner_labels.len())?,
    })
}

/// How the serving engine was chosen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pick {
    /// The user named its device.
    Named,
    /// The preferred engine here that clears the bundle's bar ([`prefers`]).
    Measured,
    /// The bundle ships no reference to hold an engine to, so the built-in
    /// engine serves.
    BuiltIn,
    /// An engine here has no row yet: the built-in engine serves until the
    /// after-bind calibration lands ([`BaselineCalibration`], FIX 7108).
    Calibrating,
}

impl Pick {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Named => "named",
            Self::Measured => "measured",
            Self::BuiltIn => "built-in",
            Self::Calibrating => "calibrating",
        }
    }
}

/// What this machine knows about the slot's Candle baseline for one bundle:
/// the baseline survey. A platform runtime is measured on its own, never
/// here.
pub(crate) struct Survey {
    /// Every Candle engine this machine runs, with its row when the bundle
    /// ships a reference.
    pub(crate) engines: Vec<(Engine, Option<Row>)>,
    /// The engine `auto` serves; `None` when the bundle ships a reference
    /// and no engine here clears it.
    pub(crate) default: Option<Engine>,
    pub(crate) pick: Pick,
    /// The default's tagger, when measuring it left it loaded.
    loaded: Option<LocalTagger>,
}

/// The baseline survey: measures the Candle engines this machine runs for
/// the section's bundle, whichever runtime setting it names, reading each
/// row from this machine's file when one is there for its key ([`RowKey`]).
///
/// The default is the preferred clearing engine: the scan starts from the
/// first clearing one, the built-in engine when it clears, and a later one
/// takes its place only when [`prefers`] says so. Only the default stays
/// loaded; no second model is held beside it. An engine that cannot load
/// the bundle or answer a case clears nothing this start, and no row is kept
/// for it: the next start measures it again. When no engine clears, the
/// survey has no default and `auto` is refused: it would serve answers the
/// reference disowns. A named device still serves.
///
/// `rows_location` names the rows file; `None` keeps the XDG/HOME default
/// ([`rows_path`]).
pub(crate) fn survey(
    config: &OneironerConfig,
    rows_location: Option<&Path>,
) -> anyhow::Result<Survey> {
    survey_rows(config, rows_location, Unmeasured::Measure)?
        .ok_or_else(|| anyhow::anyhow!("the oneironer survey left an engine unmeasured"))
}

/// What a survey does with an engine that has no row here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Unmeasured {
    /// Measures it now.
    Measure,
    /// Leaves the whole survey to the after-bind calibration: `None`.
    Defer,
}

/// [`survey`], measuring an engine with no row here only when `unmeasured`
/// says so; `None` when it defers one.
fn survey_rows(
    config: &OneironerConfig,
    rows_location: Option<&Path>,
    unmeasured: Unmeasured,
) -> anyhow::Result<Option<Survey>> {
    let dir = config
        .model_dir
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("local oneironer requires oneironer.model_dir"))?;
    let identity = bundle_identity(dir)?;
    let stack = identity.stack_sha16.as_str();
    // `auto` and `candle` both survey the Candle baseline.
    let here = engines_here(OneironerRuntime::Candle);
    let Some(reference) = Reference::read(dir, stack)? else {
        let default = here
            .iter()
            .copied()
            .find(|engine| engine.built_in())
            .ok_or_else(|| anyhow::anyhow!("oneironer runtime candle has no built-in engine"))?;
        return Ok(Some(Survey {
            engines: here.into_iter().map(|engine| (engine, None)).collect(),
            default: Some(default),
            pick: Pick::BuiltIn,
            loaded: None,
        }));
    };
    let path = rows_path(rows_location);
    let mut rows = path.as_deref().map(read_rows).unwrap_or_default();
    let (build, os_build) = (build_id(), os_build());
    let window = WindowRules {
        max_input_tokens: config.max_input_tokens,
        live_window_tokens: config.live_window_tokens,
    };
    let mut engines = Vec::with_capacity(here.len());
    let mut preferred: Option<(Engine, Timing)> = None;
    let mut loaded: Option<LocalTagger> = None;
    let mut measured = false;
    for engine in here {
        // Candle holds a case to the window it is configured to build, and
        // times every case it holds: its full-window row.
        let candidate = WorkerDescriptor::candle(engine, stack, config.max_input_tokens);
        let cohort = candidate.max_window_tokens();
        let key = RowKey::new(
            stack,
            &reference.sha16,
            &candidate,
            build,
            &os_build,
            window,
            cohort,
        );
        let kept = rows.iter().find(|row| row.is_for(&key)).cloned();
        let (row, tagger) = match kept {
            Some(row) => (row, None),
            None if unmeasured == Unmeasured::Defer => return Ok(None),
            None => {
                let run = measure(config, engine, &candidate, &key, &reference);
                tracing::info!(
                    engine = %run.row.engine,
                    clears = run.row.clears,
                    p50_ms = run.row.p50_ms,
                    p95_ms = run.row.p95_ms,
                    cases = run.row.cases,
                    kept = run.keep,
                    "oneironer engine measured"
                );
                // A build nothing tells apart keeps no row across starts.
                if run.keep && key.reusable() {
                    measured = true;
                    rows.retain(|old| !old.is_for(&key));
                    rows.push(run.row.clone());
                }
                (run.row, run.tagger)
            }
        };
        if let Some(timing) = row.clearing()
            && preferred.is_none_or(|(_, incumbent)| prefers(timing, incumbent))
        {
            preferred = Some((engine, timing));
            // Only the preferred clearing engine stays loaded.
            loaded = tagger;
        }
        engines.push((engine, Some(row)));
    }
    if measured && let Some(path) = path.as_deref() {
        write_rows(path, &rows);
    }
    Ok(Some(Survey {
        engines,
        default: preferred.map(|(engine, _)| engine),
        pick: Pick::Measured,
        loaded,
    }))
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
    load_with(config, rows_location, Unmeasured::Measure)
}

/// [`load`] for the serving build (FIX 7108): an engine with no row here is
/// not measured before the listener binds. The built-in engine serves,
/// picked [`Pick::Calibrating`], until the slot's [`BaselineCalibration`]
/// lands; cached rows pick as [`load`] does.
pub(crate) fn load_serving(
    config: &OneironerConfig,
    rows_location: Option<&Path>,
) -> anyhow::Result<(LocalTagger, Serving)> {
    load_with(config, rows_location, Unmeasured::Defer)
}

fn load_with(
    config: &OneironerConfig,
    rows_location: Option<&Path>,
    unmeasured: Unmeasured,
) -> anyhow::Result<(LocalTagger, Serving)> {
    if config.device != EmbedderDevice::Auto {
        // A named device pins the Candle baseline, under `auto` too.
        let engine = Engine {
            runtime: OneironerRuntime::Candle,
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
        let tagger = LocalTagger::load(&engine.configured(config))?;
        return Ok((
            tagger,
            Serving {
                engine,
                pick: Pick::Named,
            },
        ));
    }
    let Some(survey) = survey_rows(config, rows_location, unmeasured)? else {
        return built_in_while_calibrating(config);
    };
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

/// The built-in engine, which serves while the after-bind calibration
/// measures this machine's engines (FIX 7108), as it serves a bundle with no
/// reference.
fn built_in_while_calibrating(
    config: &OneironerConfig,
) -> anyhow::Result<(LocalTagger, Serving)> {
    let engine = engines_here(OneironerRuntime::Candle)
        .into_iter()
        .find(|engine| engine.built_in())
        .ok_or_else(|| anyhow::anyhow!("oneironer runtime candle has no built-in engine"))?;
    let tagger = LocalTagger::load(&engine.configured(config))?;
    Ok((
        tagger,
        Serving {
            engine,
            pick: Pick::Calibrating,
        },
    ))
}
