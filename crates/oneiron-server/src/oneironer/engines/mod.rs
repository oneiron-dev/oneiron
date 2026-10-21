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

use std::path::Path;

use serde::Deserialize;

use super::local::LocalTagger;
use crate::config::oneironer::OneironerRuntime;
use crate::config::{EmbedderDevice, OneironerConfig};

mod calibration;
mod rows;

use calibration::{Reference, measure};
use rows::{build_id, read_rows, rows_path, sha16, write_rows};

pub(crate) use rows::Row;

/// The bundle file the local tagger loads; its SHA-256 prefix is the stack.
const MANIFEST_FILE: &str = "oneironer.json";

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
