//! The manifest's runtime rows (contract rev 3, B1-B2): the Core ML model and
//! the MLX worker, one archive each. Every object is closed, every value one
//! the contract names, and every row is checked on every OS.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::{Artifact, is_sha256, relative};

/// The Core ML row's name, the one row of its runtime.
pub(crate) const COREML_ROW: &str = "coreml-ane";
/// The MLX row's name, the one row of its runtime.
pub(crate) const MLX_ROW: &str = "mlx-worker";

/// One runtime row: one closed shape or the other, its name binding which.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Platform {
    CoreMl(CoreMlPlatform),
    Mlx(MlxPlatform),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreMlPlatform {
    name: String,
    os: String,
    arch: String,
    min_os: String,
    runtime: String,
    compute_units: String,
    model: Artifact,
    io: CoreMlIo,
}

/// The compiled model's functions and tensors (B2).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreMlIo {
    port: String,
    precision: String,
    functions: Vec<Function>,
    per_turn_functions: Vec<String>,
    max_window_tokens: usize,
    pad_token_id: u32,
    embedding: EmbeddingSpec,
    inputs: Vec<TensorSpec>,
    outputs: Vec<TensorSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Function {
    name: String,
    tokens: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingSpec {
    tensor: String,
    dtype: String,
}

/// One tensor of the compiled model: its name, element type and shape.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TensorSpec {
    name: String,
    dtype: String,
    shape: Vec<Dimension>,
}

/// A fixed dimension, or `L`: the function's tokens.
#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum Dimension {
    Fixed(usize),
    Symbol(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MlxPlatform {
    name: String,
    os: String,
    arch: String,
    min_os: String,
    runtime: String,
    compute_units: String,
    worker: Artifact,
    version: String,
    lock_sha256: String,
    protocol: String,
    max_window_tokens: usize,
    launch: Launch,
}

/// The worker's program, relative to its extraction, and its arguments.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    program: String,
    args: Vec<String>,
}

impl CoreMlPlatform {
    /// The compiled model's archive, extracted beside itself (FIX 6755
    /// slice 2c).
    pub(crate) const fn model(&self) -> &Artifact {
        &self.model
    }

    /// The `major.minor` macOS release it runs from.
    pub(crate) fn min_os(&self) -> &str {
        &self.min_os
    }

    /// The IO port its tensors follow.
    pub(crate) fn port(&self) -> &str {
        &self.io.port
    }

    /// The token id a function's positions past the window take.
    pub(crate) const fn pad_token_id(&self) -> u32 {
        self.io.pad_token_id
    }

    /// The trunk tensor its input is looked up in.
    pub(crate) fn embedding(&self) -> &str {
        &self.io.embedding.tensor
    }

    /// The functions a turn runs on, by name and tokens, ascending.
    pub(crate) fn turn_functions(&self) -> Vec<(&str, usize)> {
        let mut turns = Vec::new();
        for function in &self.io.functions {
            if self.io.per_turn_functions.contains(&function.name) {
                turns.push((function.name.as_str(), function.tokens));
            }
        }
        turns
    }

    /// The longest window it is qualified for, tokens with specials: its
    /// longest turn function's, within the row's `max_window_tokens`.
    pub(crate) fn window_tokens(&self) -> usize {
        let turns = self.turn_functions();
        let longest = turns.last().map_or(0, |&(_, tokens)| tokens);
        longest.min(self.io.max_window_tokens)
    }

    /// The tensors each function reads.
    pub(crate) fn inputs(&self) -> &[TensorSpec] {
        &self.io.inputs
    }

    /// The tensors each function writes.
    pub(crate) fn outputs(&self) -> &[TensorSpec] {
        &self.io.outputs
    }
}

impl TensorSpec {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// `float16`, `float32` or `int32`.
    pub(crate) fn dtype(&self) -> &str {
        &self.dtype
    }

    /// Its dimensions, `None` for `L`: the function's tokens.
    pub(crate) fn dims(&self) -> Vec<Option<usize>> {
        self.shape
            .iter()
            .map(|dimension| match dimension {
                Dimension::Fixed(size) => Some(*size),
                Dimension::Symbol(_) => None,
            })
            .collect()
    }
}

impl MlxPlatform {
    /// The worker archive, extracted beside itself.
    pub(crate) const fn worker(&self) -> &Artifact {
        &self.worker
    }

    /// The `major.minor` macOS release it runs from.
    pub(crate) fn min_os(&self) -> &str {
        &self.min_os
    }

    /// The worker version its handshake must name.
    pub(crate) fn version(&self) -> &str {
        &self.version
    }

    /// The full SHA-256 of the worker's locked requirements, as its
    /// handshake must name it.
    pub(crate) fn lock_sha256(&self) -> &str {
        &self.lock_sha256
    }

    /// The wire it speaks.
    pub(crate) fn protocol(&self) -> &str {
        &self.protocol
    }

    /// The longest window it is qualified for, tokens with specials.
    pub(crate) const fn max_window_tokens(&self) -> usize {
        self.max_window_tokens
    }

    /// Its program, a relative path of plain names inside its extraction,
    /// and the arguments it starts with before the engine's own.
    pub(crate) fn launch(&self) -> (&str, &[String]) {
        (&self.launch.program, &self.launch.args)
    }
}

impl Platform {
    pub(crate) fn name(&self) -> &str {
        self.head()[0]
    }

    pub(crate) fn artifact(&self) -> &Artifact {
        match self {
            Self::CoreMl(row) => &row.model,
            Self::Mlx(row) => &row.worker,
        }
    }

    /// Whether this build targets the row's OS and arch: what a fetch with
    /// `--platforms host` places. `min_os` is admission, not placement.
    pub(crate) fn on_host(&self) -> bool {
        let [_, os, arch, ..] = self.head();
        os == std::env::consts::OS && arch == std::env::consts::ARCH
    }

    /// Name, os, arch, min_os, runtime and compute units: both rows' head.
    fn head(&self) -> [&str; 6] {
        let (name, os, arch, min_os, runtime, compute) = match self {
            Self::CoreMl(row) => (
                &row.name,
                &row.os,
                &row.arch,
                &row.min_os,
                &row.runtime,
                &row.compute_units,
            ),
            Self::Mlx(row) => (
                &row.name,
                &row.os,
                &row.arch,
                &row.min_os,
                &row.runtime,
                &row.compute_units,
            ),
        };
        [name, os, arch, min_os, runtime, compute].map(String::as_str)
    }

    /// Its name binds its runtime and compute units, it runs on macOS on
    /// aarch64 from a `major.minor` release, and its archive is a `.tar`.
    fn validate(&self) -> anyhow::Result<()> {
        let [name, os, arch, min_os, runtime, compute] = self.head();
        let (wanted, wanted_runtime, wanted_compute, suffix) = match self {
            Self::CoreMl(_) => (COREML_ROW, "coreml", "CPU_AND_NE", ".mlmodelc"),
            Self::Mlx(_) => (MLX_ROW, "mlx", "GPU", ""),
        };
        anyhow::ensure!(
            name == wanted && runtime == wanted_runtime && compute == wanted_compute,
            "oneironer platform {name:?} is not {wanted} on {wanted_runtime} and {wanted_compute}"
        );
        let number = |part: &str| part.parse::<u32>().is_ok() && !part.starts_with('+');
        let release = min_os.split_once('.');
        anyhow::ensure!(
            os == "macos"
                && arch == "aarch64"
                && release.is_some_and(|(major, minor)| number(major) && number(minor)),
            "oneironer platform {name} must name macos, aarch64 and a major.minor min_os"
        );
        archive(self.artifact(), suffix)?;
        match self {
            Self::CoreMl(row) => row.io.validate(),
            Self::Mlx(row) => {
                anyhow::ensure!(
                    !row.version.is_empty()
                        && !row.protocol.is_empty()
                        && is_sha256(&row.lock_sha256)
                        && row.max_window_tokens > 0
                        && relative(&row.launch.program),
                    "oneironer {MLX_ROW} has an invalid version, protocol, lock or launch"
                );
                Ok(())
            }
        }
    }
}

impl CoreMlIo {
    /// Functions named once, ascending in tokens to the qualified window;
    /// turn functions among them; `float16`; well-formed tensors.
    fn validate(&self) -> anyhow::Result<()> {
        let mut names = BTreeSet::new();
        let mut last = 0;
        for function in &self.functions {
            anyhow::ensure!(
                !function.name.is_empty()
                    && names.insert(function.name.as_str())
                    && function.tokens > last,
                "oneironer {COREML_ROW} functions must be named once and ascend in tokens"
            );
            last = function.tokens;
        }
        anyhow::ensure!(
            last > 0 && last == self.max_window_tokens,
            "oneironer {COREML_ROW} functions must end at its max_window_tokens"
        );
        let mut turns = BTreeSet::new();
        for name in &self.per_turn_functions {
            anyhow::ensure!(
                names.contains(name.as_str()) && turns.insert(name),
                "oneironer {COREML_ROW} per_turn_functions must name its functions, each once"
            );
        }
        anyhow::ensure!(
            !turns.is_empty() && !self.port.is_empty() && !self.embedding.tensor.is_empty(),
            "oneironer {COREML_ROW} io names no turn function, port or embedding"
        );
        anyhow::ensure!(
            self.precision == "float16"
                && self.embedding.dtype == self.precision
                && tensors(&self.inputs)
                && tensors(&self.outputs),
            "oneironer {COREML_ROW} io must be float16, its tensors well formed"
        );
        Ok(())
    }
}

/// Tensors named once, of a closed type, shaped by positive sizes or `L`.
fn tensors(specs: &[TensorSpec]) -> bool {
    let mut names = BTreeSet::new();
    for spec in specs {
        let dimensions = spec.shape.iter().all(|dimension| match dimension {
            Dimension::Fixed(size) => *size > 0,
            Dimension::Symbol(symbol) => symbol == "L",
        });
        if spec.name.is_empty()
            || !names.insert(spec.name.as_str())
            || !["float16", "float32", "int32"].contains(&spec.dtype.as_str())
            || spec.shape.is_empty()
            || !dimensions
        {
            return false;
        }
    }
    !specs.is_empty()
}

/// A row's archive: one plain, unhidden `<name><suffix>.tar` in the bundle.
fn archive(artifact: &Artifact, suffix: &str) -> anyhow::Result<()> {
    artifact.validate()?;
    let plain = |stem: &str| {
        stem.len() > suffix.len()
            && stem.ends_with(suffix)
            && !stem.starts_with('.')
            && !stem.contains('/')
    };
    anyhow::ensure!(
        artifact.file.strip_suffix(".tar").is_some_and(plain),
        "oneironer platform archive {:?} is not one <name>{suffix}.tar file",
        artifact.file
    );
    Ok(())
}

/// Checks every row's values, and that no two share a name.
pub(super) fn validate_rows(rows: &[Platform]) -> anyhow::Result<()> {
    let mut names = BTreeSet::new();
    for row in rows {
        anyhow::ensure!(
            names.insert(row.name()),
            "oneironer platform {:?} appears twice",
            row.name()
        );
        row.validate()?;
    }
    Ok(())
}
