//! The native Core ML worker (FIX 6755 slice 2c, contract rev 3 B2): the
//! bundle's `coreml-ane` row, its compiled multifunction model run on the
//! CPU and the Neural Engine, in this process, on its dispatcher worker's
//! own thread.
//!
//! The worker is one more worker of the slot's dispatcher,
//! `coreml/cpu_and_ne`, qualified for the row's 512-token window; a longer
//! window goes to Candle. Each call's window is Candle's own, built by the slot's
//! window counter. Its token ids are looked up in the trunk's raw word
//! embedding table ([`inputs`]), padded to the smallest turn function that
//! holds them, and the function's float16 logits and character-head
//! projection are decoded by Candle's own decode ([`decode`]). A bulk unit
//! is one call: units of one, run in turn.
//!
//! A session loads on the worker's thread with no deadline, while Candle
//! serves: the manifest, still the slot's stack; the row, a port this
//! adapter runs; the word embeddings and the character head, from the
//! verified trunk; then every turn function, compiled for the CPU and the
//! Neural Engine (tens of seconds each on a cold OS cache), checked against
//! the row and warmed. A dispatcher close stops it between functions. Any
//! failure there is down, by a fixed name, never a crash and never a failed
//! start: Core ML holds no process to restart. A failed prediction fails its
//! call alone, with the worker's receipt.
//!
//! Only a macOS aarch64 build runs Core ML: the framework is called from
//! `model` and `arrays` alone, both built there only, behind the portable
//! `Models` seam. Everything else here checks on every target.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod arrays;
mod decode;
mod inputs;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod model;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use candle_core::Device;
use oneiron::memory::extraction::{
    EncoderInput, EncoderOutput, ExecutionCompute, ExecutionRuntime, NerSpan,
};

use super::bundle::{
    COREML_ROW, CoreMlPlatform, Platform, ReadManifest, TensorSpec, read_manifest,
};
use super::dispatcher::{Fault, Lifeline, Restart, Worker, WorkerDescriptor, WorkerSpec};
use super::local::{CharacterModel, WindowCounter, character_model};
use decode::Outputs;
use inputs::WordEmbeddings;

/// Tool name on every failure the Core ML worker's calls report.
const COREML_TOOL: &str = "oneironer-coreml";
/// The IO port this adapter runs: the trunk's raw word embeddings in, the
/// NER logits and the character head's projection out.
const PORT: &str = "ane-port-v1";
/// The one table that port's input is looked up in.
const EMBEDDING: &str = "encoder.embeddings.word_embeddings.weight";
/// The port's tensors, by the names the model gives them.
const X: &str = "x";
const MASK: &str = "attention_mask";
const LOGITS: &str = "logits";
const PROJ: &str = "proj";

/// Down: the row's port, embedding or tensors are not what this adapter
/// reads, or its projection is not the character head's width.
const UNSUPPORTED_PORT: &str = "coreml_unsupported_port";
/// Down: the bundle declares a head this adapter cannot run (mentions,
/// coreference or affect), or no character head.
const UNSUPPORTED_HEADS: &str = "coreml_unsupported_heads";
/// Down, `coreml_load_failed:<what>`: the manifest, row, trunk, embedding,
/// character head, model or one function did not load or warm.
const LOAD_FAILED: &str = "coreml_load_failed";
/// Down: the bundle's manifest no longer hashes to the slot's stack.
const STACK_MISMATCH: &str = "identity_mismatch:stack";

/// What an admitted Core ML row loads each session of its worker from.
pub(crate) struct Load {
    /// The bundle directory, canonical: its manifest and its trunk.
    pub(crate) bundle: PathBuf,
    /// The row's verified extraction, the stable path the OS keys its
    /// Neural Engine compile cache on.
    pub(crate) model: PathBuf,
    /// The stack the slot serves, which the manifest must still hash to.
    pub(crate) stack: String,
    /// The slot's live windows, as Candle builds them.
    pub(crate) windows: Arc<WindowCounter>,
}

/// What a Core ML row's worker is: `coreml/cpu_and_ne`, the bytes of its
/// model archive by hash, and its qualified window. The compute names the
/// units Core ML may use, the CPU and the Neural Engine, not proof of
/// where any operation ran.
pub(crate) fn descriptor(model_sha256: &str, max_window_tokens: usize) -> WorkerDescriptor {
    let artifact = model_sha256.get(..16).unwrap_or(model_sha256);
    WorkerDescriptor::new(
        ExecutionRuntime::CoreMl,
        ExecutionCompute::CpuAndNe,
        artifact,
        max_window_tokens,
    )
}

/// The Core ML worker's spec: `descriptor`, units of one call, each session
/// loaded from `load` and admitted by `admit`, and a crashed one loaded
/// again after `restart`'s backoff.
pub(crate) fn spec(
    descriptor: WorkerDescriptor,
    load: Load,
    admit: impl FnMut(&mut dyn Worker) -> Result<usize, Fault> + Send + 'static,
    restart: Restart,
) -> WorkerSpec {
    let factory = move |lifeline: &Lifeline| CoreMlWorker::start(&load, lifeline);
    WorkerSpec::background(descriptor, 1, factory, admit, restart)
}

/// The compiled model's functions, loaded on the worker's own thread and
/// never moved off it: Core ML's on a macOS aarch64 build (`model`), none
/// on any other.
trait Models {
    /// Loads function `name`, of `tokens` tokens, and checks Core ML's
    /// description of it against the row's tensors: a down fault names
    /// what failed or differs.
    fn load(
        &mut self,
        name: &str,
        tokens: usize,
        inputs: &[TensorSpec],
        outputs: &[TensorSpec],
    ) -> Result<(), Fault>;

    /// Runs loaded function `function` on `x` and `mask`, each first-major
    /// in the function's shape, and copies its logits and projection into
    /// `outputs`.
    fn predict(
        &self,
        function: usize,
        x: &[f32],
        mask: &[i32],
        outputs: &mut Outputs,
    ) -> anyhow::Result<()>;
}

/// The compiled model at `model`, no function loaded yet.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn open(model: &Path) -> Result<Box<dyn Models>, Fault> {
    Ok(Box::new(model::ModelSet::open(model)?))
}

/// No build but macOS on aarch64 runs Core ML: discovery finds no
/// candidate here, and a session that started anyway is down.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn open(_: &Path) -> Result<Box<dyn Models>, Fault> {
    Err(down("unsupported_host"))
}

/// The row as this adapter runs it.
struct Port {
    /// Each turn function, by name and tokens, ascending.
    functions: Vec<(String, usize)>,
    /// The token id past the window.
    pad: u32,
    /// `x`'s channels: the trunk's hidden width.
    hidden: usize,
    /// `proj`'s channels: the character head's width.
    projected: usize,
    inputs: Vec<TensorSpec>,
    outputs: Vec<TensorSpec>,
}

impl Port {
    /// `row`, when it is this adapter's port and embedding, its inputs are
    /// exactly `x` float32 `[1, H, 1, L]` and `attention_mask` int32
    /// `[1, L]`, its outputs hold `logits` float16 `[1, labels, 1, L]` and
    /// `proj` float16 `[1, P, 1, L]`, and it names a turn function. Its
    /// other outputs (`pooled`) are not read.
    fn new(row: &CoreMlPlatform, labels: usize) -> Option<Self> {
        let (inputs, outputs) = (row.inputs(), row.outputs());
        let mask = tensor(inputs, MASK, "int32");
        let masked = mask.is_some_and(|mask| mask.dims() == [Some(1), None]);
        let hidden = channels(tensor(inputs, X, "float32"))?;
        let projected = channels(tensor(outputs, PROJ, "float16"))?;
        let logits = channels(tensor(outputs, LOGITS, "float16"));
        let mut functions = Vec::new();
        for (name, tokens) in row.turn_functions() {
            functions.push((name.to_owned(), tokens));
        }
        let runs = row.port() == PORT
            && row.embedding() == EMBEDDING
            && inputs.len() == 2
            && masked
            && logits == Some(labels)
            && !functions.is_empty();
        runs.then(|| Self {
            functions,
            pad: row.pad_token_id(),
            hidden,
            projected,
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
        })
    }

    /// The smallest turn function whose tokens hold a window of `tokens`,
    /// special tokens included: its place and its tokens. `None` past the
    /// longest, a window the dispatcher never routes here.
    fn select_function(&self, tokens: usize) -> Option<(usize, usize)> {
        let fits = |(_, held): &(String, usize)| *held >= tokens;
        let function = self.functions.iter().position(fits)?;
        Some((function, self.functions[function].1))
    }
}

/// The row's tensor `name` among `specs`, when it is `dtype`.
fn tensor<'a>(specs: &'a [TensorSpec], name: &str, dtype: &str) -> Option<&'a TensorSpec> {
    specs
        .iter()
        .find(|spec| spec.name() == name && spec.dtype() == dtype)
}

/// The channels of a `[1, C, 1, L]` tensor.
fn channels(spec: Option<&TensorSpec>) -> Option<usize> {
    match spec?.dims().as_slice() {
        [Some(1), Some(channels), Some(1), None] => Some(*channels),
        _ => None,
    }
}

/// One session of the worker, on its dispatcher worker's own thread.
struct CoreMlWorker {
    models: Box<dyn Models>,
    port: Port,
    embeddings: WordEmbeddings,
    head: CharacterModel,
    windows: Arc<WindowCounter>,
    labels: Vec<String>,
    stack: String,
    /// What each prediction refills.
    outputs: Outputs,
}

impl CoreMlWorker {
    /// Loads a session on the worker's own thread, as the module says. Its
    /// stop hook is registered first, so a dispatcher close ends the load
    /// at the next function.
    fn start(load: &Load, lifeline: &Lifeline) -> Result<Box<dyn Worker>, Fault> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        lifeline.on_close(Box::new(move || flag.store(true, Ordering::Relaxed)));
        let stopped = || stop.load(Ordering::Relaxed);
        let ReadManifest {
            manifest,
            stack_sha16,
        } = read_manifest(&load.bundle).map_err(|error| load_failed("manifest", &error))?;
        if stack_sha16 != load.stack {
            return Err(down(STACK_MISMATCH));
        }
        let Some(Platform::CoreMl(row)) = manifest.platform(COREML_ROW) else {
            return Err(down(&format!("{LOAD_FAILED}:row")));
        };
        let labels = manifest.ner_labels.len();
        let port = Port::new(row, labels).ok_or_else(|| down(UNSUPPORTED_PORT))?;
        if manifest.mentions.is_some() || manifest.coref.is_some() || manifest.vad.is_some() {
            return Err(down(UNSUPPORTED_HEADS));
        }
        if stopped() {
            return Err(Fault::Stopped);
        }
        let weights = manifest.trunk.weights(&load.bundle, &Device::Cpu);
        let weights = weights.map_err(|error| load_failed("trunk", &error))?;
        let embeddings = WordEmbeddings::load(&weights, EMBEDDING, port.hidden);
        let embeddings = embeddings.map_err(|error| load_failed("embedding", &error))?;
        let head = character_model(&manifest, &load.bundle, &weights, port.hidden);
        let head = head.map_err(|error| load_failed("char_head", &error))?;
        // Only the embedding table and the head's weights stay.
        drop(weights);
        let head = head.ok_or_else(|| down(UNSUPPORTED_HEADS))?;
        if head.width != port.projected {
            return Err(down(UNSUPPORTED_PORT));
        }
        let mut models = open(&load.model)?;
        for (name, tokens) in &port.functions {
            if stopped() {
                return Err(Fault::Stopped);
            }
            models.load(name, *tokens, &port.inputs, &port.outputs)?;
            tracing::info!(function = %name, "oneironer coreml function loaded");
        }
        let mut worker = Self {
            models,
            port,
            embeddings,
            head,
            windows: Arc::clone(&load.windows),
            labels: manifest.ner_labels,
            stack: stack_sha16,
            outputs: Outputs::new(),
        };
        worker.warm(&stopped)?;
        Ok(Box::new(worker))
    }

    /// One untimed prediction on each function, a window of one pad token,
    /// so no call is the first a function runs. A function that fails it
    /// is down.
    fn warm(&mut self, stopped: &dyn Fn() -> bool) -> Result<(), Fault> {
        let (functions, pad) = (self.port.functions.clone(), self.port.pad);
        for (function, (name, tokens)) in functions.iter().enumerate() {
            if stopped() {
                return Err(Fault::Stopped);
            }
            if let Err(error) = self.predict(function, &[pad], *tokens) {
                return Err(load_failed(name, &error));
            }
        }
        Ok(())
    }

    /// Runs turn function `function`, of `tokens` tokens, on `ids` padded
    /// to it, into the worker's outputs.
    fn predict(&mut self, function: usize, ids: &[u32], tokens: usize) -> anyhow::Result<()> {
        let inputs = self.embeddings.prepare(ids, tokens, self.port.pad)?;
        let (x, mask) = (&inputs.x, &inputs.mask);
        self.models.predict(function, x, mask, &mut self.outputs)
    }

    /// The answer of a call with `spans`: no link and no mood, as this
    /// bundle's card says.
    fn answer(&self, spans: Vec<NerSpan>) -> EncoderOutput {
        EncoderOutput {
            spans,
            links: Vec::new(),
            vad: None,
            context_links: Vec::new(),
            speaker_links: Vec::new(),
            stack_sha16: Some(self.stack.clone()),
        }
    }
}

impl Worker for CoreMlWorker {
    /// One call. A call with no current message is answered with no
    /// prediction, as Candle answers it; any other runs on the smallest
    /// function its window fits, and fails alone when it cannot.
    fn run(&mut self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        if input.messages.is_empty() {
            return Ok(self.answer(Vec::new()));
        }
        let window = self.windows.window(input)?;
        let ids = window.ids();
        let Some((function, tokens)) = self.port.select_function(ids.len()) else {
            return Err(failure("window_too_long"));
        };
        if let Err(error) = self.predict(function, ids, tokens) {
            tracing::warn!(%error, "oneironer coreml prediction failed");
            return Err(failure("prediction_failed"));
        }
        let decoded = decode::decode(
            &window,
            &self.outputs,
            tokens,
            &self.head,
            &self.labels,
            input.language.as_deref(),
        );
        match decoded {
            Ok(spans) => Ok(self.answer(spans)),
            Err(error) => {
                tracing::warn!(%error, "oneironer coreml outputs refused");
                Err(failure("bad_output"))
            }
        }
    }
}

/// A down fault named `reason`.
fn down(reason: &str) -> Fault {
    Fault::Down(reason.to_owned())
}

/// The down fault of a load that failed at `what`, its error logged once.
fn load_failed(what: &str, error: &dyn std::fmt::Display) -> Fault {
    tracing::warn!(what, %error, "oneironer coreml worker did not load");
    down(&format!("{LOAD_FAILED}:{what}"))
}

/// A failed Core ML call, by its fixed code alone: never text a call read.
fn failure(code: &str) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: COREML_TOOL,
        code: code.to_owned(),
    }
}
