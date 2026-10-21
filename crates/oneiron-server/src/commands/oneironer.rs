//! `oneiron-server oneironer`: the tagger's offline handoff with the model
//! project (ARCH-0036 "one base, two roles").
//!
//! The teacher teaches the tagger offline and serves no turn. `distill`
//! writes one job for a candidate student from the vault's approved teacher
//! and live probe policy; `export` binds the packed student the model project
//! produced to that exact job; `publish` pins the student, its provenance and
//! the candidate manifest in a stopped vault. Each student is its own job,
//! and which tier serves is the manifest's binding. None of these trains
//! weights, opens the source checkpoints or calls a model.
//!
//! `qualify` is the one that runs a model: a native bundle on this machine,
//! over qualification cases, through the local tagger the slot serves. It is
//! a development tool and opens no vault and no network. Its conversation
//! window, which tags a case's whole conversation as the model project's
//! reference predictor does, is a window the slot never builds.
//!
//! `fetch` places a shipped release from the catalogue
//! ([`crate::oneironer::release`]) under a models root: resumable, verified
//! file by file, committed whole. It opens no vault; a managed engine never
//! runs it, its supervisor does, into the node's shared model root.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use oneiron::llm::manifest::{
    EncoderDistillationRequest, EncoderExport, ModelManifest, ModelRole, SharedBaseFork,
};
use oneiron::memory::extraction::{EncoderInput, EncoderMessage, EncoderTurn, SpeakerRole};
use serde::Deserialize;

use super::{ensure_existing_vault_for_revoke, init_tracing};
use crate::config::{
    EmbedderDevice, OneironerConfig, OneironerProvider, ServeArgs, ServeConfig,
    resolve_serve_config,
};
use crate::oneironer::release::{self, ReleaseSource};

#[derive(Subcommand)]
pub enum OneironerCommand {
    /// Write one distillation job for the candidate manifest's
    /// extraction_encoder, from the vault's approved teacher (server stopped).
    Distill(Box<DistillArgs>),
    /// Bind a packed student checkpoint to its job: writes the export
    /// receipt `publish` takes. Needs no vault.
    Export(ExportArgs),
    /// Pin the candidate manifest and its distilled encoder in a stopped
    /// vault, after checking the checkpoint against its receipt.
    Publish(Box<PublishArgs>),
    /// Run a native bundle over JSONL cases and append each answer, in
    /// input order: qualification against the model project's decode. Needs
    /// no vault; prints counts only.
    Qualify(QualifyArgs),
    /// Fetch a shipped tagger release into a models root, resumable and
    /// verified, and print the `[oneironer]` section that serves it. Needs
    /// no vault.
    Fetch(FetchArgs),
}

#[derive(Args, Clone)]
pub struct DistillArgs {
    /// The candidate model manifest (JSON); its extraction_encoder row names
    /// the student, tier included.
    #[arg(long)]
    pub candidate: PathBuf,
    /// The shared-base fork (JSON: `base`, `reasoner` and `teacher`, each a
    /// `model` and its `checkpoint_blake3`).
    #[arg(long)]
    pub fork: PathBuf,
    /// BLAKE3 of the model project's distillation recipe.
    #[arg(long)]
    pub recipe_blake3: String,
    /// BLAKE3 of the training corpus the runner reads, never vault text.
    #[arg(long)]
    pub corpus_blake3: String,
    /// Where the job is written; an existing file is never overwritten.
    #[arg(long)]
    pub out: PathBuf,
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone)]
pub struct ExportArgs {
    /// The job `distill` wrote.
    #[arg(long)]
    pub request: PathBuf,
    /// The packed student checkpoint the model project produced for it.
    #[arg(long)]
    pub checkpoint: PathBuf,
    /// Where the receipt is written; an existing file is never overwritten.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args, Clone)]
pub struct PublishArgs {
    /// The candidate model manifest the job was written for.
    #[arg(long)]
    pub manifest: PathBuf,
    /// The receipt `export` wrote.
    #[arg(long)]
    pub export: PathBuf,
    /// The packed student checkpoint the receipt names.
    #[arg(long)]
    pub checkpoint: PathBuf,
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone)]
pub struct QualifyArgs {
    /// The bundle directory holding `oneironer.json`.
    #[arg(long)]
    pub model_dir: PathBuf,
    /// The engine's device.
    #[arg(long, value_enum)]
    pub device: QualifyDevice,
    /// One case a line: `{"id": <string>, "input": <EncoderInput>}`, the
    /// input as contract version 2 sends it.
    #[arg(long)]
    pub inputs: PathBuf,
    /// Where each case's `{"id", "output"}` line is appended, or
    /// `{"id", "error"}` for a case the tagger failed.
    #[arg(long)]
    pub out: PathBuf,
    /// The decode layers: `e4` (E4's baseline, with no DATE snap after
    /// refinement) or `served` (the slot's).
    #[arg(long, value_enum, default_value_t = QualifyLayers::E4)]
    pub layers: QualifyLayers,
    /// The window each case is tagged in: `live` (the slot's) or
    /// `conversation` (the whole conversation in one window, as the model
    /// project's reference predictor tags it, every turn's spans returned).
    #[arg(long, value_enum, default_value_t = QualifyWindow::Live)]
    pub window: QualifyWindow,
    /// `oneironer.max_input_tokens` for this run, its default when absent:
    /// the whole window's tokens, special tokens included. The conversation
    /// window is cut there.
    #[arg(long)]
    pub max_input_tokens: Option<usize>,
    /// `oneironer.live_window_tokens` for this run, its default when absent:
    /// the earlier text the live window keeps. The conversation window does
    /// not read it.
    #[arg(long)]
    pub live_window_tokens: Option<u32>,
}

#[derive(Args, Clone)]
pub struct FetchArgs {
    /// The release's stack_sha16; the catalogue's default release when
    /// absent.
    #[arg(long)]
    pub stack: Option<String>,
    /// The models root the bundle lands under, as `<root>/oneironer/<stack>/`
    /// (a node's shared model root, say). When absent,
    /// `$XDG_DATA_HOME/oneiron/models`, else
    /// `$HOME/.local/share/oneiron/models`; with it, no environment is read.
    #[arg(long)]
    pub into: Option<PathBuf>,
    /// The Hugging Face model repo the release is fetched from;
    /// `oneiron-dev/oneironer` when absent.
    #[arg(long)]
    pub repo: Option<String>,
    /// A file holding a read token for a private release repo, such as a
    /// credential file. It is sent to huggingface.co alone and never printed;
    /// without one the fetch is anonymous.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
}

/// The engine device a qualification runs on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum QualifyDevice {
    Cpu,
    Cuda,
    Metal,
}

/// The decode layers a qualification runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum QualifyLayers {
    /// E4's frozen baseline: no DATE snap after refinement.
    E4,
    /// What the slot serves.
    Served,
}

/// The window a qualification tags each case in.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum QualifyWindow {
    /// The slot's causal window: earlier text up to `live_window_tokens`,
    /// then the current turn, whose spans alone return, each `message`
    /// indexing the input's `messages`.
    Live,
    /// The whole conversation in one window, as the model project's
    /// reference predictor tags it, cut at `max_input_tokens` rather than
    /// refused. Every turn's spans return, each `message` the ordinal of
    /// its message in the flattened conversation (context first, then the
    /// current turn) and `start`/`end` UTF-8 byte offsets into it.
    Conversation,
}

pub fn oneironer(command: OneironerCommand) -> anyhow::Result<()> {
    match command {
        OneironerCommand::Distill(args) => distill(*args),
        OneironerCommand::Export(args) => export(args),
        OneironerCommand::Publish(args) => publish(*args),
        OneironerCommand::Qualify(args) => qualify(args),
        OneironerCommand::Fetch(args) => fetch(args),
    }
}

fn distill(args: DistillArgs) -> anyhow::Result<()> {
    let (_, vault) = open_stopped(&args.serve)?;
    let candidate = ModelManifest::load(&args.candidate)?;
    let fork: SharedBaseFork = serde_json::from_slice(&std::fs::read(&args.fork)?)
        .map_err(|error| anyhow::anyhow!("invalid shared-base fork: {error}"))?;
    let request = vault.encoder_distillation_request(
        &candidate,
        fork,
        args.recipe_blake3,
        args.corpus_blake3,
    )?;
    let policy = vault.teacher_probe_policy(request.teacher_approval.holder_ref.as_deref())?;
    request.write(&candidate, &policy, &args.out)?;
    print(serde_json::json!({
        "request": args.out,
        "request_blake3": request.identity_hash()?,
        "teacher": request.fork.teacher.model.as_str(),
        "encoder": request.encoder.model.as_str(),
        "tier": request.encoder.tier.as_str(),
    }))
}

fn export(args: ExportArgs) -> anyhow::Result<()> {
    let request = EncoderDistillationRequest::load(&args.request)?;
    let export = EncoderExport::from_checkpoint(request, &args.checkpoint)?;
    export.write(&args.out)?;
    print(serde_json::json!({
        "export": args.out,
        "request_blake3": export.request_blake3,
        "encoder": export.checkpoint.model.as_str(),
        "checkpoint_blake3": export.checkpoint.checkpoint_blake3,
    }))
}

fn publish(args: PublishArgs) -> anyhow::Result<()> {
    let (config, vault) = open_stopped(&args.serve)?;
    let manifest = ModelManifest::load(&args.manifest)?;
    let export = EncoderExport::load(&args.export)?;
    vault.set_model_manifest_with_encoder_export(&manifest, &export, &args.checkpoint)?;
    let encoder = &manifest.binding(ModelRole::ExtractionEncoder)?.model;
    // The host serves the student once a configured tier's bundle holds its
    // checkpoint; until then the vault's markers wait.
    let tier = config
        .oneironer
        .as_ref()
        .and_then(|section| section.tier_serving(encoder.revision()));
    print(serde_json::json!({
        "published": encoder.as_str(),
        "served_by_tier": tier,
    }))
}

/// Loads the bundle once on the named engine and answers every case in
/// order, flushing each line as it lands. The answers carry offsets and
/// labels, never text; stdout carries counts.
fn qualify(args: QualifyArgs) -> anyhow::Result<()> {
    // The section names what the bundle declares; the tagger checks both
    // against the bundle again as it loads.
    let bytes = std::fs::read(args.model_dir.join("oneironer.json"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes)?;
    let checkpoint = manifest["trunk"]["sha256"]
        .as_str()
        .and_then(|sha| sha.get(..16))
        .unwrap_or_default();
    let labels = manifest["ner_labels"].as_array().map_or(0, Vec::len);
    let device = match args.device {
        QualifyDevice::Cpu => EmbedderDevice::Cpu,
        QualifyDevice::Cuda => EmbedderDevice::Cuda,
        QualifyDevice::Metal => EmbedderDevice::Metal,
    };
    let layers = match args.layers {
        QualifyLayers::E4 => "e4",
        QualifyLayers::Served => "served",
    };
    let window = match args.window {
        QualifyWindow::Live => "live",
        QualifyWindow::Conversation => "conversation",
    };
    let defaults = OneironerConfig::default();
    let config = OneironerConfig {
        provider: OneironerProvider::Local,
        model_dir: Some(args.model_dir),
        device,
        checkpoint_sha16: Some(checkpoint.to_owned()),
        label_count: Some(u32::try_from(labels)?),
        max_input_tokens: args.max_input_tokens.unwrap_or(defaults.max_input_tokens),
        live_window_tokens: args
            .live_window_tokens
            .unwrap_or(defaults.live_window_tokens),
        ..defaults
    };
    let (mut tagger, _) = crate::oneironer::engines::load(&config, None)?;
    if args.layers == QualifyLayers::E4 {
        tagger.decode_as_e4();
    }
    if args.window == QualifyWindow::Conversation {
        tagger.window_as_conversation()?;
    }
    let inputs = BufReader::new(std::fs::File::open(&args.inputs)?);
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.out)?;
    let (mut answered, mut failed) = (0_usize, 0_usize);
    for (number, line) in (1_usize..).zip(inputs.lines()) {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        // A parse error can quote the line, so the refusal names its number.
        let case: Case = serde_json::from_str(&line)
            .map_err(|_| anyhow::anyhow!("qualify input line {number} is not a case"))?;
        let row = match tagger.infer(&case.input.into()) {
            Ok(output) => {
                answered += 1;
                serde_json::json!({ "id": case.id, "output": output })
            }
            Err(error) => {
                failed += 1;
                serde_json::json!({ "id": case.id, "error": error.to_string() })
            }
        };
        writeln!(out, "{row}")?;
        out.flush()?;
    }
    print(serde_json::json!({
        "answered": answered,
        "failed": failed,
        "device": device.as_str(),
        "layers": layers,
        "window": window,
        "max_input_tokens": config.max_input_tokens,
        "live_window_tokens": config.live_window_tokens,
        "stack_sha16": tagger.card().stack_sha16,
    }))
}

/// Places a shipped release under a models root and prints one JSON object:
/// the outcome, the bundle's directory and, once the bundle is there, the
/// `[oneironer]` section that serves it. A release not published, or private
/// to this fetch, prints its outcome and then fails.
fn fetch(args: FetchArgs) -> anyhow::Result<()> {
    let Some(entry) = release::find(args.stack.as_deref()) else {
        let named = args.stack.unwrap_or_default();
        let known = release::known_stacks();
        anyhow::bail!("no oneironer release has stack {named}; known: {known}");
    };
    let source = ReleaseSource::new(args.repo, args.token_file.as_deref())?;
    // A named root reads no environment.
    let root = match args.into {
        Some(root) => root,
        None => release::default_models_root()?,
    };
    let root = std::path::absolute(root)?;
    let dir = release::bundle_dir(&root, entry);
    let Some(model_dir) = dir.to_str().map(str::to_owned) else {
        anyhow::bail!("the bundle directory {} is not UTF-8", dir.display());
    };
    // The blocking HTTP client cannot run on the CLI's async runtime, so the
    // fetch gets a thread of its own.
    let fetched = std::thread::scope(|scope| {
        scope
            .spawn(|| release::fetch_release(entry, &source, &root))
            .join()
    });
    let outcome = fetched.map_err(|_| anyhow::anyhow!("the oneironer fetch panicked"))??;
    let stack = entry.stack_sha16;
    let repo = source.repo();
    let refusal = outcome.refusal(repo, stack);
    let (bytes, resumed_bytes) = outcome.transferred().unzip();
    let block = outcome
        .placed()
        .map(|placed| release::oneironer_block(entry, placed));
    print(serde_json::json!({
        "outcome": outcome.as_str(),
        "stack_sha16": stack,
        "repo": repo,
        "licence": entry.licence,
        "model_dir": model_dir,
        "bytes": bytes,
        "resumed_bytes": resumed_bytes,
        "file": outcome.refused_file(),
        "message": refusal.as_deref(),
        "oneironer_block": block,
    }))?;
    if let Some(refusal) = refusal {
        anyhow::bail!(refusal);
    }
    Ok(())
}

/// One qualification case.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    input: CaseInput,
}

/// An [`EncoderInput`] as contract version 2 sends it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    turn: String,
    messages: Vec<CaseMessage>,
    #[serde(default)]
    context: Vec<CaseTurn>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    speaker: Option<SpeakerRole>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseMessage {
    id: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseTurn {
    turn: String,
    messages: Vec<CaseMessage>,
    #[serde(default)]
    speaker: Option<SpeakerRole>,
}

fn messages(wire: Vec<CaseMessage>) -> Vec<EncoderMessage> {
    wire.into_iter()
        .map(|message| EncoderMessage {
            id: message.id,
            text: message.text,
        })
        .collect()
}

impl From<CaseInput> for EncoderInput {
    fn from(wire: CaseInput) -> Self {
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

/// Opens a stopped vault as `dreamer grant` does: the writer lease refuses a
/// running server.
fn open_stopped(args: &ServeArgs) -> anyhow::Result<(ServeConfig, oneiron::Vault)> {
    anyhow::ensure!(
        !args.managed_by_hypnos,
        "managed vaults take their model manifest from their supervisor"
    );
    let config = resolve_serve_config(args)?;
    init_tracing(&config.log_level);
    ensure_existing_vault_for_revoke(&config.vault_path)?;
    let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config())?;
    Ok((config, vault))
}

fn print(value: serde_json::Value) -> anyhow::Result<()> {
    writeln!(std::io::stdout().lock(), "{value}")?;
    Ok(())
}
