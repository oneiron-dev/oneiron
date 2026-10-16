//! `oneiron-server oneironer`: the tagger's offline handoff with the model
//! project (ARCH-0036 "one base, two roles").
//!
//! The teacher teaches the tagger offline and serves no turn. `distill`
//! writes one job for a candidate student from the vault's approved teacher
//! and live probe policy; `export` binds the packed student the model project
//! produced to that exact job; `publish` pins the student, its provenance and
//! the candidate manifest in a stopped vault. Each student is its own job,
//! and which tier serves is the manifest's binding. Nothing here trains
//! weights, opens the source checkpoints or calls a model.

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use oneiron::llm::manifest::{
    EncoderDistillationRequest, EncoderExport, ModelManifest, ModelRole, SharedBaseFork,
};

use super::{ensure_existing_vault_for_revoke, init_tracing};
use crate::config::{ServeArgs, ServeConfig, resolve_serve_config};

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

pub fn oneironer(command: OneironerCommand) -> anyhow::Result<()> {
    match command {
        OneironerCommand::Distill(args) => distill(*args),
        OneironerCommand::Export(args) => export(args),
        OneironerCommand::Publish(args) => publish(*args),
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
