//! Owner-driven native audio production. The stopped vault's writer lease
//! admits the host configuration; the output is an artifact, not an import.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use oneiron::ingest::meeting_audio::{
    AsrRole, AsrRoute, AudioFile, BatchDefault, CleanupPolicy, CommandAudioConfig,
    CommandMeetingAudioHost, MeetingAudioSeats, NativeAudioCapabilities, ProcessingTier,
    ProducedMeetingTranscript, ProducerOptions, produce_meeting_transcript,
};
use oneiron::llm::media::{AiOperation, MediaCaps, NativeRate};
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, MemoryReceipts, OfferBinding, OfferRoute, Payer, RunAdmission,
    RunDeclaration, UnitRate, WireSeat, offer_id, offer_place,
};
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelId, ModelLocality, ModelTierRef, PurposeDefault,
    ResponseFormat, TierPrecedence, VoiceBackendBinding, VoiceLane, VoicePrecedence,
    canonical_json_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{ServeArgs, resolve_serve_config};

#[derive(Args, Clone, Debug)]
pub struct MeetingTranscriptArgs {
    /// The recording to transcribe. It is not imported or retained in the vault.
    pub input: PathBuf,
    /// Host-owned JSON file naming the native runtime, policy, budget and rates.
    #[arg(long)]
    pub native_config: PathBuf,
    /// Create a new owner-only artifact file instead of writing JSON to stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// The recording's start in Unix milliseconds, when known.
    #[arg(long)]
    pub capture_started_at: Option<u64>,
    /// The recording's language, supported by the native ASR and alignment runtime.
    #[arg(long)]
    pub language: String,
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeConfig {
    runtime: CommandAudioConfig,
    runtime_profile: Option<RuntimeProfile>,
    asr_tier: ModelTierRef,
    /// An explicit owner setting, subject to the vault's existing precedence.
    asr_override: Option<PurposeDefault>,
    budget: BudgetLine,
    call_class: CallClass,
    rates: UnitRates,
    /// Token-to-line-unit conversions. Empty for a line already in tokens.
    line_rates: Vec<UnitRate>,
    #[serde(default)]
    glossary: Vec<String>,
    cleanup_policy: Option<CleanupPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProfile {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitRates {
    vad: NativeRate,
    diarization: NativeRate,
    asr: NativeRate,
    alignment_window: NativeRate,
    cleanup_group: NativeRate,
}

/// The actual host selection, carried in full beside the route that names it.
/// Writer-lease custody authenticates this local act; this is not a signature
/// or independent evidence that a model ran.
#[derive(Serialize)]
struct AsrSelectionReceipt {
    owner: oneiron::EntityId,
    vault_path: PathBuf,
    authority_vault: Option<String>,
    run_instance: oneiron::EntityId,
    vault_policy: PurposeDefault,
    voice_precedence: VoicePrecedence,
    explicit_policy: Option<PurposeDefault>,
    selected: VoiceBackendBinding,
    host_route: OfferRoute,
    host_revision: String,
    unit_models: BTreeMap<String, Vec<String>>,
}

pub fn meeting_transcript(args: MeetingTranscriptArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let vault = super::open_stopped_vault(
        &config,
        "native meeting transcription holds the stopped vault's writer lease",
    )?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let native: NativeConfig = serde_json::from_slice(
        &std::fs::read(&args.native_config).context("read native audio configuration")?,
    )
    .context("parse native audio configuration")?;
    let capabilities = native.runtime.inspect_capabilities(
        native
            .runtime_profile
            .as_ref()
            .map(|profile| (profile.path.as_path(), profile.sha256.as_str())),
    )?;
    let asr_model = one_model(&capabilities, "asr")?;
    let diarizer = one_model(&capabilities, "diarization")?;
    let table = vault.purpose_default_table()?;
    let selected = table.select_voice_backend(
        VoiceLane::AsrBatch,
        native.asr_override.as_ref(),
        &[VoiceBackendBinding {
            model: ModelId::new(asr_model)?,
            tier: native.asr_tier.clone(),
            locality: ModelLocality::OnDevice,
        }],
    )?;
    anyhow::ensure!(
        selected
            .model
            .as_str()
            .rsplit_once('@')
            .map(|(name, _)| name)
            == Some(capabilities.asr_model_id.as_str()),
        "native ASR capability does not match its model-file binding"
    );
    let receipts = Arc::new(MemoryReceipts::default());
    let run = RunAdmission::new(
        format!("meeting-audio:{}", oneiron::EntityId::now().to_hex()),
        RunDeclaration::declared(native.budget.clone()),
        None,
        receipts.clone(),
    )
    .initiated_by(Some(owner));
    let revision = digest(&canonical_json_bytes(&(
        &capabilities.script_sha256,
        &capabilities.runtime_components_sha256,
        &capabilities.runtime_profile_sha256,
        &capabilities.runtime_helper_sha256,
        &capabilities.unit_models,
    ))?);
    let host_route = OfferRoute::new("meeting-audio-command", format!("native:{revision}"))?;
    let selection = AsrSelectionReceipt {
        owner,
        vault_path: std::fs::canonicalize(&config.vault_path)?,
        authority_vault: vault
            .authority_fold()?
            .vault_id
            .map(|id| id.iter().map(|byte| format!("{byte:02x}")).collect()),
        run_instance: run.instance(),
        vault_policy: table.voice(VoiceLane::AsrBatch).clone(),
        voice_precedence: table.voice_precedence,
        explicit_policy: native.asr_override.clone(),
        selected,
        host_route: host_route.clone(),
        host_revision: revision.clone(),
        unit_models: capabilities.unit_models.clone(),
    };
    let route = AsrRoute {
        role: AsrRole::Asr,
        model_id: capabilities.asr_model_id.clone(),
        tier: ProcessingTier::Local,
        route_receipt_ref: format!("sha256:{}", digest(&canonical_json_bytes(&selection)?)),
    };
    let seat =
        |model: &str, operation: AiOperation, rate: NativeRate| -> anyhow::Result<WireSeat> {
            anyhow::ensure!(
                rate.unit == operation.native_unit() && rate.per > 0,
                "native rate must name the operation's unit with a nonzero denominator"
            );
            let model = ModelId::new(model)?;
            let locality = ModelLocality::OnDevice;
            let offer = OfferBinding {
                offer: offer_id(&model, &offer_place(locality, host_route.origin())),
                model,
                route: host_route.clone(),
                locality,
                payer: Payer::Local,
                credential_binding: None,
                catalog_revision: Some(revision.clone()),
                custody: KeyCustody::Keyless,
                rates: native.line_rates.clone(),
                payer_person: None,
            };
            let envelope = CallEnvelope {
                scope: Default::default(),
                purpose: CallPurpose::Voice,
                class: native.call_class.clone(),
                tier: TierPrecedence {
                    per_seat: None,
                    vault_policy: None,
                    purpose_default: None,
                    global_default: native.asr_tier.clone(),
                    seat: None,
                },
                response_format: ResponseFormat::Text,
                locality,
                host_keyless: false,
                seat_effort: None,
            };
            let mut caps = MediaCaps::for_operation(operation);
            caps.native_rates = vec![rate];
            Ok(WireSeat::new(run.clone(), offer, envelope, caps))
        };
    let audio = AiOperation::Transcribe;
    let seats = MeetingAudioSeats {
        vad: seat(one_model(&capabilities, "vad")?, audio, native.rates.vad)?,
        diarization: seat(diarizer, audio, native.rates.diarization)?,
        asr: seat(asr_model, audio, native.rates.asr)?,
        alignment: models(&capabilities, "alignment_window")?
            .iter()
            .map(|model| seat(model, audio, native.rates.alignment_window))
            .collect::<anyhow::Result<_>>()?,
        cleanup: seat(
            one_model(&capabilities, "cleanup_group")?,
            AiOperation::Text,
            native.rates.cleanup_group,
        )?,
    };
    let mut host = CommandMeetingAudioHost::new(native.runtime.clone(), route, seats)?;
    if let Some(profile) = &native.runtime_profile {
        host = host.with_runtime_profile(profile.path.clone(), profile.sha256.clone())?;
    }
    let options = ProducerOptions {
        glossary: native.glossary,
        batch_default: BatchDefault::Provisional {
            model_id: capabilities.asr_model_id.clone(),
        },
        diarization_model_id: diarizer
            .rsplit_once('@')
            .context("diarizer model revision")?
            .0
            .to_owned(),
        cleanup_policy: native.cleanup_policy,
        local_only: true,
        batch_asr_policy: None,
    }
    .with_vault_policy(&vault)?;
    let bytes = std::fs::read(&args.input).context("read recording")?;
    let source_name = args
        .input
        .file_name()
        .context("recording filename")?
        .to_string_lossy();
    let artifact = produce_meeting_transcript(
        &AudioFile {
            bytes: &bytes,
            source_name: &source_name,
            capture_started_at: args.capture_started_at.map(|millis| millis / 1_000),
            language_hint: Some(args.language.as_str()),
        },
        &options,
        &mut host,
    )?;
    let mut document: serde_json::Value = serde_json::from_str(artifact.json())?;
    document["producer"]["route_receipt"] = serde_json::to_value(&selection)?;
    document["producer"]["run_receipts"] = serde_json::to_value(receipts.rows())?;
    let artifact = ProducedMeetingTranscript::from_json(serde_json::to_string(&document)?)?;
    if let Some(out) = args.out {
        super::write_new_file(&out, |file| {
            file.write_all(artifact.json().as_bytes())?;
            file.write_all(b"\n")
        })
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(artifact.json().as_bytes())?;
        stdout.write_all(b"\n")?;
        Ok(())
    }
}

fn models<'a>(
    capabilities: &'a NativeAudioCapabilities,
    kind: &str,
) -> anyhow::Result<&'a [String]> {
    capabilities
        .unit_models
        .get(kind)
        .filter(|models| !models.is_empty())
        .map(Vec::as_slice)
        .with_context(|| format!("native capabilities have no {kind} model"))
}

fn one_model<'a>(capabilities: &'a NativeAudioCapabilities, kind: &str) -> anyhow::Result<&'a str> {
    let models = models(capabilities, kind)?;
    anyhow::ensure!(
        models.len() == 1,
        "native {kind} must name one actual model"
    );
    Ok(&models[0])
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
