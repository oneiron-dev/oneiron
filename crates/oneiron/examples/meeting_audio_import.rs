//! Host-run meeting-audio adapter: one file to a normalized artifact, never a consent grant.
//! See scripts/meeting-audio-adapter/SKILL.md for provisioning and policy boundaries.

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oneiron::ingest::meeting_audio::{
    AsrRole, AsrRoute, AudioFile, BatchDefault, CleanupPolicy, CohortManifest, CommandAudioConfig,
    CommandMeetingAudioHost, E1SelectionReceipt, ProcessingTier, ProducerOptions,
    produce_meeting_transcript,
};
use oneiron::ingest::{
    INGEST_SOURCE_REGISTRY, KNOWN_INGEST_HARNESS_CONFIG, MEETING_TRANSCRIPT_SOURCE_ID,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Host-owned paths, not a model installer, route authority or consent record.
/// Glossary and cleanup instructions are loaded from external policy files.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterConfig {
    python: PathBuf,
    bridge: PathBuf,
    ffmpeg: PathBuf,
    workspace: PathBuf,
    model_snapshot: PathBuf,
    runtime_profile: PathBuf,
    runtime_profile_sha256: String,
    audio: PathBuf,
    output: PathBuf,
    language_hint: String,
    capture_started_at: Option<u64>,
    glossary: PathBuf,
    /// Host-owned policy rows; absent uses the shipped default rows.
    policy_manifest: Option<PathBuf>,
    /// Resolved by the host OF-133 router, which owns each model and revision.
    routes: ModelRoutes,
    /// Absent until a separate E1 selection and authenticated OF-133 act exist.
    measured_e1: Option<MeasuredE1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasuredE1 {
    cohort: PathBuf,
    selection: PathBuf,
    evidence_ref: String,
}

/// Host selections, not engine defaults. The local native bridge is only one
/// implementation; a remote selection needs a different MeetingAudioHost.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRoutes {
    asr: ModelRoute,
    aligner: ModelRoute,
    diarization: ModelRoute,
    cleanup: ModelRoute,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRoute {
    model_id: String,
    /// The pinned snapshot revision (last path component) for local native ports.
    model_revision: String,
    /// Reference to the host-authenticated OF-133 role-selection receipt.
    route_receipt_ref: String,
    /// `remote` is a valid choice, but this example runs only `native` ports.
    execution: RouteExecution,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RouteExecution {
    Native,
    Remote,
}

impl ModelRoutes {
    fn stages(&self) -> [(&'static str, &ModelRoute); 4] {
        [
            ("asr", &self.asr),
            ("alignment", &self.aligner),
            ("diarization", &self.diarization),
            ("cleanup", &self.cleanup),
        ]
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        for (_, route) in self.stages() {
            if route.model_id.trim().is_empty()
                || route.model_revision.trim().is_empty()
                || route.route_receipt_ref.trim().is_empty()
            {
                return Err(
                    "model id, revision and route receipt are required for every role".into(),
                );
            }
        }
        Ok(())
    }

    /// Fail before any model call; no local port pretends to be a remote host.
    fn require_native_profile(
        &self,
        path: &Path,
        expected_digest: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.validate()?;
        if self
            .stages()
            .iter()
            .any(|(_, route)| route.execution != RouteExecution::Native)
        {
            return Err("selected model needs a remote MeetingAudioHost adapter; no native inference attempted".into());
        }
        let bytes = fs::read(path)?;
        if bytes.len() > 1024 * 1024 || format!("{:x}", Sha256::digest(&bytes)) != expected_digest {
            return Err("runtime profile digest mismatch".into());
        }
        let profile: serde_json::Value = serde_json::from_slice(&bytes)?;
        for (stage, route) in self.stages() {
            let spec = &profile[stage];
            if spec["backend"] == "process" {
                let worker_path = spec["profile"].as_str().ok_or("missing worker profile")?;
                let worker_bytes = fs::read(worker_path)?;
                let digest = spec["profile_sha256"]
                    .as_str()
                    .ok_or("missing worker profile digest")?;
                if worker_bytes.len() > 1024 * 1024
                    || format!("{:x}", Sha256::digest(&worker_bytes)) != digest
                {
                    return Err("worker profile digest mismatch".into());
                }
                // Keep worker JSON alive until the identity comparison below.
                let worker: serde_json::Value = serde_json::from_slice(&worker_bytes)?;
                let worker_spec = &worker[stage];
                check_profile_model(stage, route, worker_spec)?;
                continue;
            }
            check_profile_model(stage, route, spec)?;
        }
        Ok(())
    }
}

fn check_profile_model(
    stage: &str,
    route: &ModelRoute,
    spec: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = spec["model_id"].as_str();
    let revision = spec["snapshot"]
        .as_str()
        .and_then(|snapshot| Path::new(snapshot).file_name())
        .and_then(|name| name.to_str());
    if id != Some(route.model_id.as_str()) || revision != Some(route.model_revision.as_str()) {
        return Err(format!(
            "{stage} route model id/revision does not match the pinned native snapshot"
        )
        .into());
    }
    Ok(())
}

fn batch_default(
    route: &ModelRoute,
    measured: Option<&MeasuredE1>,
) -> Result<BatchDefault, Box<dyn std::error::Error>> {
    if route.model_id.trim().is_empty()
        || route.model_revision.trim().is_empty()
        || route.route_receipt_ref.trim().is_empty()
    {
        return Err("ASR role requires model id, revision and route receipt".into());
    }
    let Some(measured) = measured else {
        return Ok(BatchDefault::Provisional {
            model_id: route.model_id.clone(),
        });
    };
    if measured.evidence_ref.trim().is_empty() {
        return Err("missing E1 evidence reference".into());
    }
    if !measured.cohort.is_absolute() || !measured.selection.is_absolute() {
        return Err("E1 receipt paths must be absolute".into());
    }
    let cohort = CohortManifest::parse(&fs::read_to_string(&measured.cohort)?)?;
    let selection = E1SelectionReceipt::parse(&fs::read_to_string(&measured.selection)?)?;
    selection.validate_for_cohort(&cohort)?;
    if selection.arms.len() < 2 {
        return Err("E1 selection requires at least two arms".into());
    }
    if selection.winner != route.model_id
        || !selection
            .arms
            .iter()
            .any(|arm| arm.model_id == route.model_id && arm.model_revision == route.model_revision)
    {
        return Err("route must name the selected E1 winner and its revision".into());
    }
    Ok(BatchDefault::MeasuredE1 {
        model_id: selection.winner,
        evidence_ref: measured.evidence_ref.clone(),
    })
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyLimits {
    glossary_max_bytes: usize,
    glossary_max_terms: usize,
    glossary_max_term_bytes: usize,
    stage_timeout_seconds: u64,
    cleanup: CleanupPolicy,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ShippedPolicy {
    precedence: PrecedencePolicy,
    limits: PolicyLimits,
}

/// This row selects whether holder policy participates, and determines the
/// resolution order. It is supplied as data, not built into the resolver.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrecedencePolicy {
    layers: Vec<String>,
    mode: String,
    holder_cap: String,
}

impl PrecedencePolicy {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.mode != "nested_narrowing"
            || self.holder_cap != "vault"
            || !matches!(self.layers.as_slice(), [shipped, vault] if shipped == "shipped" && vault == "vault")
                && !matches!(self.layers.as_slice(), [shipped, vault, holder] if shipped == "shipped" && vault == "vault" && holder == "holder")
        {
            return Err("unsupported policy precedence row".into());
        }
        Ok(())
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyOverride {
    glossary_max_bytes: Option<usize>,
    glossary_max_terms: Option<usize>,
    glossary_max_term_bytes: Option<usize>,
    stage_timeout_seconds: Option<u64>,
    cleanup: Option<CleanupPolicy>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyManifest {
    precedence: Option<PrecedencePolicy>,
    vault: Option<PolicyOverride>,
    holder: Option<PolicyOverride>,
}

impl PolicyLimits {
    fn resolve(path: Option<&Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let shipped: ShippedPolicy = serde_json::from_str(include_str!(
            "../../../scripts/meeting-audio-adapter/policy-defaults.json"
        ))?;
        shipped.limits.validate_substrate()?;
        shipped.precedence.validate()?;
        let Some(path) = path else {
            return Ok(shipped.limits);
        };
        if fs::metadata(path)?.len() > 64 * 1024 {
            return Err("policy manifest exceeds configuration ceiling".into());
        }
        let manifest: PolicyManifest = serde_json::from_slice(&fs::read(path)?)?;
        let precedence = manifest.precedence.unwrap_or(shipped.precedence);
        precedence.validate()?;
        if !precedence.layers.iter().any(|layer| layer == "holder") && manifest.holder.is_some() {
            return Err("holder policy is disabled by precedence row".into());
        }
        let mut current = shipped.limits;
        let mut vault = None;
        for layer in &precedence.layers {
            match layer.as_str() {
                "shipped" => {}
                "vault" => {
                    current = current.apply(manifest.vault.as_ref());
                    current.validate_substrate()?;
                    vault = Some(current.clone());
                }
                "holder" => {
                    let parent = vault.as_ref().ok_or("policy holder has no vault cap")?;
                    current = current.apply(manifest.holder.as_ref());
                    current.validate_substrate()?;
                    current.validate_holder_narrowing(parent)?;
                }
                _ => return Err("invalid policy layer".into()),
            }
        }
        Ok(current)
    }

    fn apply(&self, policy: Option<&PolicyOverride>) -> Self {
        let Some(policy) = policy else {
            return self.clone();
        };
        Self {
            glossary_max_bytes: policy.glossary_max_bytes.unwrap_or(self.glossary_max_bytes),
            glossary_max_terms: policy.glossary_max_terms.unwrap_or(self.glossary_max_terms),
            glossary_max_term_bytes: policy
                .glossary_max_term_bytes
                .unwrap_or(self.glossary_max_term_bytes),
            stage_timeout_seconds: policy
                .stage_timeout_seconds
                .unwrap_or(self.stage_timeout_seconds),
            cleanup: policy
                .cleanup
                .clone()
                .unwrap_or_else(|| self.cleanup.clone()),
        }
    }

    fn validate_holder_narrowing(&self, vault: &Self) -> Result<(), Box<dyn std::error::Error>> {
        if self.glossary_max_bytes > vault.glossary_max_bytes
            || self.glossary_max_terms > vault.glossary_max_terms
            || self.glossary_max_term_bytes > vault.glossary_max_term_bytes
            || self.stage_timeout_seconds > vault.stage_timeout_seconds
            || self.cleanup.max_candidates_per_word > vault.cleanup.max_candidates_per_word
            || self.cleanup.max_candidate_bytes > vault.cleanup.max_candidate_bytes
        {
            return Err("holder policy cannot widen the vault ceiling".into());
        }
        for (language, rule) in &self.cleanup.language_rules {
            let parent = vault
                .cleanup
                .language_rules
                .get(language)
                .ok_or("holder added a correction language")?;
            if rule
                .allowed_pairs
                .iter()
                .any(|pair| !parent.allowed_pairs.contains(pair))
                || parent
                    .protected_tokens
                    .iter()
                    .any(|word| !rule.protected_tokens.contains(word))
                || parent
                    .protected_suffixes
                    .iter()
                    .any(|suffix| !rule.protected_suffixes.contains(suffix))
            {
                return Err("holder correction policy must narrow vault permissions".into());
            }
        }
        Ok(())
    }

    fn validate_substrate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Byte framing and maximum process lifetime are protocol ceilings;
        // term/candidate counts and protected classes belong to policy data.
        if self.glossary_max_bytes == 0
            || self.glossary_max_bytes > 1024 * 1024
            || self.glossary_max_terms == 0
            || self.glossary_max_term_bytes == 0
            || self.glossary_max_term_bytes > 1024 * 1024
            || self.stage_timeout_seconds == 0
            || self.stage_timeout_seconds > 7200
            || self.cleanup.max_candidates_per_word == 0
            || self.cleanup.max_candidates_per_word > 1024 * 1024
            || self.cleanup.max_candidate_bytes == 0
            || self.cleanup.max_candidate_bytes > 1024 * 1024
        {
            return Err("policy exceeds substrate ceiling".into());
        }
        Ok(())
    }
}

fn read_glossary(
    path: &Path,
    limits: &PolicyLimits,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if fs::metadata(path)?.len() > limits.glossary_max_bytes as u64 {
        return Err("glossary file exceeds policy limit".into());
    }
    let glossary: Vec<String> = serde_json::from_slice(&fs::read(path)?)?;
    if glossary.len() > limits.glossary_max_terms
        || glossary
            .iter()
            .any(|entry| entry.trim().is_empty() || entry.len() > limits.glossary_max_term_bytes)
    {
        return Err("invalid glossary under policy".into());
    }
    Ok(glossary)
}

fn run(config: AdapterConfig) -> Result<(), Box<dyn std::error::Error>> {
    config.routes.validate()?;
    if config.language_hint.trim().is_empty() {
        return Err("missing language".into());
    }
    if !config.audio.is_absolute() || !config.glossary.is_absolute() || !config.output.is_absolute()
    {
        return Err("audio, glossary and output paths must be absolute".into());
    }
    let source_name = config
        .audio
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid source name")?;
    let policy = PolicyLimits::resolve(config.policy_manifest.as_deref())?;
    let options = ProducerOptions {
        glossary: read_glossary(&config.glossary, &policy)?,
        batch_default: batch_default(&config.routes.asr, config.measured_e1.as_ref())?,
        diarization_model_id: config.routes.diarization.model_id.clone(),
        cleanup_policy: Some(policy.cleanup.clone()),
        local_only: true,
        batch_asr_policy: None,
    };
    config
        .routes
        .require_native_profile(&config.runtime_profile, &config.runtime_profile_sha256)?;
    let route = AsrRoute {
        role: AsrRole::Asr,
        model_id: config.routes.asr.model_id.clone(),
        tier: ProcessingTier::Local,
        route_receipt_ref: config.routes.asr.route_receipt_ref.clone(),
    };
    let native = CommandAudioConfig {
        python: config.python,
        bridge: config.bridge,
        ffmpeg: config.ffmpeg,
        workspace: config.workspace,
        model_snapshot: config.model_snapshot,
        stage_timeout: Duration::from_secs(policy.stage_timeout_seconds),
    };
    let mut host = CommandMeetingAudioHost::new(native, route)?
        .with_runtime_profile(config.runtime_profile, config.runtime_profile_sha256)?;
    if fs::metadata(&config.audio)?.len() > 256 * 1024 * 1024 {
        return Err("audio exceeds the native bridge input limit".into());
    }
    let bytes = fs::read(&config.audio)?;
    let artifact = produce_meeting_transcript(
        &AudioFile {
            bytes: &bytes,
            source_name,
            capture_started_at: config.capture_started_at,
            language_hint: Some(&config.language_hint),
        },
        &options,
        &mut host,
    )?;
    // Producer construction already normalizes. Recheck the registry parity at
    // the adapter boundary before exposing bytes to an import authorizer.
    let config_source = INGEST_SOURCE_REGISTRY
        .get_config(MEETING_TRANSCRIPT_SOURCE_ID)
        .ok_or("missing meeting source")?;
    if KNOWN_INGEST_HARNESS_CONFIG.get_config(MEETING_TRANSCRIPT_SOURCE_ID) != Some(config_source)
        || config_source
            .adapter_skill
            .map(|skill| (skill.skill_id, skill.version))
            != Some(("builtin.ingest.meeting-transcript", "1"))
    {
        return Err("meeting adapter registry drift".into());
    }
    let normalized =
        INGEST_SOURCE_REGISTRY.normalize(MEETING_TRANSCRIPT_SOURCE_ID, artifact.json())?;
    if normalized.records.is_empty() || !normalized.claims.is_empty() {
        return Err("meeting import must contain evidence turns and no claims".into());
    }
    // No overwrite: the host may inspect this immutable artifact and invoke
    // ProducedMeetingTranscript::authorize_import with a real owner authorizer.
    let mut builder = OpenOptions::new();
    builder.write(true).create_new(true);
    #[cfg(unix)]
    builder.mode(0o600);
    let mut output = builder.open(&config.output)?;
    if let Err(error) = output
        .write_all(artifact.json().as_bytes())
        .and_then(|()| output.sync_all())
    {
        drop(output);
        let _ = fs::remove_file(&config.output);
        return Err(error.into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .ok_or("usage: meeting_audio_import CONFIG.json")?;
    if args.next().is_some() {
        return Err("usage: meeting_audio_import CONFIG.json".into());
    }
    let config: AdapterConfig = serde_json::from_slice(&fs::read(path)?)?;
    run(config)
}

#[cfg(test)]
#[path = "meeting_audio_import/tests.rs"]
mod tests;
