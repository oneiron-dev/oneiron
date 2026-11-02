//! The media workers under the owned supervisor (FIX 8318): VoxCPM2 speech
//! and local ASR, each a managed worker class beside llama.cpp and EXL3.
//!
//! Launch: the bundled script (`voxcpm2_worker.py` or `asr_worker.py`, with
//! `worker_support.py` beside it) on the row's own locked environment's
//! interpreter, given the verified weights directory, the weights manifest
//! it was verified against, this launch's manifest, the wire model and its
//! provider's loopback address. Its bearer credential goes in its
//! environment under its provider's `key_env` alone, and the worker is told
//! that variable's name. The worker hashes every pinned file again and loads
//! that directory alone before it listens.
//!
//! Qualification: `/health` is liveness only, and `/ready` alone never
//! qualifies. Each incarnation gets one actual inference: VoxCPM2 one render
//! of [`MEDIA_PROBE_TEXT`] from a synthetic reference, ASR one transcription
//! of the same clip ([`qualification_wav`], silence: never a person's
//! voice). The answer must name the worker, its identity and its epoch
//! (VoxCPM2's: the boot id its `/ready` named), the configured wire model
//! and, for a managed launch, this launch's manifest by its digest; then
//! [`judge_media`] needs the model and runtime pinned and observed, with no
//! template. Missing evidence is `Unverified`, a contradiction `Failed`.
//!
//! Activity: the worker's bearer `/stats`, its queued and active requests
//! (each counted until its response is cleaned up) and its CUDA allocator's
//! reservation. A read that fails reports nothing, which is never idle.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::media::wav::pcm16_wav;
use oneiron::llm::{
    CacheDigest, CacheEpoch, CacheIdentity, INFERENCE_CALLS_KEY, WorkerBuildEvidence,
    WorkerDescriptor, WorkerFailure, WorkerKind, WorkerReadiness,
};
use oneiron::voice_cascade::voxcpm2::WarmTarget;
use oneiron_driver::{LaunchFailure, WorkerSpec};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use super::super::http::{MediaSend, ProviderHttp, UploadAdmission};
use super::bundle::{ASR_WORKER, VOXCPM2_WORKER};
use super::install::{permanent, transient};
use super::launch_manifest::{self, BuildSection, LaunchManifest, LaunchRecord, launch_nonce};
use super::launcher::{Installation, ProcessLauncher};
use super::probe::{Field, LAUNCH_MANIFEST_KEY, judge_pins, model, runtime};
use crate::config::models::ManagedLaunch;

/// The text a VoxCPM2 qualification renders.
const MEDIA_PROBE_TEXT: &str = "Ready.";

/// What the qualification's reference clip is said to hold.
const MEDIA_PROBE_TRANSCRIPT: &str = MEDIA_PROBE_TEXT;

/// The qualification clip's length, in milliseconds of silence.
const MEDIA_PROBE_WAV_MS: u32 = 1_000;

/// The qualification clip's rate: Whisper's own, and one VoxCPM2 takes.
const MEDIA_PROBE_SAMPLE_RATE: u32 = 16_000;

/// The synthetic identity a qualification render names: no banked voice's.
const PROBE_VOICE: &str = "oneiron-qualification";

/// How long one stats read may take before it reports nothing.
const STATS_REQUEST: Duration = Duration::from_secs(5);

/// The OpenAI-compatible transcription route the ASR worker serves.
const TRANSCRIPTIONS: &str = "/v1/audio/transcriptions";

/// Where a media worker's activity is read: its bearer `/stats`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(super) struct StatsRoute {
    client: reqwest::Client,
    url: String,
}

/// A media worker's `/stats`.
#[derive(Deserialize)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Stats {
    queued: u64,
    active: u64,
    #[serde(default)]
    resident_mib: Option<u64>,
}

/// What one qualification answer named.
struct Answered {
    /// The worker its record named; `None` when it named none.
    worker: Option<WorkerDescriptor>,
    /// The wire model it answered as.
    wire_model: Option<String>,
    /// The launch manifest's digest it echoed.
    launch_manifest: Option<String>,
    /// The epoch the worker named beside its answer: VoxCPM2's boot id.
    epoch: Option<CacheEpoch>,
}

/// A media worker's bearer credential: the variable its provider's
/// `key_env` names, and that variable's value here.
pub(super) fn credential(launch: &ManagedLaunch) -> Result<(String, String), LaunchFailure> {
    let name = launch.credential_env.clone().ok_or_else(|| {
        permanent(
            WorkerFailure::LoadFailed,
            "a media worker's provider names no key_env".to_owned(),
        )
    })?;
    let value = std::env::var(&name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| permanent(WorkerFailure::LoadFailed, format!("{name} is not set")))?;
    Ok((name, value))
}

/// The stats route at `url`, read with `credential` as its bearer.
pub(super) fn stats_route(url: String, credential: &str) -> Result<StatsRoute, LaunchFailure> {
    let mut bearer = reqwest::header::HeaderValue::from_str(&format!("Bearer {credential}"))
        .map_err(|_| {
            permanent(
                WorkerFailure::LoadFailed,
                "the media worker's credential is not a header value".to_owned(),
            )
        })?;
    bearer.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, bearer);
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(STATS_REQUEST)
        .timeout(STATS_REQUEST)
        .default_headers(headers)
        .build()
        .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?;
    Ok(StatsRoute { client, url })
}

/// What the worker's `/stats` reports it holds now; `None` when the read
/// fails.
#[cfg(unix)]
pub(super) async fn activity(route: &StatsRoute) -> Option<oneiron_driver::WorkerActivity> {
    let reply = route.client.get(&route.url).send().await.ok()?;
    if !reply.status().is_success() {
        return None;
    }
    let bytes = reply.bytes().await.ok()?;
    let stats: Stats = serde_json::from_slice(&bytes).ok()?;
    Some(oneiron_driver::WorkerActivity {
        queued: stats.queued,
        active: stats.active,
        resident_mib: stats.resident_mib,
    })
}

impl ProcessLauncher {
    /// A media worker's command line, its launch manifest written: its
    /// bundled script on its locked environment's interpreter, told the
    /// name of the variable its credential is in.
    pub(super) fn media_launch(
        &self,
        installation: &Installation,
        credential_env: &str,
    ) -> Result<(PathBuf, Vec<String>), LaunchFailure> {
        let (Some(env), Some(weights_manifest)) = (&installation.env, &installation.media_manifest)
        else {
            return Err(transient(
                WorkerFailure::LoadFailed,
                "the media worker's environment is not installed".to_owned(),
            ));
        };
        let build = BuildSection {
            bundle_sha256: &installation.bundle_sha256,
            env_freeze_sha256: Some(env.freeze_sha256.as_str()),
            env_lock_sha256: Some(env.lock_sha256.as_str()),
            python_version: Some(env.python_version.as_str()),
        };
        let runtime = build.digest();
        // The model a media worker names is its weights manifest's digest:
        // the install record's, never a shard list's.
        let record = installation.weights.record_sha256.as_str();
        let manifest = LaunchManifest {
            backend_model: Some(record),
            bundle_sha256: &installation.bundle_sha256,
            draft_record_sha256: None,
            env_freeze_sha256: Some(env.freeze_sha256.as_str()),
            env_lock_sha256: Some(env.lock_sha256.as_str()),
            kind: self.row.kind,
            launch_nonce: launch_nonce(),
            llama_identity_sha256: None,
            model: self.row.model.as_str(),
            native_binary_sha256: None,
            python_version: Some(env.python_version.as_str()),
            runtime: &runtime,
            schema_version: launch_manifest::schema_version(),
            template_sha256: None,
            tokenizer_sha256: None,
            weights_record_sha256: record,
            wire_model: &self.row.binding.model,
            worker_id: &self.row.id,
        };
        let pins = CacheIdentity {
            model: CacheDigest::new(record).ok(),
            runtime: CacheDigest::new(runtime.as_str()).ok(),
            ..CacheIdentity::default()
        };
        let path = self.record(installation, &manifest, None, pins, None)?;
        let script = match self.row.kind {
            WorkerKind::VoxCpm2 => VOXCPM2_WORKER,
            _ => ASR_WORKER,
        };
        let mut args = vec![
            installation.bundle_dir.join(script).display().to_string(),
            "--weights-dir".to_owned(),
            installation.weights.dir.display().to_string(),
            "--weights-manifest".to_owned(),
            weights_manifest.display().to_string(),
            "--launch-manifest".to_owned(),
            path.display().to_string(),
            "--model-id".to_owned(),
            self.row.binding.model.clone(),
            "--host".to_owned(),
            self.launch.listen_host.clone(),
            "--port".to_owned(),
            self.launch.listen_port.to_string(),
            "--credential-env".to_owned(),
            credential_env.to_owned(),
        ];
        if self.row.kind == WorkerKind::VoxCpm2 {
            let policy = self.launch.policy_file.as_ref().ok_or_else(|| {
                permanent(
                    WorkerFailure::LoadFailed,
                    "a VoxCPM2 worker names its serving-policy file".to_owned(),
                )
            })?;
            // The worker's private directory for each render's reference.
            let run = installation.runtime_root.join("run").join(&self.row.id);
            args.extend([
                "--runtime-dir".to_owned(),
                run.display().to_string(),
                "--policy-file".to_owned(),
                policy.display().to_string(),
            ]);
        }
        Ok((env.python.clone(), args))
    }
}

/// One media worker's qualification on its provider's route, for the
/// launch `launch` names when it is managed.
pub(super) async fn probe(
    http: &ProviderHttp,
    wire_model: &str,
    expected: &WorkerSpec,
    launch: Option<&LaunchRecord>,
) -> WorkerReadiness {
    let answered = match expected.kind {
        WorkerKind::VoxCpm2 => vox_answer(http).await,
        _ => asr_answer(http, wire_model).await,
    };
    let answered = match answered {
        Ok(answered) => answered,
        Err(readiness) => return readiness,
    };
    let Some(observed) = answered.worker else {
        // An answer with no worker record, as from a VoxCPM2 worker started
        // by hand: its epoch alone, when it named one.
        let observed = answered.epoch.map(|epoch| WorkerDescriptor {
            kind: expected.kind,
            identity: CacheIdentity {
                backend_epoch: Some(epoch),
                ..CacheIdentity::default()
            },
            build_evidence: WorkerBuildEvidence::Unknown,
        });
        return WorkerReadiness::Unverified { observed };
    };
    if observed.kind != expected.kind {
        return failed(WorkerFailure::KindMismatch, Some(observed));
    }
    if answered.wire_model.as_deref() != Some(wire_model) {
        return failed(WorkerFailure::ModelMismatch, Some(observed));
    }
    if answered
        .epoch
        .as_ref()
        .is_some_and(|epoch| observed.identity.backend_epoch.as_ref() != Some(epoch))
    {
        return failed(WorkerFailure::BuildMismatch, Some(observed));
    }
    if let Some(launch) = launch {
        match answered.launch_manifest.as_deref() {
            None => {
                return WorkerReadiness::Unverified {
                    observed: Some(observed),
                };
            }
            Some(echoed) if echoed != launch.manifest_sha256 => {
                return failed(WorkerFailure::BuildMismatch, Some(observed));
            }
            Some(_) => {}
        }
    }
    judge_media(observed, &expected.expected, launch)
}

/// Whether a media worker serves as pinned: [`judge_pins`] with its model
/// and runtime required, and no template, which it never renders.
fn judge_media(
    observed: WorkerDescriptor,
    config: &CacheIdentity,
    launch: Option<&LaunchRecord>,
) -> WorkerReadiness {
    let required: [Field; 2] = [model, runtime];
    judge_pins(observed, config, launch, &required)
}

/// A VoxCPM2 worker's qualification: its `/ready` warm target, then one
/// render for exactly that target from the synthetic reference. The audio
/// must be the target's mono PCM16, and not empty.
async fn vox_answer(http: &ProviderHttp) -> Result<Answered, WorkerReadiness> {
    let ready = http
        .send_media("/ready", MediaSend::Get)
        .await
        .map_err(|_| failed(WorkerFailure::Unreachable, None))?;
    if !(200..300).contains(&ready.status) {
        return Err(failed(WorkerFailure::InvalidReply, None));
    }
    let warm = serde_json::from_slice::<WarmTarget>(&ready.body)
        .ok()
        .filter(|warm| warm.validate().is_ok())
        .ok_or_else(|| failed(WorkerFailure::InvalidReply, None))?;
    let target = json!({
        "voice_id": PROBE_VOICE,
        "owner": PROBE_VOICE,
        "register": PROBE_VOICE,
        "reference_revision": PROBE_VOICE,
        "limits": warm.limits,
        "warm": warm,
    });
    let header = serde_json::to_vec(&json!({
        "target": target,
        "text": MEDIA_PROBE_TEXT,
        "transcript": MEDIA_PROBE_TRANSCRIPT,
    }))
    .unwrap_or_default();
    let length =
        u32::try_from(header.len()).map_err(|_| failed(WorkerFailure::InvalidReply, None))?;
    let mut body = length.to_be_bytes().to_vec();
    body.extend_from_slice(&header);
    body.extend_from_slice(&qualification_wav());
    // The reference is synthetic: every resend of it may go.
    let admits: UploadAdmission = Arc::new(|| true);
    let reply = http
        .send_media("/render", MediaSend::Octets(body, admits))
        .await
        .map_err(|_| failed(WorkerFailure::Unreachable, None))?;
    if !(200..300).contains(&reply.status) {
        return Err(failed(WorkerFailure::InvalidReply, None));
    }
    let (meta, pcm) =
        render_parts(&reply.body).ok_or_else(|| failed(WorkerFailure::InvalidReply, None))?;
    if meta["target"] != target
        || meta["sample_rate"].as_u64() != Some(u64::from(warm.sample_rate))
        || meta["channels"].as_u64() != Some(1)
        || pcm.is_empty()
        || !pcm.len().is_multiple_of(2)
    {
        return Err(failed(WorkerFailure::InvalidReply, None));
    }
    Ok(Answered {
        worker: meta
            .get("worker")
            .and_then(|worker| WorkerDescriptor::deserialize(worker).ok()),
        wire_model: text(&meta, "wire_model"),
        launch_manifest: text(&meta, LAUNCH_MANIFEST_KEY),
        epoch: CacheEpoch::new(warm.boot_id.clone()).ok(),
    })
}

/// A local ASR worker's qualification: one transcription of the synthetic
/// clip, as the media client sends one. Its text may be empty: the clip is
/// silence.
async fn asr_answer(http: &ProviderHttp, wire_model: &str) -> Result<Answered, WorkerReadiness> {
    let file = reqwest::multipart::Part::bytes(qualification_wav())
        .file_name("qualification.wav")
        .mime_str("audio/wav")
        .map_err(|_| failed(WorkerFailure::InvalidReply, None))?;
    let form = reqwest::multipart::Form::new()
        .text("model", wire_model.to_owned())
        .text("response_format", "json")
        .part("file", file);
    let reply = http
        .send_media(TRANSCRIPTIONS, MediaSend::Multipart(form))
        .await
        .map_err(|_| failed(WorkerFailure::Unreachable, None))?;
    if !(200..300).contains(&reply.status) {
        return Err(failed(WorkerFailure::InvalidReply, None));
    }
    let body: JsonValue = serde_json::from_slice(&reply.body)
        .map_err(|_| failed(WorkerFailure::InvalidReply, None))?;
    if !body.get("text").is_some_and(JsonValue::is_string) {
        return Err(failed(WorkerFailure::InvalidReply, None));
    }
    let usage = body.get("usage").cloned().unwrap_or(JsonValue::Null);
    Ok(Answered {
        worker: usage
            .get(INFERENCE_CALLS_KEY)
            .and_then(|calls| calls.get(0))
            .and_then(|call| call.get("worker"))
            .and_then(|worker| WorkerDescriptor::deserialize(worker).ok()),
        wire_model: text(&body, "model"),
        launch_manifest: text(&usage, LAUNCH_MANIFEST_KEY),
        epoch: None,
    })
}

/// A render reply's JSON header and its PCM, as the worker frames them: a
/// big-endian `u32` header length, the header, then the audio.
fn render_parts(body: &[u8]) -> Option<(JsonValue, &[u8])> {
    let length = body.get(..4)?;
    let n = usize::try_from(u32::from_be_bytes(length.try_into().ok()?)).ok()?;
    let end = n.checked_add(4)?;
    let meta = serde_json::from_slice(body.get(4..end)?).ok()?;
    Some((meta, body.get(end..)?))
}

/// The qualification clip: [`MEDIA_PROBE_WAV_MS`] of silence, mono PCM16 at
/// [`MEDIA_PROBE_SAMPLE_RATE`]. Synthetic: no person's voice.
fn qualification_wav() -> Vec<u8> {
    let samples = u64::from(MEDIA_PROBE_SAMPLE_RATE) * u64::from(MEDIA_PROBE_WAV_MS) / 1_000;
    let pcm = vec![0_u8; usize::try_from(samples * 2).unwrap_or(0)];
    pcm16_wav(MEDIA_PROBE_SAMPLE_RATE, 1, &pcm).unwrap_or_default()
}

/// The string at `key` in `value`.
fn text(value: &JsonValue, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
}

fn failed(failure: WorkerFailure, observed: Option<WorkerDescriptor>) -> WorkerReadiness {
    WorkerReadiness::Failed { failure, observed }
}
