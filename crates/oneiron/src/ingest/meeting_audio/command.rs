//! Optional process adapter for an explicitly configured native meeting-audio host.
//!
//! The executable is trusted host configuration, never recording metadata. The
//! caller supplies an OF-133 route receipt; this adapter does not invent one.
//! The bundled offline bridge refuses missing forced alignment/community-1.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use super::provenance::sha256;
use super::{
    AsrOutput, AsrPackRequest, AsrRoute, AsrWord, AudioError, AudioFile, AudioResult,
    BatchAsrRequest, CleanupOutput, CleanupRequest, GlobalDiarization, InferenceExecution,
    InferenceProvenance, MeetingAudioHost, Pcm16, ProcessingTier, SpeakerTrack, SpeechSpan,
    VadOutput,
};

mod process;

const PROTOCOL: &str = "oneiron.meeting_audio.host.v1";
const MAX_HEADER: usize = 1024 * 1024;
const MAX_INPUT: usize = 256 * 1024 * 1024;
const MAX_PCM: usize = 2 * 16000 * 7200;

/// Native process configuration. Every path is absolute and host-owned.
/// No launcher, shell, remote URL, package installer or model downloader runs.
/// Configure `python` as the existing environment's interpreter itself.
#[derive(Debug, Clone)]
pub struct CommandAudioConfig {
    pub python: PathBuf,
    pub bridge: PathBuf,
    pub ffmpeg: PathBuf,
    pub workspace: PathBuf,
    pub model_snapshot: PathBuf,
    /// Bound for one native port call, including output and process shutdown.
    pub stage_timeout: std::time::Duration,
}

/// Capability data reported by a configured bridge. This is not qualification
/// or an authorization to run a model or change the ASR role's default.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAudioCapabilities {
    pub packages: std::collections::BTreeMap<String, Option<String>>,
    pub asr_model_id: String,
    pub asr_snapshot: String,
    pub operations: Vec<String>,
    pub artifact_capable: bool,
    pub missing: Vec<String>,
    pub e1_e3_evidence: bool,
    pub python_executable: String,
    pub python_version: String,
    pub script_sha256: String,
    #[serde(default)]
    pub runtime_profile_sha256: Option<String>,
    #[serde(default)]
    pub runtime_helper_sha256: Option<String>,
}
impl NativeAudioCapabilities {
    fn require_artifact(&self) -> AudioResult<()> {
        if !self.artifact_capable
            || !self.missing.is_empty()
            || [
                "decode",
                "silero_vad",
                "transcribe_pack",
                "community1_exclusive_full_file",
                "cleanup_turns",
            ]
            .iter()
            .any(|required| !self.operations.iter().any(|op| op == required))
        {
            return Err(host_error("capabilities", "ArtifactBackendUnavailable"));
        }
        Ok(())
    }
}

/// Concrete [`MeetingAudioHost`] bridge. Spawns one isolated native call per
/// port; it cannot carry transcript history between ASR requests. Reuse of model
/// weights in a persistent process is a later host optimization, not a promise.
pub struct CommandMeetingAudioHost {
    config: CommandAudioConfig,
    route: AsrRoute,
    runtime_profile: Option<(PathBuf, String)>,
}

impl CommandMeetingAudioHost {
    /// `route` must come from the caller's authenticated OF-133 selection.
    /// This local-only backend refuses fleet/hosted routes rather than claiming
    /// inference ran on another tier. The engine checks the batch-default pin.
    pub fn new(config: CommandAudioConfig, route: AsrRoute) -> AudioResult<Self> {
        let files = [&config.python, &config.bridge, &config.ffmpeg];
        let dirs = [&config.workspace, &config.model_snapshot];
        if files.iter().any(|p| !p.is_absolute() || !p.is_file())
            || dirs.iter().any(|p| !p.is_absolute() || !p.is_dir())
            || config.stage_timeout.is_zero()
            || config.stage_timeout > std::time::Duration::from_secs(7200)
            || route.tier != ProcessingTier::Local
            || route.model_id.trim().is_empty()
            || route.route_receipt_ref.trim().is_empty()
        {
            return Err(AudioError::InvalidOptions);
        }
        Ok(Self {
            config,
            route,
            runtime_profile: None,
        })
    }

    /// Bind optional native ports to a host-owned, hash-pinned runtime profile.
    /// The profile is data, not consent, qualification or ASR-selection authority.
    /// The bridge requires local snapshots and exact runtime/file fingerprints.
    pub fn with_runtime_profile(mut self, path: PathBuf, digest: String) -> AudioResult<Self> {
        validate_runtime_profile(&path, &digest)?;
        self.runtime_profile = Some((path, digest));
        Ok(self)
    }

    /// Inspect the native bridge without inference. A configured profile may
    /// hash local model files, but does not load a model or acquire any bytes.
    pub fn inspect_capabilities(&self) -> AudioResult<NativeAudioCapabilities> {
        let reply = self.call("capabilities", &[], json!({}))?;
        let capabilities: NativeAudioCapabilities = serde_json::from_value(reply.result)
            .map_err(|_| host_error("capabilities", "InvalidCapabilities"))?;
        let script = std::fs::read(&self.config.bridge)
            .map_err(|_| host_error("capabilities", "BridgeReadFailed"))?;
        if capabilities.script_sha256 != sha256(&script)
            || capabilities.asr_model_id != self.route.model_id
            || Path::new(&capabilities.asr_snapshot) != self.config.model_snapshot
        {
            return Err(host_error("capabilities", "CapabilityBindingMismatch"));
        }
        if capabilities.runtime_profile_sha256.as_ref()
            != self.runtime_profile.as_ref().map(|(_, digest)| digest)
        {
            return Err(host_error("capabilities", "RuntimeProfileBindingMismatch"));
        }
        if let Some(expected) = &capabilities.runtime_helper_sha256 {
            let helper = self
                .config
                .bridge
                .with_file_name("meeting_audio_runtime.py");
            let bytes = std::fs::read(helper)
                .map_err(|_| host_error("capabilities", "RuntimeHelperReadFailed"))?;
            if &sha256(&bytes) != expected {
                return Err(host_error("capabilities", "RuntimeHelperBindingMismatch"));
            }
        } else if self.runtime_profile.is_some() {
            return Err(host_error("capabilities", "RuntimeHelperBindingMismatch"));
        }
        Ok(capabilities)
    }

    fn call(&self, stage: &str, body: &[u8], options: Value) -> AudioResult<Reply> {
        if body.len() > MAX_INPUT {
            return Err(host_error(stage, "InputTooLarge"));
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let header = json!({
            "protocol": PROTOCOL, "request_id": request_id, "operation": stage,
            "input_bytes": body.len(), "input_sha256": sha256(body), "options": options,
        });
        let mut encoded = serde_json::to_vec(&header).map_err(|_| AudioError::Serialization)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_HEADER {
            return Err(host_error(stage, "RequestTooLarge"));
        }
        // A private request file avoids blocking-pipe write/read deadlocks for
        // full recordings. Unique, create_new, 0600 on Unix; removed on every
        // normal return. This scratch area is not the vault or an import door.
        let (scratch, mut input) = RequestFile::create(&self.config.workspace, stage)?;
        input
            .write_all(&encoded)
            .and_then(|()| input.write_all(body))
            .and_then(|()| input.seek(SeekFrom::Start(0)).map(|_| ()))
            .map_err(|_| host_error(stage, "RequestIo"))?;
        let mut command = Command::new(&self.config.python);
        command
            .arg(&self.config.bridge)
            .arg("--workspace")
            .arg(&self.config.workspace)
            .arg("--ffmpeg")
            .arg(&self.config.ffmpeg)
            .arg("--model-snapshot")
            .arg(&self.config.model_snapshot)
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .current_dir(&self.config.workspace)
            .stdin(Stdio::from(input));
        if let Some((path, digest)) = &self.runtime_profile {
            validate_runtime_profile(path, digest)?;
            command
                .arg("--runtime-profile")
                .arg(path)
                .arg("--runtime-profile-sha256")
                .arg(digest);
        }
        let (success, output) = process::capture(
            &mut command,
            MAX_PCM + MAX_HEADER,
            self.config.stage_timeout,
        )
        .map_err(|code| host_error(stage, code))?;
        drop(scratch);
        parse_reply(stage, &request_id, success, output)
    }

    fn pcm_call(
        &self,
        stage: &str,
        audio: &Pcm16,
        digest: &str,
        options: Value,
    ) -> AudioResult<Reply> {
        if audio.samples.is_empty() || audio.samples.len() > MAX_PCM / 2 {
            return Err(AudioError::InvalidAudio);
        }
        let bytes: Vec<u8> = audio.samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        if sha256(&bytes) != digest {
            return Err(AudioError::InvalidProvenance);
        }
        self.call(stage, &bytes, options)
    }
}

impl MeetingAudioHost for CommandMeetingAudioHost {
    fn preflight_artifact(&mut self) -> AudioResult<()> {
        self.inspect_capabilities()?.require_artifact()
    }
    fn decode(&mut self, file: &AudioFile<'_>) -> AudioResult<Pcm16> {
        let output = self.call("decode", file.bytes, json!({}))?;
        if output.result["sample_rate"] != 16000
            || output.result["channels"] != 1
            || output.result["format"] != "s16le"
            || output.body.is_empty()
            || !output.body.len().is_multiple_of(2)
            || output.result["samples"].as_u64() != Some((output.body.len() / 2) as u64)
            || output.result["pcm_sha256"].as_str() != Some(sha256(&output.body).as_str())
        {
            return Err(AudioError::InvalidAudio);
        }
        Ok(Pcm16 {
            samples: output
                .body
                .chunks_exact(2)
                .map(|s| i16::from_le_bytes([s[0], s[1]]))
                .collect(),
        })
    }

    fn silero_vad(&mut self, audio: &Pcm16, digest: &str) -> AudioResult<VadOutput> {
        let reply = self.pcm_call("silero_vad", audio, digest, json!({}))?;
        let spans = array(&reply.result, "spans")?
            .iter()
            .map(|s| {
                Ok(SpeechSpan {
                    start_ms: number(s, "start_ms")?,
                    end_ms: number(s, "end_ms")?,
                })
            })
            .collect::<AudioResult<_>>()?;
        Ok(VadOutput {
            spans,
            provenance: receipt(&reply.result)?,
        })
    }

    fn route_batch_asr(&mut self, request: BatchAsrRequest<'_>) -> AudioResult<AsrRoute> {
        if self.route.model_id != request.batch_default.model_id()
            || self.route.role != request.role
        {
            return Err(AudioError::InvalidRoute);
        }
        Ok(self.route.clone())
    }

    fn transcribe_pack(&mut self, request: AsrPackRequest<'_>) -> AudioResult<AsrOutput> {
        if request.route.model_id != self.route.model_id
            || request.route.tier != self.route.tier
            || request.route.role != self.route.role
            || request.route.route_receipt_ref != self.route.route_receipt_ref
        {
            return Err(AudioError::InvalidRoute);
        }
        // Only acoustic word alignment can produce AsrWord values. An absent
        // pinned runtime or unsupported alignment language refuses the call.
        let reply = self.pcm_call(
            "transcribe_pack",
            request.audio,
            request.audio_sha256,
            json!({
                "model_id": request.route.model_id, "glossary": request.glossary,
                "language_hint": request.language_hint,
            }),
        )?;
        let words = array(&reply.result, "words")?
            .iter()
            .map(|word| {
                let confidence = match word.get("confidence") {
                    Some(Value::Null) => None,
                    Some(Value::Number(value)) => {
                        Some(value.as_f64().ok_or(AudioError::InvalidWords)?)
                    }
                    _ => return Err(AudioError::InvalidWords),
                };
                Ok(AsrWord {
                    start_ms: number(word, "start_ms")?,
                    end_ms: number(word, "end_ms")?,
                    text: text(word, "text")?,
                    confidence,
                })
            })
            .collect::<AudioResult<_>>()?;
        Ok(AsrOutput {
            words,
            aligner_model: text(&reply.result, "aligner_model")?,
            provenance: receipt(&reply.result)?,
        })
    }

    fn community1_exclusive_full_file(
        &mut self,
        audio: &Pcm16,
        digest: &str,
    ) -> AudioResult<GlobalDiarization> {
        let reply = self.pcm_call("community1_exclusive_full_file", audio, digest, json!({}))?;
        let exclusive_tracks = array(&reply.result, "exclusive_tracks")?
            .iter()
            .map(|s| {
                Ok(SpeakerTrack {
                    start_ms: number(s, "start_ms")?,
                    end_ms: number(s, "end_ms")?,
                    speaker_cluster: text(s, "speaker_cluster")?,
                })
            })
            .collect::<AudioResult<_>>()?;
        Ok(GlobalDiarization {
            exclusive_tracks,
            provenance: receipt(&reply.result)?,
        })
    }

    fn cleanup_turns(&mut self, request: CleanupRequest<'_>) -> AudioResult<CleanupOutput> {
        let bytes = serde_json::to_vec(request.turns).map_err(|_| AudioError::Serialization)?;
        if sha256(&bytes) != request.input_sha256 {
            return Err(AudioError::InvalidProvenance);
        }
        let reply = self.call("cleanup_turns", &bytes, json!({}))?;
        let texts = array(&reply.result, "texts")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or(AudioError::Serialization)
            })
            .collect::<AudioResult<_>>()?;
        Ok(CleanupOutput {
            texts,
            provenance: receipt(&reply.result)?,
        })
    }
}

fn validate_runtime_profile(path: &Path, digest: &str) -> AudioResult<()> {
    if !path.is_absolute()
        || !path.is_file()
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || std::fs::metadata(path)
            .map_err(|_| host_error("runtime_profile", "ProfileReadFailed"))?
            .len()
            > MAX_HEADER as u64
    {
        return Err(host_error("runtime_profile", "InvalidProfile"));
    }
    let bytes =
        std::fs::read(path).map_err(|_| host_error("runtime_profile", "ProfileReadFailed"))?;
    if sha256(&bytes) != digest {
        return Err(host_error("runtime_profile", "ProfileDigestMismatch"));
    }
    Ok(())
}

struct RequestFile(PathBuf);

impl RequestFile {
    fn create(workspace: &Path, stage: &str) -> AudioResult<(Self, File)> {
        let path = workspace.join(format!(".audio-request-{}", uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|_| host_error(stage, "RequestIo"))?;
        Ok((Self(path), file))
    }
}

impl Drop for RequestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct Reply {
    result: Value,
    body: Vec<u8>,
}

fn parse_reply(stage: &str, request_id: &str, success: bool, bytes: Vec<u8>) -> AudioResult<Reply> {
    let newline = bytes
        .iter()
        .position(|b| *b == b'\n')
        .filter(|n| *n < MAX_HEADER)
        .ok_or_else(|| host_error(stage, "InvalidResponse"))?;
    let header: Value = serde_json::from_slice(&bytes[..newline])
        .map_err(|_| host_error(stage, "InvalidResponse"))?;
    let body = &bytes[newline + 1..];
    if header["protocol"] != PROTOCOL
        || header["request_id"] != request_id
        || header["body_bytes"].as_u64() != Some(body.len() as u64)
        || (stage != "decode" && !body.is_empty())
    {
        return Err(host_error(stage, "InvalidResponse"));
    }
    if header["ok"] == false {
        let code = header["error"]["code"]
            .as_str()
            .filter(|code| !code.is_empty() && code.len() <= 128)
            .ok_or_else(|| host_error(stage, "InvalidResponse"))?;
        return Err(host_error(stage, code));
    }
    if !success || header["ok"] != true || !header["result"].is_object() {
        return Err(host_error(stage, "InvalidResponse"));
    }
    Ok(Reply {
        result: header["result"].clone(),
        body: body.to_vec(),
    })
}

fn array<'a>(value: &'a Value, key: &str) -> AudioResult<&'a Vec<Value>> {
    value[key].as_array().ok_or(AudioError::Serialization)
}

fn number(value: &Value, key: &str) -> AudioResult<u64> {
    value[key].as_u64().ok_or(AudioError::Serialization)
}

fn text(value: &Value, key: &str) -> AudioResult<String> {
    value[key]
        .as_str()
        .map(str::to_owned)
        .ok_or(AudioError::Serialization)
}

fn receipt(value: &Value) -> AudioResult<InferenceProvenance> {
    let value = &value["provenance"];
    let execution = match value["execution"].as_str() {
        Some("measured") => InferenceExecution::Measured,
        Some("fixture") => InferenceExecution::Fixture,
        _ => return Err(AudioError::InvalidProvenance),
    };
    Ok(InferenceProvenance {
        invocation_id: text(value, "invocation_id")?,
        model_id: text(value, "model_id")?,
        input_sha256: text(value, "input_sha256")?,
        execution,
    })
}

fn host_error(stage: &str, code: &str) -> AudioError {
    AudioError::Host {
        stage: stage.to_owned(),
        code: code.to_owned(),
    }
}

#[cfg(test)]
mod tests;
