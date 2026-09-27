//! Host-run meeting-audio adapter: one file to a normalized artifact, never a consent grant.
//! See scripts/meeting-audio-adapter/SKILL.md for provisioning and policy boundaries.

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oneiron::ingest::meeting_audio::{
    AsrRole, AsrRoute, AudioFile, BatchDefault, CohortManifest, CommandAudioConfig,
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

fn read_glossary(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if fs::metadata(path)?.len() > 128 * 1024 {
        return Err("glossary file too large".into());
    }
    let glossary: Vec<String> = serde_json::from_slice(&fs::read(path)?)?;
    if glossary.len() > 256
        || glossary
            .iter()
            .any(|entry| entry.trim().is_empty() || entry.len() > 512)
    {
        return Err("invalid glossary".into());
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
    let options = ProducerOptions {
        glossary: read_glossary(&config.glossary)?,
        batch_default: batch_default(&config.routes.asr, config.measured_e1.as_ref())?,
        local_only: true,
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
        stage_timeout: Duration::from_secs(900),
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
mod tests {
    use super::*;
    use oneiron::claim::{ClaimApprovalStatus, ClaimSource};

    #[test]
    fn adapter_registration_stays_imported_and_matches_the_harness() {
        let source = INGEST_SOURCE_REGISTRY
            .get_config(MEETING_TRANSCRIPT_SOURCE_ID)
            .unwrap();
        assert_eq!(
            KNOWN_INGEST_HARNESS_CONFIG.get_config(MEETING_TRANSCRIPT_SOURCE_ID),
            Some(source)
        );
        assert_eq!(
            source
                .adapter_skill
                .map(|skill| (skill.skill_id, skill.version)),
            Some(("builtin.ingest.meeting-transcript", "1"))
        );
        assert_eq!(source.trust_ceiling.claim_source, ClaimSource::Imported);
        assert_eq!(source.default_admission, ClaimApprovalStatus::Proposed);
        assert!(!source.trust_ceiling.permits_auto(Some(0)));
    }

    fn route(id: &str, revision: &str) -> ModelRoute {
        ModelRoute {
            model_id: id.into(),
            model_revision: revision.into(),
            route_receipt_ref: "host-of133:receipt".into(),
            execution: RouteExecution::Native,
        }
    }

    #[test]
    fn no_selection_receipt_keeps_the_host_selected_model_provisional() {
        let selected = route("custom/asr-beta", "rev-42");
        assert_eq!(
            batch_default(&selected, None).unwrap().model_id(),
            "custom/asr-beta"
        );
        assert!(matches!(
            batch_default(&selected, None).unwrap(),
            BatchDefault::Provisional { .. }
        ));
    }

    #[test]
    fn missing_route_receipt_refuses_before_inference() {
        let mut routes = ModelRoutes {
            asr: route("model-a", "rev-a"),
            aligner: route("model-b", "rev-b"),
            diarization: route("model-c", "rev-c"),
            cleanup: route("model-d", "rev-d"),
        };
        routes.aligner.route_receipt_ref.clear();
        assert!(routes.validate().is_err());
        routes.aligner.route_receipt_ref = "host-of133:receipt".into();
        routes.asr.route_receipt_ref.clear();
        assert!(batch_default(&routes.asr, None).is_err());
    }

    #[test]
    fn remote_model_refuses_native_host_cleanly() {
        let mut routes = ModelRoutes {
            asr: route("model-a", "rev-a"),
            aligner: route("model-b", "rev-b"),
            diarization: route("model-c", "rev-c"),
            cleanup: route("model-d", "rev-d"),
        };
        routes.asr.execution = RouteExecution::Remote;
        assert!(
            routes
                .require_native_profile(Path::new("/missing/profile"), "sha256")
                .is_err()
        );
    }

    #[test]
    fn glossary_policy_is_loaded_from_a_file_and_rejects_blank_terms() {
        let temp = std::env::temp_dir().join(format!(
            "oneiron-audio-glossary-{}.json",
            uuid::Uuid::new_v4()
        ));
        fs::write(&temp, "[\"Alice\",\"製品名\"]").unwrap();
        assert_eq!(read_glossary(&temp).unwrap(), ["Alice", "製品名"]);
        fs::write(&temp, r#"["Alice"," "]"#).unwrap();
        assert!(read_glossary(&temp).is_err());
        fs::remove_file(temp).unwrap();
    }

    #[test]
    fn e1_default_accepts_three_arbitrary_arms_and_rejects_foreign_winner() {
        use oneiron::ingest::meeting_audio::CohortFile;
        use serde_json::json;

        let dir = std::env::temp_dir().join(format!("oneiron-audio-e1-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let mut cohort = CohortManifest {
            corpus_id: "fixture-only-not-measured".into(),
            cohort_sha256: "0".repeat(64),
            files: vec![CohortFile {
                file_id: "synthetic".into(),
                audio_sha256: "a".repeat(64),
                reference_sha256: "b".repeat(64),
                consent_ref: "fixture-not-consent".into(),
            }],
        };
        cohort.cohort_sha256 = cohort.computed_hash().unwrap();
        let cohort_path = dir.join("cohort.json");
        let selection_path = dir.join("selection.json");
        fs::write(&cohort_path, serde_json::to_vec(&cohort).unwrap()).unwrap();
        let arm = |model_id: &str, revision: &str| {
            json!({
                "model_id": model_id,
                "model_revision": revision,
                "model_sha256": "c".repeat(64),
                "runtime_sha256": "d".repeat(64),
                "wer_by_lang": {"English": {
                    "substitutions": 0, "deletions": 0,
                    "insertions": 0, "reference_len": 1
                }}
            })
        };
        let mut receipt = json!({
            "corpus_id": cohort.corpus_id,
            "corpus_sha256": cohort.cohort_sha256,
            "arms": [arm("vendor-a", "r1"), arm("vendor-b", "r2"), arm("vendor-c", "r3")],
            "winner": "vendor-c"
        });
        let binding = MeasuredE1 {
            cohort: cohort_path,
            selection: selection_path.clone(),
            evidence_ref: "fixture-only-not-an-of133-act".into(),
        };
        let write = |value: &serde_json::Value| {
            fs::write(&selection_path, serde_json::to_vec(value).unwrap()).unwrap();
        };
        write(&receipt);
        assert_eq!(
            batch_default(&route("vendor-c", "r3"), Some(&binding))
                .unwrap()
                .model_id(),
            "vendor-c"
        );
        assert!(batch_default(&route("vendor-c", "wrong-revision"), Some(&binding)).is_err());
        assert!(batch_default(&route("vendor-a", "r1"), Some(&binding)).is_err());
        receipt["winner"] = "outside-the-arms".into();
        write(&receipt);
        assert!(batch_default(&route("outside-the-arms", "r4"), Some(&binding)).is_err());
        receipt["winner"] = "vendor-c".into();
        receipt["arms"] = json!([arm("vendor-c", "r3")]);
        write(&receipt);
        assert!(batch_default(&route("vendor-c", "r3"), Some(&binding)).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn native_profile_binds_all_four_route_models_and_revisions() {
        use serde_json::json;
        let dir =
            std::env::temp_dir().join(format!("oneiron-audio-route-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("profile.json");
        let routes = ModelRoutes {
            asr: route("custom-asr", "rev-a"),
            aligner: route("custom-aligner", "rev-b"),
            diarization: route("custom-diarizer", "rev-c"),
            cleanup: route("custom-cleanup", "rev-d"),
        };
        let profile = json!({
            "asr": {"model_id":"custom-asr", "snapshot":"/models/rev-a"},
            "alignment": {"model_id":"custom-aligner", "snapshot":"/models/rev-b"},
            "diarization": {"model_id":"custom-diarizer", "snapshot":"/models/rev-c"},
            "cleanup": {"model_id":"custom-cleanup", "snapshot":"/models/rev-d"}
        });
        let bytes = serde_json::to_vec(&profile).unwrap();
        fs::write(&path, &bytes).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        routes.require_native_profile(&path, &digest).unwrap();
        let mut changed = profile;
        changed["cleanup"]["snapshot"] = "wrong-revision".into();
        let bytes = serde_json::to_vec(&changed).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(
            routes
                .require_native_profile(&path, &format!("{:x}", Sha256::digest(&bytes)))
                .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
