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
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyOverride {
    glossary_max_bytes: Option<usize>,
    glossary_max_terms: Option<usize>,
    glossary_max_term_bytes: Option<usize>,
    stage_timeout_seconds: Option<u64>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyManifest {
    vault: Option<PolicyOverride>,
    holder: Option<PolicyOverride>,
}

impl PolicyLimits {
    fn resolve(path: Option<&Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let defaults: Self = serde_json::from_str(include_str!(
            "../../../scripts/meeting-audio-adapter/policy-defaults.json"
        ))?;
        defaults.validate_substrate()?;
        let Some(path) = path else {
            return Ok(defaults);
        };
        if fs::metadata(path)?.len() > 64 * 1024 {
            return Err("policy manifest exceeds configuration ceiling".into());
        }
        let manifest: PolicyManifest = serde_json::from_slice(&fs::read(path)?)?;
        let vault = defaults.apply(manifest.vault.unwrap_or_default());
        vault.validate_substrate()?;
        let holder = vault.apply(manifest.holder.unwrap_or_default());
        holder.validate_substrate()?;
        if holder.glossary_max_bytes > vault.glossary_max_bytes
            || holder.glossary_max_terms > vault.glossary_max_terms
            || holder.glossary_max_term_bytes > vault.glossary_max_term_bytes
            || holder.stage_timeout_seconds > vault.stage_timeout_seconds
        {
            return Err("holder policy cannot widen the vault ceiling".into());
        }
        Ok(holder)
    }

    fn apply(&self, policy: PolicyOverride) -> Self {
        Self {
            glossary_max_bytes: policy.glossary_max_bytes.unwrap_or(self.glossary_max_bytes),
            glossary_max_terms: policy.glossary_max_terms.unwrap_or(self.glossary_max_terms),
            glossary_max_term_bytes: policy
                .glossary_max_term_bytes
                .unwrap_or(self.glossary_max_term_bytes),
            stage_timeout_seconds: policy
                .stage_timeout_seconds
                .unwrap_or(self.stage_timeout_seconds),
        }
    }

    fn validate_substrate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // These are protocol/process ceilings, not workload defaults.
        if self.glossary_max_bytes == 0
            || self.glossary_max_bytes > 512 * 1024
            || self.glossary_max_terms == 0
            || self.glossary_max_terms > 10000
            || self.glossary_max_term_bytes == 0
            || self.glossary_max_term_bytes > 512 * 1024
            || self.stage_timeout_seconds == 0
            || self.stage_timeout_seconds > 7200
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
        assert_eq!(
            read_glossary(&temp, &PolicyLimits::resolve(None).unwrap()).unwrap(),
            ["Alice", "製品名"]
        );
        fs::write(&temp, r#"["Alice"," "]"#).unwrap();
        assert!(read_glossary(&temp, &PolicyLimits::resolve(None).unwrap()).is_err());
        fs::remove_file(temp).unwrap();
    }

    #[test]
    fn policy_rows_allow_nondefault_workloads_but_holder_cannot_widen_vault() {
        let dir =
            std::env::temp_dir().join(format!("oneiron-audio-policy-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let policy_path = dir.join("policy.json");
        let glossary_path = dir.join("glossary.json");
        let terms = (0..257).map(|n| format!("term-{n}")).collect::<Vec<_>>();
        fs::write(&glossary_path, serde_json::to_vec(&terms).unwrap()).unwrap();
        fs::write(&policy_path, r#"{"vault":{"glossary_max_terms":300,"stage_timeout_seconds":1800},"holder":{"glossary_max_terms":260,"stage_timeout_seconds":1200}}"#).unwrap();
        let resolved = PolicyLimits::resolve(Some(&policy_path)).unwrap();
        assert_eq!(resolved.stage_timeout_seconds, 1200);
        assert_eq!(read_glossary(&glossary_path, &resolved).unwrap(), terms);
        fs::write(
            &policy_path,
            r#"{"vault":{"stage_timeout_seconds":1800},"holder":{"stage_timeout_seconds":1801}}"#,
        )
        .unwrap();
        assert!(PolicyLimits::resolve(Some(&policy_path)).is_err());
        fs::write(&policy_path, r#"{"vault":{"stage_timeout_seconds":7201}}"#).unwrap();
        assert!(PolicyLimits::resolve(Some(&policy_path)).is_err());
        fs::remove_dir_all(dir).unwrap();
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
        let relative = MeasuredE1 {
            cohort: PathBuf::from("relative-cohort.json"),
            selection: selection_path.clone(),
            evidence_ref: "fixture-only".into(),
        };
        assert!(batch_default(&route("vendor-c", "r3"), Some(&relative)).is_err());
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
    #[test]
    fn packaged_mp4_fixture_emits_normalizable_artifact_and_survives_consent_handoff() {
        use oneiron::ingest::meeting_audio::{
            BulkImportAuthorizer, BulkImportBinding, BulkImportReceipt, ProducedMeetingTranscript,
        };
        use serde_json::json;

        struct OwnerConsent {
            allow: bool,
            seen: Vec<BulkImportBinding>,
        }
        impl BulkImportAuthorizer for OwnerConsent {
            fn vault_scope(&self) -> &str {
                "fixture-owner-vault"
            }
            fn authorize_import(
                &mut self,
                binding: &BulkImportBinding,
            ) -> oneiron::ingest::meeting_audio::AudioResult<Option<BulkImportReceipt>>
            {
                self.seen.push(binding.clone());
                Ok(self.allow.then(|| BulkImportReceipt {
                    binding: binding.clone(),
                    receipt_ref: "fixture-owner-approved".into(),
                }))
            }
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let media =
            root.join("crates/oneiron/tests/fixtures/ingest/native_audio/public-speech.mp4");
        let pcm =
            root.join("crates/oneiron/tests/fixtures/ingest/native_audio/public-speech.pcm16.zlib");
        let dir =
            std::env::temp_dir().join(format!("oneiron-audio-adapter-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let bridge = dir.join("fixture-host.py");
        fs::copy(
            root.join("scripts/meeting-audio-adapter/fixture-host.py"),
            &bridge,
        )
        .unwrap();
        fs::copy(
            root.join("scripts/meeting_audio_runtime.py"),
            dir.join("meeting_audio_runtime.py"),
        )
        .unwrap();
        let snapshot = dir.join("asr-revision");
        fs::create_dir(&snapshot).unwrap();
        let mk_spec = |id: &str, rev: &str| json!({"model_id":id,"snapshot":dir.join(rev)});
        let prompt = dir.join("cleanup-v1.txt");
        fs::write(&prompt, "Fix only ASR-backed words: {{TRANSCRIPT_JSON}}").unwrap();
        let glossary = dir.join("glossary.json");
        fs::write(&glossary, r#"["Ada","製品名"]"#).unwrap();
        let profile = json!({
            "asr": mk_spec("fixture-asr", "asr-revision"),
            "alignment": mk_spec("fixture-aligner", "aligner-revision"),
            "diarization": mk_spec("fixture-alternative-diarizer", "diarizer-revision"),
            "cleanup": {"model_id":"fixture-cleanup", "snapshot":dir.join("cleanup-revision"),
                        "instructions":prompt,"instructions_sha256":format!("{:x}", Sha256::digest(fs::read(&prompt).unwrap()))},
            "fixture_mp4_sha256": format!("{:x}", Sha256::digest(fs::read(&media).unwrap())),
            "fixture_pcm_sha256": "5e0f5f5721d8b79cfc91fe0fa0cc67dc37b495eec93c2706d02940dc9527cb8d",
            "fixture_pcm_zlib": pcm,
        });
        let profile_path = dir.join("profile.json");
        let bytes = serde_json::to_vec(&profile).unwrap();
        fs::write(&profile_path, &bytes).unwrap();
        let python = PathBuf::from("/usr/bin/python3");
        let output = dir.join("meeting-transcript.json");
        let routes = ModelRoutes {
            asr: route("fixture-asr", "asr-revision"),
            aligner: route("fixture-aligner", "aligner-revision"),
            diarization: route("fixture-alternative-diarizer", "diarizer-revision"),
            cleanup: route("fixture-cleanup", "cleanup-revision"),
        };
        run(AdapterConfig {
            python: python.clone(),
            bridge,
            // The fixture consumes retained PCM, so it does not execute this path.
            ffmpeg: python,
            workspace: dir.clone(),
            model_snapshot: snapshot,
            runtime_profile: profile_path,
            runtime_profile_sha256: format!("{:x}", Sha256::digest(bytes)),
            audio: media,
            output: output.clone(),
            language_hint: "English".into(),
            capture_started_at: None,
            glossary,
            policy_manifest: None,
            routes,
            measured_e1: None,
        })
        .unwrap();
        let saved = fs::read_to_string(output).unwrap();
        let document: serde_json::Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(document["schema"], "oneiron.meeting_transcript.v1");
        assert_eq!(document["producer"]["execution"], "fixture");
        assert_eq!(
            document["diarization"]["provenance"]["model_id"],
            "fixture-alternative-diarizer"
        );
        assert_eq!(document["words"][0]["text"], "allice");
        assert_eq!(document["turns"][0]["text"], "Alice.");
        let artifact = ProducedMeetingTranscript::from_json(saved.clone()).unwrap();
        let normalized = INGEST_SOURCE_REGISTRY
            .normalize(MEETING_TRANSCRIPT_SOURCE_ID, artifact.json())
            .unwrap();
        assert_eq!(normalized.records.len(), 1);
        assert!(normalized.claims.is_empty());
        let mut pending = OwnerConsent {
            allow: false,
            seen: Vec::new(),
        };
        assert!(artifact.authorize_import(&mut pending).is_err());
        let mut approved = OwnerConsent {
            allow: true,
            seen: Vec::new(),
        };
        let imported = artifact.authorize_import(&mut approved).unwrap();
        assert_eq!(approved.seen[0], pending.seen[0]);
        assert_eq!(
            approved.seen[0].artifact_sha256,
            format!("{:x}", Sha256::digest(saved.as_bytes()))
        );
        assert_eq!(imported.normalized().records.len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
