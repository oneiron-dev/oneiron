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

const QWEN: &str = "mlx-community/Qwen3-ASR-1.7B-8bit";
const SONIOX: &str = "soniox/async";

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
    /// Supplied by the authenticated host's OF-133 router, not minted here.
    route_receipt_ref: String,
    /// Absent until a real E1 cohort, both arms and a separate OF-133 selection act exist.
    measured_e1: Option<MeasuredE1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasuredE1 {
    cohort: PathBuf,
    selection: PathBuf,
    evidence_ref: String,
}

fn batch_default(
    measured: Option<&MeasuredE1>,
) -> Result<BatchDefault, Box<dyn std::error::Error>> {
    let Some(measured) = measured else {
        return Ok(BatchDefault::Provisional {
            model_id: QWEN.to_owned(),
        });
    };
    if measured.evidence_ref.trim().is_empty() {
        return Err("missing E1 evidence reference".into());
    }
    let cohort = CohortManifest::parse(&fs::read_to_string(&measured.cohort)?)?;
    let selection = E1SelectionReceipt::parse(&fs::read_to_string(&measured.selection)?)?;
    selection.validate_for_cohort(&cohort)?;
    // The offline native bridge only implements Qwen; never substitute the
    // Soniox winning arm or invent a compatible local model from an E1 score.
    if selection.winner != QWEN {
        return Err("E1 winner is not supported by the configured native bridge".into());
    }
    if selection.arms.len() != 2
        || !selection.arms.iter().any(|arm| arm.model_id == QWEN)
        || !selection.arms.iter().any(|arm| arm.model_id == SONIOX)
    {
        return Err("E1 selection must compare Qwen against Soniox async".into());
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
    if config.route_receipt_ref.trim().is_empty() || config.language_hint.trim().is_empty() {
        return Err("missing route receipt or language".into());
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
        batch_default: batch_default(config.measured_e1.as_ref())?,
        local_only: true,
    };
    let route = AsrRoute {
        role: AsrRole::Asr,
        model_id: QWEN.to_owned(),
        tier: ProcessingTier::Local,
        route_receipt_ref: config.route_receipt_ref,
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

    #[test]
    fn no_selection_receipt_keeps_batch_default_provisional() {
        assert_eq!(batch_default(None).unwrap().model_id(), QWEN);
        assert!(matches!(
            batch_default(None).unwrap(),
            BatchDefault::Provisional { .. }
        ));
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
    fn e1_default_requires_bound_two_arm_receipt_and_rejects_soniox_winner() {
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
        let arm = |model_id: &str| {
            json!({
                "model_id": model_id,
                "model_revision": "fixture",
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
            "arms": [arm(QWEN), arm(SONIOX)],
            "winner": QWEN
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
        assert!(matches!(
            batch_default(Some(&binding)).unwrap(),
            BatchDefault::MeasuredE1 { .. }
        ));
        receipt["winner"] = SONIOX.into();
        write(&receipt);
        assert!(batch_default(Some(&binding)).is_err());
        receipt["winner"] = QWEN.into();
        receipt["arms"][1]["model_id"] = "not-soniox".into();
        write(&receipt);
        assert!(batch_default(Some(&binding)).is_err());
        receipt["arms"][1]["model_id"] = SONIOX.into();
        receipt["corpus_sha256"] = "e".repeat(64).into();
        write(&receipt);
        assert!(batch_default(Some(&binding)).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
