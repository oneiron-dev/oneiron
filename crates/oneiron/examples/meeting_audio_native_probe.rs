//! Manual native-port proof. No model downloads, identity or consent grant.
//! Run only on the host that owns an already installed interpreter/model.

use std::path::PathBuf;

use oneiron::ingest::meeting_audio::{
    AsrRole, AsrRoute, AudioError, AudioFile, BatchDefault, CommandAudioConfig,
    CommandMeetingAudioHost, ProcessingTier, ProducerOptions, produce_meeting_transcript,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 7 {
        return Err(
            "expected: PYTHON BRIDGE FFMPEG WORKSPACE MODEL_SNAPSHOT MP4 ROUTE_RECEIPT".into(),
        );
    }
    let config = CommandAudioConfig {
        python: PathBuf::from(&args[0]),
        bridge: PathBuf::from(&args[1]),
        ffmpeg: PathBuf::from(&args[2]),
        workspace: PathBuf::from(&args[3]),
        model_snapshot: PathBuf::from(&args[4]),
        stage_timeout: std::time::Duration::from_secs(900),
    };
    let model_id = "mlx-community/Qwen3-ASR-1.7B-8bit".to_owned();
    // Caller supplies its own receipt. A diagnostic run identifier is NOT a
    // claim of authenticated OF-133 selection or an E1 model-default decision.
    let route = AsrRoute {
        role: AsrRole::Asr,
        model_id: model_id.clone(),
        tier: ProcessingTier::Local,
        route_receipt_ref: args[6].clone(),
    };
    let mut host = CommandMeetingAudioHost::new(config, route)?;
    let bytes = std::fs::read(&args[5])?;
    let file = AudioFile {
        bytes: &bytes,
        source_name: "public-synthetic-speech.mp4",
        capture_started_at: None,
        language_hint: Some("English"),
    };
    let options = ProducerOptions {
        glossary: vec!["notebook".into(), "station".into()],
        batch_default: BatchDefault::Provisional { model_id },
        local_only: true,
    };
    match produce_meeting_transcript(&file, &options, &mut host) {
        Err(AudioError::Host { stage, code })
            if stage == "transcribe_pack" && code == "ForcedAlignmentUnavailable" =>
        {
            // Expected native limitation. stdout is one machine-readable result,
            // not a transcript with invented words/speaker labels/approval.
            serde_json::to_writer(
                std::io::stdout().lock(),
                &serde_json::json!({
                    "native_producer": "refused", "stage": "transcribe_pack",
                    "code": "ForcedAlignmentUnavailable", "artifact": null,
                }),
            )?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err("unexpected artifact: this installed host has no aligner/community-1".into()),
    }
}
