//! File → VAD → routed packs → one full-file diarization → cleanup → native artifact.

use std::collections::HashSet;

use serde_json::json;

use crate::ingest::MEETING_TRANSCRIPT_SCHEMA_V1;

use super::alignment::make_turns;
use super::cleanup::apply_cleanup;
use super::packing::{packed_audio, source_times};
use super::provenance::{COMMUNITY1_MODEL, execution_mode, pcm_sha256, sha256, validate_receipt};
use super::{
    AsrPackRequest, AsrRole, AudioError, AudioFile, AudioResult, BatchAsrRequest, BatchDefault,
    CleanupRequest, InferenceExecution, MeetingAudioHost, ProcessingTier,
    ProducedMeetingTranscript, ProducerOptions, TranscriptWord, align_words_to_speakers,
    pack_speech,
};

/// Produce without admitting claims, enrolling speakers, or persisting audio.
/// The returned artifact still needs explicit bulk import authorization. The
/// host is the trusted inference/transport boundary; receipts bind inputs but
/// cannot independently attest that the named model actually ran.
pub fn produce_meeting_transcript<H: MeetingAudioHost + ?Sized>(
    file: &AudioFile<'_>,
    options: &ProducerOptions,
    host: &mut H,
) -> AudioResult<ProducedMeetingTranscript> {
    validate_options(file, options)?;
    let audio = host.decode(file)?;
    let duration_ms = audio.duration_ms()?;
    if duration_ms == 0 {
        return Err(AudioError::InvalidAudio);
    }
    let source_hash = sha256(file.bytes);
    let recording_id = format!("sha256:{source_hash}");
    let pcm_hash = pcm_sha256(&audio);
    let mut invocation_ids = HashSet::new();
    let vad = host.silero_vad(&audio, &pcm_hash)?;
    validate_receipt(&vad.provenance, &pcm_hash, &mut invocation_ids)?;
    let packs = pack_speech(&vad.spans, duration_ms)?;
    let route = host.route_batch_asr(BatchAsrRequest {
        role: AsrRole::Asr,
        preferred_tier: if options.local_only {
            ProcessingTier::Local
        } else {
            ProcessingTier::HomeFleet
        },
        local_only: options.local_only,
        batch_default: &options.batch_default,
    })?;
    if route.model_id != options.batch_default.model_id()
        || route.route_receipt_ref.trim().is_empty()
        || (options.local_only && route.tier != ProcessingTier::Local)
    {
        return Err(AudioError::InvalidRoute);
    }

    let mut words = Vec::new();
    let mut pack_receipts = Vec::new();
    let mut asr_fixture = false;
    let mut aligner_model: Option<String> = None;
    let mut previous_source_end = 0;
    for pack in &packs {
        let pack_audio = packed_audio(&audio, pack)?;
        let pack_hash = pcm_sha256(&pack_audio);
        let output = host.transcribe_pack(AsrPackRequest {
            route: &route,
            pack,
            audio: &pack_audio,
            audio_sha256: &pack_hash,
            glossary: &options.glossary,
            language_hint: file.language_hint,
        })?;
        validate_receipt(&output.provenance, &pack_hash, &mut invocation_ids)?;
        if output.provenance.model_id != route.model_id
            || output.aligner_model.trim().is_empty()
            || aligner_model
                .as_ref()
                .is_some_and(|model| model != &output.aligner_model)
        {
            return Err(AudioError::InvalidProvenance);
        }
        asr_fixture |= output.provenance.execution == InferenceExecution::Fixture;
        aligner_model = Some(output.aligner_model);
        if output.words.is_empty() {
            return Err(AudioError::EmptyAsr);
        }
        let mut previous_pack_end = 0;
        for word in output.words {
            if word.start_ms < previous_pack_end
                || word.end_ms > pack.audio_ms
                || word.text.trim().is_empty()
                || word.confidence.is_some_and(|confidence| {
                    !confidence.is_finite() || !(0.0..=1.0).contains(&confidence)
                })
            {
                return Err(AudioError::InvalidWords);
            }
            let (start_ms, end_ms) = source_times(pack, word.start_ms, word.end_ms)?;
            if start_ms < previous_source_end || end_ms > duration_ms {
                return Err(AudioError::InvalidWords);
            }
            previous_pack_end = word.end_ms;
            previous_source_end = end_ms;
            words.push(TranscriptWord {
                word_id: format!("word-{:06}", words.len() + 1),
                pack_id: pack.pack_id.clone(),
                start_ms,
                end_ms,
                text: word.text.trim().to_owned(),
                confidence: word.confidence,
                speaker_cluster: String::new(),
            });
        }
        pack_receipts.push(json!({ "pack_id": pack.pack_id, "provenance": output.provenance }));
    }

    // Deliberately outside the pack loop. The host gets the original complete
    // PCM (not concatenated speech, not an ASR pack), once and only once.
    let diarization = host.community1_exclusive_full_file(&audio, &pcm_hash)?;
    validate_receipt(&diarization.provenance, &pcm_hash, &mut invocation_ids)?;
    if diarization.provenance.model_id != COMMUNITY1_MODEL {
        return Err(AudioError::InvalidProvenance);
    }
    align_words_to_speakers(&mut words, &diarization.exclusive_tracks, duration_ms)?;
    let mut turns = make_turns(&words);
    let cleanup_input = serde_json::to_vec(&turns).map_err(|_| AudioError::Serialization)?;
    let cleanup_hash = sha256(&cleanup_input);
    let cleanup = host.cleanup_turns(CleanupRequest {
        turns: &turns,
        input_sha256: &cleanup_hash,
    })?;
    validate_receipt(&cleanup.provenance, &cleanup_hash, &mut invocation_ids)?;
    apply_cleanup(&mut turns, cleanup.texts)?;
    let glossary_bytes =
        serde_json::to_vec(&options.glossary).map_err(|_| AudioError::Serialization)?;
    // All execution modes are host reports. A fixture at any stage marks the
    // run as a fixture; an E1 reference never overrides that evidence class.
    let mut execution = execution_mode(&[
        &vad.provenance,
        &diarization.provenance,
        &cleanup.provenance,
    ]);
    if asr_fixture {
        execution = InferenceExecution::Fixture;
    }
    let note_body = turns
        .iter()
        .map(|turn| turn.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let document = json!({
        "schema": MEETING_TRANSCRIPT_SCHEMA_V1,
        "recording": {
            "recording_id": recording_id,
            "source_name": file.source_name,
            "source_sha256": source_hash,
            "canonical_pcm_sha256": pcm_hash,
            "capture_started_at": file.capture_started_at,
            "duration_ms": duration_ms,
            "language_hint": file.language_hint,
        },
        "producer": {
            "asr_model": route.model_id,
            "aligner_model": aligner_model.ok_or(AudioError::EmptyAsr)?,
            "vad_model": vad.provenance.model_id,
            "glossary_sha256": sha256(&glossary_bytes),
            "batch_default": options.batch_default,
            "route": route,
            "execution": execution,
            "evidence_basis": "host_reported",
            "vad_provenance": vad.provenance,
            "asr_packs": pack_receipts,
        },
        "packs": packs,
        "words": words,
        "turns": turns,
        "cleanup": {
            "status": "turns_only",
            "policy": "lexical_content_preserving_v1",
            "provenance": cleanup.provenance,
            "summary": null,
            "decisions": [],
            "action_items": [],
            "open_questions": [],
            "garbled_spans": [],
        },
        "note_fallback": { "title": file.source_name, "body": note_body },
        "diarization": {
            "scope": "full_file",
            "track_kind": "exclusive",
            "alignment": "timestamp_iou",
            "provenance": diarization.provenance,
            "tracks": diarization.exclusive_tracks,
        },
        "identity": null,
    });
    let json = serde_json::to_string(&document).map_err(|_| AudioError::Serialization)?;
    ProducedMeetingTranscript::new(json, recording_id)
}

fn validate_options(file: &AudioFile<'_>, options: &ProducerOptions) -> AudioResult<()> {
    if file.bytes.is_empty() {
        return Err(AudioError::InvalidAudio);
    }
    if file.source_name.trim().is_empty()
        || file
            .language_hint
            .is_some_and(|hint| hint.trim().is_empty())
        || options.batch_default.model_id().trim().is_empty()
        || options.glossary.iter().any(|entry| entry.trim().is_empty())
        || matches!(&options.batch_default, BatchDefault::MeasuredE1 { evidence_ref, .. }
            if evidence_ref.trim().is_empty())
    {
        return Err(AudioError::InvalidOptions);
    }
    Ok(())
}
