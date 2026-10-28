//! Stored-pack integrity and new-intake measurement (FIX 10177, FIX 10220).
//! Entry: validate_pack_integrity.
//!
//! A stored pack or target pointer is checked for what makes it the row it
//! says it is: its ids, its version, its origin's provenance, clips that are
//! audio, each under a register of its own. It is never checked against the
//! owner's adjustable intake rows, so a row lowered after a pack was banked
//! leaves the pack readable, and its render withdrawal and its clones'
//! eviction always read it. A new pack's clip count and sizes, and a new
//! clone's vendor id, are measured against those rows: past one, the work is
//! banked whole and the crossing is reported, never refused (Rule 5).

use std::collections::BTreeSet;

use super::{VoiceRefOrigin, VoiceRefPack, VoiceTargetRecord, invalid, valid_id};
use crate::error::Result;
use crate::voice_identity::ref_limits::VoiceRefLimits;

/// A provider value's integrity: present, and no NUL, which a key joins on.
fn valid_provider_value(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.contains('\0') {
        return Err(invalid("invalid voice provider value"));
    }
    Ok(())
}

/// Whether `pack` is the pack it says it is: valid ids, a known version, an
/// origin whose provenance is named, at least one clip, and each clip audio,
/// non-empty, under a register no other clip of the pack holds. Its size,
/// count and text lengths are not judged here.
pub(super) fn validate_pack_integrity(pack: &VoiceRefPack) -> Result<()> {
    valid_id(&pack.id)?;
    valid_id(&pack.voice_id)?;
    if pack.version != 1 {
        return Err(invalid("unsupported voice reference pack version"));
    }
    match &pack.origin {
        VoiceRefOrigin::Designed { vendor } => valid_provider_value(vendor)?,
        VoiceRefOrigin::Captured { consent_event_ref } => valid_id(consent_event_ref)?,
        VoiceRefOrigin::Generated => {}
    }
    if pack.clips.is_empty() {
        return Err(invalid("invalid voice reference pack size"));
    }
    let mut names = BTreeSet::new();
    for clip in &pack.clips {
        if clip.register.trim().is_empty()
            || !names.insert(&clip.register)
            || !clip.media_type.starts_with("audio/")
            || clip.audio.is_empty()
        {
            return Err(invalid("invalid voice reference clip"));
        }
    }
    Ok(())
}

/// Whether `record` is the target pointer of `voice_id` at `target` it says
/// it is: its keys match, it was cloned at a time, from named packs, and its
/// vendor id is present. The vendor id's length is not judged here.
pub(super) fn validate_target_integrity(
    record: &VoiceTargetRecord,
    voice_id: &str,
    target: &str,
) -> Result<()> {
    if record.voice_id != voice_id
        || record.target != target
        || record.cloned_at == 0
        || record.source_packs.is_empty()
        || valid_provider_value(&record.vendor_voice_id).is_err()
    {
        return Err(invalid("corrupt voice target clone"));
    }
    Ok(())
}

/// What one new pack measured against its owner's intake rows: its clip
/// count and audio bytes, and each row it went past.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct VoicePackIntake {
    pub(super) clips: u64,
    pub(super) audio_bytes: u64,
    pub(super) crossed: Vec<&'static str>,
}

/// Each intake row `pack` goes past under `limits`, in row order, without
/// tracing: the inspection reads it, the bank traces it where it banks.
pub(super) fn pack_intake_crossed(
    pack: &VoiceRefPack,
    limits: VoiceRefLimits,
) -> Vec<&'static str> {
    let clips = pack.clips.len() as u64;
    let audio_bytes = pack.clips.iter().fold(0u64, |total, clip| {
        total.saturating_add(clip.audio.len() as u64)
    });
    let mut crossed = Vec::new();
    if clips > limits.max_clips_per_pack {
        crossed.push("max_clips_per_pack");
    }
    if audio_bytes > limits.max_audio_bytes_per_pack {
        crossed.push("max_audio_bytes_per_pack");
    }
    if pack
        .clips
        .iter()
        .any(|clip| clip.register.len() as u64 > limits.max_register_bytes)
    {
        crossed.push("max_register_bytes");
    }
    if pack
        .clips
        .iter()
        .any(|clip| clip.transcript.len() as u64 > limits.max_transcript_bytes)
    {
        crossed.push("max_transcript_bytes");
    }
    if let VoiceRefOrigin::Designed { vendor } = &pack.origin
        && vendor.len() as u64 > limits.max_design_vendor_bytes
    {
        crossed.push("max_design_vendor_bytes");
    }
    crossed
}

/// Measures a new pack against `limits`. A row it goes past is reported, and
/// the pack is banked whole all the same: a count or size row measures and
/// paces new intake, and never refuses valid work (Rule 5).
pub(super) fn measure_pack_intake(pack: &VoiceRefPack, limits: VoiceRefLimits) -> VoicePackIntake {
    let clips = pack.clips.len() as u64;
    let audio_bytes = pack.clips.iter().fold(0u64, |total, clip| {
        total.saturating_add(clip.audio.len() as u64)
    });
    let crossed = pack_intake_crossed(pack, limits);
    let intake = VoicePackIntake {
        clips,
        audio_bytes,
        crossed,
    };
    if !intake.crossed.is_empty() {
        tracing::info!(
            clips = intake.clips,
            audio_bytes = intake.audio_bytes,
            rows = ?intake.crossed,
            "a voice reference pack went past its measured intake rows; banked whole"
        );
    }
    intake
}

/// Measures a new clone's vendor id against `limits`: past its row it is
/// reported and recorded all the same, so the clone it names can always be
/// evicted.
pub(super) fn measure_target_intake(record: &VoiceTargetRecord, limits: VoiceRefLimits) {
    if record.vendor_voice_id.len() as u64 > limits.max_vendor_voice_id_bytes {
        tracing::info!(
            row = "max_vendor_voice_id_bytes",
            "a voice target clone's vendor id went past its measured row; recorded whole"
        );
    }
}
