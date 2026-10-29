//! A call's speakers matched in production (FIX 3344). The sibling sends the
//! diarized segment embeddings it heard (`speakers`), and the host resolves
//! them into the voice roster the call's hello named, as one live, partial
//! run: a speaker it did not hear this time stays as last placed (OF-365
//! ruling a). The roster's speakers then enter the call's room as
//! `roster_changed` enters them. The owner's departure act (`depart`)
//! retires one speaker of that roster by its key (FIX 1522).
//! Entry: `VoiceHost::match_speakers`, `VoiceHost::depart_speaker`.

use std::sync::Arc;

use oneiron::Vault;
use oneiron::voice_cascade::VoiceSessionConfig;
use oneiron::voice_identity::{
    VoiceMatchPolicy, VoiceMatchRequest, VoicePrintPurpose, VoiceRunCoverage,
    VoiceSegmentEmbeddingInput, VoiceSessionRosterV1, VoiceSpeakerDeparture,
};

use super::{HostError, VoiceHost};

/// The linkage threshold a live call's unplaced speakers cluster at (CALLS,
/// FIX 3344).
const LIVE_RESIDUAL_THRESHOLD: f32 = 0.7;

/// The voice roster a call's speakers are matched under: the hello's roster
/// ref, and the call's own ref, which names each run's recording.
pub(super) struct CallRoster {
    vault: Arc<Vault>,
    roster_ref: String,
    call_ref: String,
}

impl CallRoster {
    /// The roster `session`'s hello named; `None` for a call that named none.
    pub(super) fn of(vault: &Arc<Vault>, session: &VoiceSessionConfig) -> Option<Self> {
        Some(Self {
            vault: Arc::clone(vault),
            roster_ref: session.interlocutors.voice_session_ref.clone()?,
            call_ref: session.session_ref.clone(),
        })
    }
}

impl VoiceHost {
    /// Resolves `segments`, heard on this call, into the call's roster: its
    /// enrolled speakers by their prints for a live interlocutor, the rest
    /// clustered. A call whose hello named no roster, or no segments, is an
    /// invalid request.
    pub(super) fn match_speakers(
        &self,
        segments: Vec<VoiceSegmentEmbeddingInput>,
    ) -> Result<VoiceSessionRosterV1, HostError> {
        self.require_running()?;
        let roster = self.roster.as_ref().ok_or(HostError::InvalidRequest)?;
        let space_id = segments
            .first()
            .map(|segment| segment.space_id.clone())
            .ok_or(HostError::InvalidRequest)?;
        let request = VoiceMatchRequest {
            voice_session_ref: roster.roster_ref.clone(),
            recording_id: roster.call_ref.clone(),
            space_id,
            segments,
            // A live call has no invite list, so elimination names no one.
            invite_attendee_refs: Vec::new(),
            policy: VoiceMatchPolicy::with_known_default(LIVE_RESIDUAL_THRESHOLD),
            created_at: roster.vault.now_recorded_at(),
            purpose: VoicePrintPurpose::LiveInterlocutor,
            coverage: VoiceRunCoverage::Partial,
        };
        Ok(roster.vault.resolve_voice_segments(&request)?)
    }

    /// The owner's departure act for `speaker_key` on the call's roster. A
    /// call whose hello named no roster is an invalid request.
    pub(super) fn depart_speaker(
        &self,
        speaker_key: &str,
    ) -> Result<VoiceSpeakerDeparture, HostError> {
        self.require_running()?;
        let roster = self.roster.as_ref().ok_or(HostError::InvalidRequest)?;
        Ok(roster
            .vault
            .depart_voice_speaker(&roster.roster_ref, speaker_key)?)
    }
}
