//! Voice reference packs, render decisions and target record values.

use crate::Result;
use crate::memory::voice_actor::{VoiceRefSubjectKind, invalid, valid_id};

#[doc(hidden)]
pub use oneiron_consent_state::verbs::voice_records::model::{
    VoiceIdentity, VoiceRefFence, VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip,
    VoiceRenderConsent, VoiceRenderDecision, VoiceRenderGrant, VoiceTargetClone, VoiceTargetRecord,
};

pub(crate) fn voice_render_decision_validate(
    voice_render_decision: &VoiceRenderDecision,
) -> Result<()> {
    valid_id(&voice_render_decision.event_id)?;
    valid_id(&voice_render_decision.voice_id)?;
    if voice_render_decision.occurred_at == 0 {
        return Err(invalid("a voice render decision needs its time"));
    }
    match (
        &voice_render_decision.basis,
        voice_render_decision.subject_kind,
    ) {
        (Some(basis), _) => crate::verbs::voice_records::voice_consent_basis_validate(&basis),
        (None, VoiceRefSubjectKind::Designed) => Ok(()),
        (None, VoiceRefSubjectKind::Person) => Err(invalid(
            "a person's voice render decision needs how it was captured",
        )),
    }
}
