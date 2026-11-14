//! Audio-free voice-bank metadata views and record conversions.

use super::consent::{VoiceConsentBasis, VoiceConsentState};
use super::model::{VoiceIdentity, VoiceRefOrigin, VoiceRenderConsent, VoiceTargetRecord};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::ModelLocality;
use crate::memory::voice_actor::VoiceRefSubjectKind;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::voice_records::views::{
    VoiceBankInspection, VoiceBankView, VoiceClipSummary, VoiceIdentityView, VoicePackSummary,
    VoiceReferenceFenceView, VoiceRenderConsentView, VoiceTargetCloneView, VoiceTargetInspection,
    VoiceTargetRender,
};
