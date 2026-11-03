//! Voice-bank record vocabulary consumed by core verbs.

pub(crate) mod consent;
mod model;
mod render_history;
mod views;

pub use crate::memory::voice_actor::{VoiceBankActor, VoiceCreator, VoiceRefSubjectKind};
pub use consent::{VoiceConsentBasis, VoiceConsentState};
pub use model::{
    VoiceIdentity, VoiceRefFence, VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip,
    VoiceRenderConsent, VoiceRenderDecision, VoiceRenderGrant, VoiceTargetClone, VoiceTargetRecord,
};
pub use render_history::{
    VoiceDroppedTargetView, VoiceRenderConsentWrite, VoiceRenderEventReceipt, VoiceRenderEventView,
};
pub use views::{
    VoiceBankInspection, VoiceBankView, VoiceClipSummary, VoiceIdentityView, VoicePackSummary,
    VoiceReferenceFenceView, VoiceRenderConsentView, VoiceTargetCloneView, VoiceTargetInspection,
    VoiceTargetRender,
};
