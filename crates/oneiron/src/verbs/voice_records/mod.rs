//! Voice-bank record vocabulary consumed by core verbs.

pub(crate) mod consent;
mod model;
mod views;
mod render_history;

pub use consent::{VoiceConsentBasis, VoiceConsentState};
pub use crate::memory::voice_actor::{VoiceBankActor, VoiceCreator, VoiceRefSubjectKind};
pub use model::{VoiceRefOrigin, VoiceRegisterClip, VoiceRefPack, VoiceIdentity, VoiceTargetClone, VoiceRenderDecision, VoiceRenderConsent, VoiceRenderGrant, VoiceTargetRecord, VoiceRefFence};
pub use views::{VoiceIdentityView, VoicePackSummary, VoiceClipSummary, VoiceRenderConsentView, VoiceTargetCloneView, VoiceTargetRender, VoiceReferenceFenceView, VoiceTargetInspection, VoiceBankInspection, VoiceBankView};
pub use render_history::{VoiceRenderEventReceipt, VoiceRenderConsentWrite, VoiceRenderEventView, VoiceDroppedTargetView};
