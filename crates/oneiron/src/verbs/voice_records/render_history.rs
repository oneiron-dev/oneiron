//! Render-decision receipts and metadata-only history views.

use super::model::VoiceTargetRecord;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::voice_records::render_history::{
    VoiceDroppedTargetView, VoiceRenderEventReceipt, VoiceRenderEventView,
};

/// What recording a render decision did: its event's receipt, whether the
/// decision was already recorded under its event id, and the target
/// pointers this call dropped. A replay drops none, so no caller deletes a
/// vendor's clone, or evicts a later target, twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceRenderConsentWrite {
    pub receipt: VoiceRenderEventReceipt,
    pub replayed: bool,
    pub newly_evicted: Vec<VoiceTargetRecord>,
}
