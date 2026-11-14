//! Moved from `crates/oneiron/src/verbs/voice_records/render_history.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::verbs::voice_records::views::VoiceRenderConsentView;
use crate::verbs::voice_records::views::VoiceTargetCloneView;
use oneiron_consent_state::verbs::voice_records::model::VoiceRenderConsent;
use oneiron_consent_state::verbs::voice_records::model::VoiceTargetRecord;
use serde::Deserialize;
use serde::Serialize;

/// One recorded render decision, as the bank keeps it: the decision with its
/// revision and sequence, and each target pointer it dropped from the bank.
/// What the vendors did with those clones happens after the decision commits
/// and is not kept here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderEventReceipt {
    pub consent: VoiceRenderConsent,
    pub evicted: Vec<VoiceTargetRecord>,
}

/// One render decision in a voice's history, metadata only: the decision as
/// [`VoiceRenderConsentView`] shows it, with its revision and sequence, and
/// each target clone it dropped. No reference audio, transcript or provider
/// configuration, and no vendor's deletion outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderEventView {
    pub voice_id: String,
    pub decision: VoiceRenderConsentView,
    /// The target pointers this decision dropped from the bank: a
    /// withdrawal's, else none.
    pub dropped: Vec<VoiceDroppedTargetView>,
}

/// A target pointer a render decision dropped: the target and its clone as
/// the bank held it then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceDroppedTargetView {
    pub target: String,
    pub held: VoiceTargetCloneView,
}

impl From<VoiceRenderEventReceipt> for VoiceRenderEventView {
    fn from(receipt: VoiceRenderEventReceipt) -> Self {
        Self {
            voice_id: receipt.consent.decision.voice_id.clone(),
            decision: VoiceRenderConsentView::from(receipt.consent),
            dropped: receipt
                .evicted
                .into_iter()
                .map(|record| VoiceDroppedTargetView {
                    target: record.target.clone(),
                    held: VoiceTargetCloneView::from(record),
                })
                .collect(),
        }
    }
}
