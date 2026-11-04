//! Voice reference packs, render decisions and target record values.

use super::consent::{VoiceConsentBasis, VoiceConsentState};
use crate::llm::ModelLocality;
use crate::memory::voice_actor::{VoiceRefSubjectKind, invalid, valid_id};
use crate::{EntityId, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VoiceRefOrigin {
    /// Recorded from the person, under the render consent decision it cites:
    /// the subject's current grant when the pack is banked.
    Captured { consent_event_ref: String },
    /// Samples captured from a design tool. The captured audio, not its vendor ID, is ours.
    Designed { vendor: String },
    /// AI-made audio added to an existing identity; never replaces its source pack.
    Generated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceRegisterClip {
    pub register: String,
    pub media_type: String,
    pub audio: Vec<u8>,
    pub transcript: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceRefPack {
    pub version: u8,
    pub id: String,
    pub voice_id: String,
    #[serde(with = "crate::llm::entity_refs")]
    pub owner: EntityId,
    pub origin: VoiceRefOrigin,
    pub clips: Vec<VoiceRegisterClip>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceIdentity {
    pub version: u8,
    pub id: String,
    /// The real person whose voice it is, or a designed voice's creator.
    #[serde(with = "crate::llm::entity_refs")]
    pub owner: EntityId,
    /// Bound when the identity is born, from the voice's render decision or
    /// its first designed pack; a later pack never relabels it.
    pub subject_kind: VoiceRefSubjectKind,
    /// Source and generated pack IDs are kept separate by their persisted origin tags.
    pub pack_ids: Vec<String>,
}

/// The material to submit to one render target. No vendor ID is an input to this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceTargetClone {
    pub voice_id: String,
    pub target: String,
    pub source_packs: Vec<String>,
    pub clips: Vec<VoiceRegisterClip>,
    pub ref_digest: [u8; 32],
    pub include_generated: bool,
    /// The render consent that lets these refs reach the target.
    pub grant: VoiceRenderGrant,
}

/// The subject's decision on letting a banked voice be rendered from its
/// refs: provisioned as a target's clone, or uploaded to a target that
/// renders from them on each call. It is apart from recognition consent:
/// neither grants the other. A designed voice's creator decides for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderDecision {
    pub event_id: String,
    pub voice_id: String,
    /// Whose voice it is: the identity's owner, a real person or a designed
    /// voice's creator as `subject_kind` says.
    #[serde(with = "crate::llm::entity_refs")]
    pub subject: EntityId,
    pub subject_kind: VoiceRefSubjectKind,
    #[serde(with = "crate::llm::entity_refs")]
    pub recorded_by: EntityId,
    pub occurred_at: u64,
    /// The farthest render target a grant lets the refs reach: the device,
    /// the owner's own server, or a third party.
    pub reach: ModelLocality,
    /// How a person's decision was captured; a designed voice needs none.
    pub basis: Option<VoiceConsentBasis>,
    pub state: VoiceConsentState,
}

impl VoiceRenderDecision {
    pub(crate) fn validate(&self) -> Result<()> {
        valid_id(&self.event_id)?;
        valid_id(&self.voice_id)?;
        if self.occurred_at == 0 {
            return Err(invalid("a voice render decision needs its time"));
        }
        match (&self.basis, self.subject_kind) {
            (Some(basis), _) => basis.validate(),
            (None, VoiceRefSubjectKind::Designed) => Ok(()),
            (None, VoiceRefSubjectKind::Person) => Err(invalid(
                "a person's voice render decision needs how it was captured",
            )),
        }
    }
}

/// A voice's current render decision, as the bank keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsent {
    pub version: u8,
    pub decision: VoiceRenderDecision,
    /// Fresh on every decision. Selections and bindings fence on it, so a
    /// withdrawal or a narrower grant never leaves an older one current.
    pub revision: [u8; 16],
    /// The decision's place in the voice's render history, from 1: one past
    /// the decision current when it was recorded. Decisions made at the same
    /// time order by it.
    pub sequence: u64,
}

/// The render consent a selection was admitted under: its revision, and the
/// locality of the target it covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceRenderGrant {
    pub revision: [u8; 16],
    pub locality: ModelLocality,
}

/// A cached target pointer, valid only while its selected refs still match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetRecord {
    pub voice_id: String,
    pub target: String,
    pub vendor_voice_id: String,
    pub source_packs: Vec<String>,
    pub ref_digest: [u8; 32],
    pub cloned_at: u64,
    /// Fresh on every new or replaced record. A hosted binding fences on it, so a
    /// withdrawn and re-recorded target cannot revive an older binding.
    pub revision: [u8; 16],
    /// The vendor holds the clone until the voice is verified there (FIX 1567):
    /// no finished clone yet.
    #[serde(default)]
    pub awaiting_verification: bool,
}

/// A target that uploads the banked refs with every request keeps no provider
/// record to fence on. It binds to the identity's incarnation, minted when the
/// identity is born and deleted with it, and to the digest of its selected refs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoiceRefFence {
    pub owner: EntityId,
    /// None only for an identity banked before incarnations were minted. Every
    /// rebirth mints one, so such a fence never matches a re-banked identity.
    pub incarnation: Option<[u8; 16]>,
    pub ref_digest: [u8; 32],
    pub include_generated: bool,
    /// The render consent the refs reach the target under.
    pub grant: VoiceRenderGrant,
}
