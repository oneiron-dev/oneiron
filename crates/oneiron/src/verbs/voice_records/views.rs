//! Audio-free voice-bank metadata views and record conversions.

use super::consent::{VoiceConsentBasis, VoiceConsentState};
use super::model::{VoiceIdentity, VoiceRefOrigin, VoiceRenderConsent, VoiceTargetRecord};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::ModelLocality;
use crate::memory::voice_actor::VoiceRefSubjectKind;
use serde::{Deserialize, Serialize};

/// A banked voice identity: its owner (entity hex), whether it is a real
/// person's voice or a designed one, and its packs' ids, source and
/// generated packs apart by their origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceIdentityView {
    pub version: u8,
    pub id: String,
    pub owner: String,
    pub subject_kind: VoiceRefSubjectKind,
    pub pack_ids: Vec<String>,
}

/// One banked pack without its audio or transcripts: its version, id,
/// origin, and each clip's register, media type and audio size. Every pack's
/// owner is its identity's; the bank refuses any other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoicePackSummary {
    pub version: u8,
    pub id: String,
    /// Captured under the render grant it cites, designed, or generated.
    pub origin: VoiceRefOrigin,
    pub clips: Vec<VoiceClipSummary>,
    /// Each intake row the pack's count or sizes went past, as the owner's
    /// current rows measure it; banked whole all the same.
    pub crossed: Vec<String>,
}

/// One clip of a banked pack, without its audio or transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceClipSummary {
    pub register: String,
    pub media_type: String,
    /// The clip's audio size, in bytes.
    pub audio_bytes: u64,
}

/// A voice's render decision, granted or withdrawn: whose voice it is (a
/// real person's or a designed voice's creator's) and who recorded it
/// (entity hex), when (unix seconds), how far a grant lets the refs reach,
/// how a person's was captured, its revision and its place in the voice's
/// render history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsentView {
    pub event_id: String,
    pub subject: String,
    pub subject_kind: VoiceRefSubjectKind,
    pub recorded_by: String,
    pub occurred_at: u64,
    pub reach: ModelLocality,
    /// None for a designed voice's decision recorded without one.
    pub basis: Option<VoiceConsentBasis>,
    pub state: VoiceConsentState,
    pub revision: String,
    /// From 1, in the order the voice's decisions were recorded.
    pub sequence: u64,
}

/// A target's current clone: the vendor's locator, the source packs and the
/// digest of the refs it was made from, when it was made (unix seconds),
/// and its revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetCloneView {
    pub vendor_voice_id: String,
    pub source_packs: Vec<String>,
    pub ref_digest: String,
    pub cloned_at: u64,
    pub revision: String,
    /// The vendor holds the clone until the voice is verified there (FIX
    /// 1567): no finished clone yet.
    pub awaiting_verification: bool,
}

/// How the host renders one named target, as the host states it (FIX
/// 4394): from its own recorded clone of the voice, from the bank's
/// reference clip uploaded with each call, or not at all. Each rendering
/// target's locality is the host's, never the caller's: how far the voice's
/// render consent must reach for its refs to go there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VoiceTargetRender {
    /// A hosted target that renders from its own clone, as its clone wire
    /// states it.
    HostedClone { locality: ModelLocality },
    /// A target that renders from the bank's reference clip on each call
    /// and keeps no clone (a `voxcpm2` worker).
    Reference { locality: ModelLocality },
    /// No target by that name renders on this host.
    Unconfigured,
}

/// The fence a reference target's next render binds, as its upload guard
/// compares it (FIX 4394): the identity's incarnation, the digest of the
/// refs the selection picks now and the render consent they reach the
/// target under. Metadata only: no clip, audio or transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceReferenceFenceView {
    /// The packs the selection picks, in the identity's order. A reference
    /// render selects recorded packs only.
    pub source_packs: Vec<String>,
    /// The digest of the selected packs, hex.
    pub ref_digest: String,
    /// The identity's incarnation, hex; `None` for an identity banked before
    /// incarnations were minted.
    pub incarnation: Option<String>,
    /// The revision of the render decision the refs reach the target under,
    /// hex.
    pub consent_revision: String,
    /// The reference revision a render request carries: the incarnation,
    /// the ref digest and the consent revision, hex.
    pub revision: String,
}

/// One named render target, as the bank holds it for the voice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetInspection {
    pub target: String,
    /// How the host renders the target, and where it runs.
    pub render: VoiceTargetRender,
    /// Whether the selection the clone is checked against counts generated
    /// packs.
    pub include_generated: bool,
    /// A hosted target's clone while it is current: made from the refs the
    /// selection picks now, under a render consent that reaches the target.
    /// None when none was made, it was evicted or withdrawn, or it went
    /// stale, and for any other target.
    pub current: Option<VoiceTargetCloneView>,
    /// A reference target's fence while its render would bind one: under a
    /// render consent that reaches the target, at a locality a reference
    /// may go to. None otherwise, and for any other target.
    pub reference: Option<VoiceReferenceFenceView>,
}

/// The actor's voice as the bank holds it, read from one snapshot: its
/// identity, each pack's metadata, its current render decision, and one
/// named target's current clone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankInspection {
    pub voice_id: String,
    /// None while only the voice's render decision is recorded, before its
    /// first pack is banked.
    pub identity: Option<VoiceIdentityView>,
    /// Each of the identity's packs, in its order.
    pub packs: Vec<VoicePackSummary>,
    /// None before a render decision is recorded.
    pub render_consent: Option<VoiceRenderConsentView>,
    pub target: VoiceTargetInspection,
}

/// The voice as the bank holds it, for its owner (FIX 1567), read from one
/// snapshot: its identity, each pack's metadata, its current render
/// decision, and each named target's current clone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankView {
    pub voice_id: String,
    /// None while only the voice's render decision is recorded.
    pub identity: Option<VoiceIdentityView>,
    /// Each of the identity's packs, in its order.
    pub packs: Vec<VoicePackSummary>,
    /// None before a render decision is recorded.
    pub render_consent: Option<VoiceRenderConsentView>,
    /// Each target the host names, in its order.
    pub targets: Vec<VoiceTargetInspection>,
}

impl From<&VoiceIdentity> for VoiceIdentityView {
    fn from(identity: &VoiceIdentity) -> Self {
        Self {
            version: identity.version,
            id: identity.id.clone(),
            owner: identity.owner.to_hex(),
            subject_kind: identity.subject_kind,
            pack_ids: identity.pack_ids.clone(),
        }
    }
}

impl From<VoiceRenderConsent> for VoiceRenderConsentView {
    fn from(consent: VoiceRenderConsent) -> Self {
        let decision = consent.decision;
        Self {
            event_id: decision.event_id,
            subject: decision.subject.to_hex(),
            subject_kind: decision.subject_kind,
            recorded_by: decision.recorded_by.to_hex(),
            occurred_at: decision.occurred_at,
            reach: decision.reach,
            basis: decision.basis,
            state: decision.state,
            revision: bytes_to_hex_lower(&consent.revision),
            sequence: consent.sequence,
        }
    }
}

impl From<VoiceTargetRecord> for VoiceTargetCloneView {
    fn from(record: VoiceTargetRecord) -> Self {
        Self {
            vendor_voice_id: record.vendor_voice_id,
            source_packs: record.source_packs,
            ref_digest: bytes_to_hex_lower(&record.ref_digest),
            cloned_at: record.cloned_at,
            revision: bytes_to_hex_lower(&record.revision),
            awaiting_verification: record.awaiting_verification,
        }
    }
}
