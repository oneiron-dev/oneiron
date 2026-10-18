//! The owner's voice-bank rows (DOOR-143, e2e VOICE-02): `vault.voices.packs.put`
//! banks a reference pack of the owner's own voice, `.render_consent` records
//! its render decision, `.targets.provision` and `.targets.evict` make or drop
//! a hosted target's clone, and `.inspect` reads the bank's metadata for one
//! target. The identity is the bank's, and a provider voice id only an
//! evictable pointer (ARCH-0061 §5). The proven owner is the voice's subject
//! and the decision's recorder, so no input names either; the bank refuses
//! another person's voice. Only the pack put runs on an embedded handle: the
//! rest need a host's clone wires, their localities and their paid runs.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::llm::ModelLocality;
use crate::memory::{MemoryError, MemoryResult};
use crate::voice_identity::ref_bank::{
    VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip, VoiceRenderConsent, VoiceRenderDecision,
    VoiceTargetRecord,
};
use crate::voice_identity::{VoiceConsentBasis, VoiceConsentState};

pub use crate::voice_identity::ref_bank::{
    VoiceBankInspection, VoiceClipSummary, VoiceIdentityView, VoicePackSummary,
    VoiceRenderConsentView, VoiceTargetCloneView, VoiceTargetInspection,
};

/// The pack version a door banks: the bank's one version.
const VOICE_PACK_VERSION: u8 = 1;

/// One reference clip on the wire, as `/v1/ai/voices/{voice_id}/packs` takes
/// it too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankClipInput {
    /// The register the clip shows, unique in its pack.
    pub register: String,
    /// An `audio/*` media type.
    pub media_type: String,
    /// The clip's audio, standard base64.
    pub audio: String,
    /// What the clip says.
    pub transcript: String,
}

/// `vault.voices.packs.put`'s input: one immutable pack of the owner's own
/// voice. The first source pack makes the identity; a retry of the same pack
/// is a no-op, and a different pack under its id refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankPackPutRequest {
    pub voice_id: String,
    pub pack_id: String,
    /// `captured` cites the owner's current render grant by its event id;
    /// `designed` names its design tool's vendor; `generated` adds AI-made
    /// refs to a banked identity and never stands in for its source.
    pub origin: VoiceRefOrigin,
    pub clips: Vec<VoiceBankClipInput>,
}

/// What a pack put banked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankPackReceipt {
    pub voice_id: String,
    pub pack_id: String,
}

/// `vault.voices.render_consent`'s input: the owner's render decision on
/// their own voice. It may come before the first pack, which cites a grant
/// by its event id. A replay of the current decision is a no-op; an older
/// one refuses. Recognition consent never stands in for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsentRequest {
    pub voice_id: String,
    /// The decision's own id.
    pub event_id: String,
    /// When the decision was made, in unix seconds.
    pub occurred_at: u64,
    /// The farthest render target a grant lets the refs reach.
    pub reach: ModelLocality,
    /// How the decision was captured.
    pub basis: VoiceConsentBasis,
    pub state: VoiceConsentState,
}

/// What a render decision recorded: its state, reach and fresh revision
/// (lowercase hex), and each target clone a withdrawal dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsentReceipt {
    pub voice_id: String,
    pub state: VoiceConsentState,
    pub reach: ModelLocality,
    pub revision: String,
    pub evicted: Vec<VoiceVendorEviction>,
}

/// One target clone a withdrawal dropped, and what its vendor did with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceVendorEviction {
    pub target: String,
    pub vendor_voice_id: String,
    pub vendor: VoiceVendorDeleteStatus,
}

/// What a vendor did with a clone the bank dropped. The bank drops its
/// pointer first, so a clone the vendor kept is no current clone of the
/// voice, whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceVendorDeleteStatus {
    /// The vendor deleted the clone, or it was already gone.
    Deleted,
    /// No configured clone wire reaches the target now: the clone may
    /// remain at the vendor.
    NoCloneWire,
    /// The vendor's delete failed: the clone may remain at the vendor.
    DeleteFailed,
    /// The bank held no clone pointer for the target.
    Absent,
}

/// `vault.voices.targets.provision`'s input: the voice and the configured
/// hosted target to clone it at. The target's locality is the host's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetProvisionRequest {
    pub voice_id: String,
    pub target: String,
    /// Whether generated packs join the source packs the clone is made from.
    #[serde(default)]
    pub include_generated: bool,
    /// The language the clips are spoken in, for a target that asks.
    #[serde(default)]
    pub language: Option<String>,
}

/// A target's current clone: the vendor's locator, when it was made, and
/// its fresh revision (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetReceipt {
    pub voice_id: String,
    pub target: String,
    pub vendor_voice_id: String,
    /// Unix seconds.
    pub cloned_at: u64,
    pub revision: String,
}

/// `vault.voices.targets.evict`'s input: the voice and the target whose
/// clone to drop. The identity and its packs stay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetEvictRequest {
    pub voice_id: String,
    pub target: String,
}

/// What an eviction dropped: whether the bank held a clone pointer, and what
/// its vendor did with the clone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetEvictReceipt {
    pub voice_id: String,
    pub target: String,
    pub evicted: bool,
    pub vendor: VoiceVendorDeleteStatus,
}

/// `vault.voices.inspect`'s input: the voice, and the configured hosted
/// target whose current clone to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankInspectRequest {
    pub voice_id: String,
    pub target: String,
    /// Whether the selection the clone is checked against counts generated
    /// packs, as the provisioning that made it did.
    #[serde(default)]
    pub include_generated: bool,
}

/// `vault.voices.packs.put` under the owner's proof: the pack's owner is the
/// proof's person, which the bank revalidates in its write.
pub fn put_voice_bank_pack_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: VoiceBankPackPutRequest,
) -> MemoryResult<VoiceBankPackReceipt> {
    let clips = decode_voice_bank_clips(input.clips)?;
    let pack = VoiceRefPack {
        version: VOICE_PACK_VERSION,
        id: input.pack_id,
        voice_id: input.voice_id,
        owner: owner.actor_for_read(vault)?,
        origin: input.origin,
        clips,
    };
    vault.store_voice_ref_pack_as(owner, &pack)?;
    Ok(VoiceBankPackReceipt {
        voice_id: pack.voice_id,
        pack_id: pack.id,
    })
}

/// The clips' audio decoded from base64; a clip whose audio is not base64
/// refuses.
pub fn decode_voice_bank_clips(
    clips: Vec<VoiceBankClipInput>,
) -> MemoryResult<Vec<VoiceRegisterClip>> {
    clips
        .into_iter()
        .map(|clip| {
            let audio = STANDARD
                .decode(clip.audio.as_bytes())
                .map_err(|_| MemoryError::bad_request("a clip's audio is base64"))?;
            Ok(VoiceRegisterClip {
                register: clip.register,
                media_type: clip.media_type,
                audio,
                transcript: clip.transcript,
            })
        })
        .collect()
}

/// `vault.voices.render_consent`'s bank write under the owner's proof: the
/// decision's subject and recorder are the proof's person, which the bank
/// revalidates in its write. Beside the recorded decision, the target
/// pointers a withdrawal dropped, for the host to delete at their vendors.
pub fn record_own_render_consent(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: VoiceRenderConsentRequest,
) -> MemoryResult<(VoiceRenderConsent, Vec<VoiceTargetRecord>)> {
    let person = owner.actor_for_read(vault)?;
    let decision = VoiceRenderDecision {
        event_id: input.event_id,
        voice_id: input.voice_id,
        subject: person,
        recorded_by: person,
        occurred_at: input.occurred_at,
        reach: input.reach,
        basis: input.basis,
        state: input.state,
    };
    Ok(vault.record_voice_render_consent_as(owner, &decision)?)
}

/// `vault.voices.targets.evict`'s bank write under the owner's proof: the
/// dropped pointer, for the host to delete its clone at the vendor.
pub fn evict_own_voice_target(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &VoiceTargetEvictRequest,
) -> MemoryResult<Option<VoiceTargetRecord>> {
    Ok(vault.evict_voice_target_as(owner, &input.voice_id, &input.target)?)
}

/// `vault.voices.inspect` under the owner's proof, at the `locality` the
/// host's clone wire for the target states. A voice the bank holds nothing
/// of is not found.
pub fn inspect_voice_bank_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &VoiceBankInspectRequest,
    locality: ModelLocality,
) -> MemoryResult<VoiceBankInspection> {
    vault
        .inspect_voice_bank(
            owner,
            &input.voice_id,
            &input.target,
            input.include_generated,
            locality,
        )?
        .ok_or_else(|| MemoryError::not_found("no voice is banked or consented under that id"))
}
