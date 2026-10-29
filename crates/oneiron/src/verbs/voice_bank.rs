//! The voice-bank rows (DOOR-143, e2e VOICE-02, FIX 4393, 4396):
//! `vault.voices.packs.put` banks a reference pack of the actor's own voice,
//! `.render_consent` records its render decision, `.targets.provision` and
//! `.targets.evict` make or drop a hosted target's clone, `.inspect` reads the
//! bank's metadata for one target, and `.lineage` reads the voice's render
//! history. The identity is the bank's, and a provider voice id only an
//! evictable pointer (ARCH-0061 §5). The actor is a real person on their own
//! person proof, owner of the vault or not, or a designed (synthetic) voice's
//! creator on its credential, the owner by default; it is the voice's subject
//! or creator and the decision's recorder, so no input names either, and the
//! bank refuses another's voice. The pack put and the lineage read run on an
//! embedded handle (FIX 8973): the rest need a host's clone wires, their
//! localities and their paid runs.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::llm::ModelLocality;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::voice_identity::ref_bank::{
    VoiceBankActor, VoiceRefOrigin, VoiceRefPack, VoiceRefSubjectKind, VoiceRegisterClip,
    VoiceRenderConsentWrite, VoiceRenderDecision, VoiceTargetRecord,
};
use crate::voice_identity::{VoiceConsentBasis, VoiceConsentState};

pub use crate::voice_identity::ref_bank::{
    VoiceBankInspection, VoiceClipSummary, VoiceDroppedTargetView, VoiceIdentityView,
    VoicePackSummary, VoiceReferenceFenceView, VoiceRenderConsentView, VoiceRenderEventView,
    VoiceTargetCloneView, VoiceTargetInspection, VoiceTargetRender,
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

/// `vault.voices.packs.put`'s input: one immutable pack of the actor's own
/// voice. The first source pack makes the identity; a retry of the same pack
/// is a no-op, and a different pack under its id refuses. The bank, not the
/// input, decides whether the voice is a person's or a designed one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceBankPackPutRequest {
    pub voice_id: String,
    pub pack_id: String,
    /// `captured` cites the subject's current render grant, a person's, by
    /// its event id; `designed` names its design tool's vendor; `generated`
    /// adds AI-made refs to a banked identity and never stands in for its
    /// source.
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

/// `vault.voices.render_consent`'s input: the actor's render decision on
/// their own voice, a real person's on their own person proof or a designed
/// voice's creator's. It may come before the first pack, which cites a
/// grant by its event id. A replay of a recorded decision answers its
/// original receipt; a different decision under its event id, or one older
/// than the current decision, refuses. Recognition consent never stands in
/// for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsentRequest {
    pub voice_id: String,
    /// The decision's own id, unique within the voice's render history.
    pub event_id: String,
    /// When the decision was made, in unix seconds.
    pub occurred_at: u64,
    /// The farthest render target a grant lets the refs reach.
    pub reach: ModelLocality,
    /// Whether the voice is the actor's own real voice (`person`, when
    /// absent) or a designed one they created (`designed`). The bank binds
    /// it when it first holds the voice; a person's voice takes the person's
    /// own proof.
    #[serde(default = "VoiceRefSubjectKind::input_default")]
    pub subject_kind: VoiceRefSubjectKind,
    /// How a person's decision was captured; a designed voice's needs none.
    #[serde(default)]
    pub basis: Option<VoiceConsentBasis>,
    pub state: VoiceConsentState,
}

/// What a render decision recorded: its state, reach, revision and event id,
/// its place in the voice's render history, whether it replays a decision
/// already recorded, and each target clone this call dropped. The revision
/// and sequence are the original decision's on a replay, which drops none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsentReceipt {
    pub voice_id: String,
    pub state: VoiceConsentState,
    pub reach: ModelLocality,
    /// Lowercase hex.
    pub revision: String,
    pub event_id: String,
    /// From 1, in the order the voice's decisions were recorded.
    pub sequence: u64,
    pub replayed: bool,
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
/// voice, whatever this says. The voice's render history keeps the dropped
/// pointer, not this.
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

/// `vault.voices.inspect`'s input: the voice, and the target to read it
/// for: a hosted target's current clone, a reference target's fence, or a
/// target this host does not render (FIX 4394).
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

/// `vault.voices.lineage`'s input: the voice whose render history to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderLineageRequest {
    pub voice_id: String,
}

/// `vault.voices.packs.put` on an embedded handle: as the vault's embedded
/// owner when the handle is theirs, else as a designed voice's creator, the
/// handle's bound actor on its read key, who banks a designed voice alone.
pub fn put_voice_bank_pack(
    memory: &Memory<'_>,
    input: VoiceBankPackPutRequest,
) -> MemoryResult<VoiceBankPackReceipt> {
    let actor = match memory.embedded_owner("vault.voices.packs.put") {
        Ok(owner) => VoiceBankActor::Person(owner),
        Err(_) => VoiceBankActor::creator(memory)?,
    };
    put_voice_bank_pack_as(memory.vault(), &actor, input)
}

/// `vault.voices.packs.put` under the actor's proof: the pack's owner is the
/// actor, which the bank revalidates in its write.
pub fn put_voice_bank_pack_as(
    vault: &Vault,
    actor: &VoiceBankActor,
    input: VoiceBankPackPutRequest,
) -> MemoryResult<VoiceBankPackReceipt> {
    let clips = decode_voice_bank_clips(input.clips)?;
    let pack = VoiceRefPack {
        version: VOICE_PACK_VERSION,
        id: input.pack_id,
        voice_id: input.voice_id,
        owner: actor.entity_for_read(vault)?,
        origin: input.origin,
        clips,
    };
    vault.store_voice_ref_pack_as(actor, &pack)?;
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

/// `vault.voices.render_consent`'s bank write under the actor's proof: the
/// decision's subject and recorder are the actor, which the bank revalidates
/// in its write. Its receipt, beside the target pointers this call dropped,
/// for the host to delete at their vendors.
pub fn record_voice_render_decision_as(
    vault: &Vault,
    actor: &VoiceBankActor,
    input: VoiceRenderConsentRequest,
) -> MemoryResult<VoiceRenderConsentWrite> {
    let entity = actor.entity_for_read(vault)?;
    let decision = VoiceRenderDecision {
        event_id: input.event_id,
        voice_id: input.voice_id,
        subject: entity,
        subject_kind: input.subject_kind,
        recorded_by: entity,
        occurred_at: input.occurred_at,
        reach: input.reach,
        basis: input.basis,
        state: input.state,
    };
    Ok(vault.record_voice_render_consent_as(actor, &decision)?)
}

/// `vault.voices.targets.evict`'s bank write under the actor's proof: the
/// dropped pointer, for the host to delete its clone at the vendor.
pub fn evict_own_voice_target(
    vault: &Vault,
    actor: &VoiceBankActor,
    input: &VoiceTargetEvictRequest,
) -> MemoryResult<Option<VoiceTargetRecord>> {
    Ok(vault.evict_voice_target_as(actor, &input.voice_id, &input.target)?)
}

/// `vault.voices.inspect` under the actor's proof, for the target as the
/// host renders it (`render`, FIX 4394): its hosted clone, the bank's
/// reference per call, or nothing on this host. A voice the bank holds
/// nothing of is not found.
pub fn inspect_voice_bank_as(
    vault: &Vault,
    actor: &VoiceBankActor,
    input: &VoiceBankInspectRequest,
    render: VoiceTargetRender,
) -> MemoryResult<VoiceBankInspection> {
    vault
        .inspect_voice_bank(
            actor,
            &input.voice_id,
            &input.target,
            input.include_generated,
            render,
        )?
        .ok_or_else(|| MemoryError::not_found("no voice is banked or consented under that id"))
}

/// `vault.voices.lineage` under the actor's proof: every render decision
/// recorded for the actor's own voice, in the order recorded. Empty for a
/// voice the bank holds nothing of.
pub fn read_voice_render_lineage_as(
    vault: &Vault,
    actor: &VoiceBankActor,
    input: &VoiceRenderLineageRequest,
) -> MemoryResult<Vec<VoiceRenderEventView>> {
    Ok(vault.voice_render_lineage_as(actor, &input.voice_id)?)
}

/// `vault.voices.lineage` on an embedded handle (FIX 8973): as the vault's
/// embedded owner when the handle is theirs, else as a designed voice's
/// creator, the handle's bound actor on its read key, as the pack put picks
/// its actor. Metadata only: the bank reads the actor's own voice, and no
/// provider or locality is asked.
pub fn read_voice_render_lineage(
    memory: &Memory<'_>,
    input: VoiceRenderLineageRequest,
) -> MemoryResult<Vec<VoiceRenderEventView>> {
    let actor = match memory.embedded_owner("vault.voices.lineage") {
        Ok(owner) => VoiceBankActor::Person(owner),
        Err(_) => VoiceBankActor::creator(memory)?,
    };
    read_voice_render_lineage_as(memory.vault(), &actor, &input)
}
