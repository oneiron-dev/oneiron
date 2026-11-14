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

use crate::Vault;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::verbs::voice_records::{
    VoiceBankActor, VoiceRefPack, VoiceRegisterClip, VoiceRenderConsentWrite, VoiceRenderDecision,
    VoiceTargetRecord,
};

pub use crate::verbs::voice_records::{
    VoiceBankInspection, VoiceClipSummary, VoiceDroppedTargetView, VoiceIdentityView,
    VoicePackSummary, VoiceReferenceFenceView, VoiceRenderConsentView, VoiceRenderEventView,
    VoiceTargetCloneView, VoiceTargetInspection, VoiceTargetRender,
};

/// The pack version a door banks: the bank's one version.
const VOICE_PACK_VERSION: u8 = 1;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::voice_bank::{
    VoiceBankClipInput, VoiceBankInspectRequest, VoiceBankPackPutRequest, VoiceBankPackReceipt,
    VoiceRenderConsentReceipt, VoiceRenderConsentRequest, VoiceRenderLineageRequest,
    VoiceTargetEvictReceipt, VoiceTargetEvictRequest, VoiceTargetProvisionRequest,
    VoiceTargetReceipt, VoiceVendorDeleteStatus, VoiceVendorEviction,
};

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
