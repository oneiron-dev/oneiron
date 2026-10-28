//! The typed doors onto the voice bank (DOOR-143, e2e VOICE-02, FIX 4393).
//! Each act takes its [`VoiceBankActor`], revalidates it in the transaction
//! it writes in, and runs the same bank write the raw methods run. The actor
//! is the voice's subject (a real person, on their own person proof) or its
//! creator (a designed voice's, the owner by default), its decision's
//! recorder and its packs' owner: a write naming anyone else refuses, so no
//! actor banks, consents to or provisions another's voice here, and a
//! creator without a person's proof never acts on a real person's voice.
//! The inspection and the render lineage read one snapshot and answer
//! metadata only: no reference audio, transcript or provider configuration
//! leaves them, and their ids, revisions and digests are lowercase hex, as
//! the doors' write receipts carry them.
use serde::{Deserialize, Serialize};

use super::actor::{VoiceBankActor, others_voice};
use super::render_history::{
    VoiceRenderConsentWrite, VoiceRenderEventView, read_render_consent, record_render_consent_in,
    voice_render_lineage_in,
};
use super::validation::pack_intake_crossed;
use super::{
    PACKS, VoiceIdentity, VoiceRefOrigin, VoiceRefPack, VoiceRefSubjectKind, VoiceRenderConsent,
    VoiceRenderDecision, VoiceTargetClone, VoiceTargetRecord, admit_render, current_target,
    evict_target_in, invalid, limits_for, read_identity, read_pack, record_target_clone_in,
    store_pack_in, target_key, valid_id,
};
use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::llm::ModelLocality;
use crate::voice_identity::{VoiceConsentBasis, VoiceConsentState};

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
}

/// One named render target, as the bank holds it for the voice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceTargetInspection {
    pub target: String,
    /// Where the target runs, as the host's clone wire states it: how far
    /// the voice's render consent must reach for its refs to go there.
    pub locality: ModelLocality,
    /// Whether the selection the clone is checked against counts generated
    /// packs.
    pub include_generated: bool,
    /// The target's clone while it is current: made from the refs the
    /// selection picks now, under a render consent that reaches the target.
    /// None when none was made, it was evicted or withdrawn, or it went
    /// stale.
    pub current: Option<VoiceTargetCloneView>,
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
        }
    }
}

/// One banked `pack` without its audio or transcripts, with the intake rows
/// it went past under the owner's current rows.
fn pack_summary(pack: VoiceRefPack, crossed: Vec<String>) -> VoicePackSummary {
    VoicePackSummary {
        version: pack.version,
        id: pack.id,
        origin: pack.origin,
        clips: pack
            .clips
            .into_iter()
            .map(|clip| VoiceClipSummary {
                register: clip.register,
                media_type: clip.media_type,
                audio_bytes: clip.audio.len() as u64,
            })
            .collect(),
        crossed,
    }
}

impl Vault {
    /// [`Self::store_voice_ref_pack`] for the actor's own voice: the pack's
    /// owner is the actor, revalidated in the writing transaction, and the
    /// voice is nobody else's. The bank, not the request, decides the voice's
    /// kind, so a creator banks a designed voice alone.
    pub fn store_voice_ref_pack_as(
        &self,
        actor: &VoiceBankActor,
        pack: &VoiceRefPack,
    ) -> Result<()> {
        valid_id(&pack.id)?;
        valid_id(&pack.voice_id)?;
        let bytes = PACKS.encode_value(pack)?;
        let txn = self.store.env.write_txn()?;
        let party = actor.revalidate_in_txn(self, &txn)?;
        if pack.owner != party.entity {
            return Err(others_voice());
        }
        party.bind_in(&self.store, &txn, &pack.voice_id)?;
        store_pack_in(&self.store, txn, pack, &bytes)
    }

    /// [`Self::record_voice_render_consent`] for the actor's own voice: the
    /// decision's subject and its recorder are both the actor, revalidated
    /// in the writing transaction, and the voice is nobody else's. A real
    /// person's decision takes that person's own proof; a designed voice's
    /// creator decides for it. A withdrawal returns the target pointers it
    /// dropped, so the host can delete the vendors' clones.
    pub fn record_voice_render_consent_as(
        &self,
        actor: &VoiceBankActor,
        decision: &VoiceRenderDecision,
    ) -> Result<VoiceRenderConsentWrite> {
        decision.validate()?;
        let _guard = self
            .voice_ref_guard
            .write()
            .map_err(|_| Error::InvariantViolation("voice reference guard poisoned"))?;
        let txn = self.store.env.write_txn()?;
        let party = actor.revalidate_in_txn(self, &txn)?;
        if decision.subject != party.entity || decision.recorded_by != party.entity {
            return Err(others_voice());
        }
        party.admits(decision.subject_kind)?;
        party.bind_in(&self.store, &txn, &decision.voice_id)?;
        record_render_consent_in(&self.store, txn, decision)
    }

    /// The actor's own banked identity, read under its proof: a voice the
    /// bank holds no identity of refuses, as does another's.
    pub fn owned_voice_identity(
        &self,
        actor: &VoiceBankActor,
        voice_id: &str,
    ) -> Result<VoiceIdentity> {
        let txn = self.store.env.read_txn()?;
        let party = actor.revalidate_in_txn(self, &txn)?;
        party.bind_in(&self.store, &txn, voice_id)?;
        read_identity(&self.store, &txn, voice_id)?.ok_or_else(|| invalid("unknown voice identity"))
    }

    /// [`Self::record_voice_target_clone`] for the actor's own voice, under
    /// its proof revalidated in the writing transaction.
    pub fn record_voice_target_clone_as(
        &self,
        actor: &VoiceBankActor,
        request: &VoiceTargetClone,
        vendor_voice_id: &str,
        cloned_at: u64,
    ) -> Result<VoiceTargetRecord> {
        let txn = self.store.env.write_txn()?;
        let party = actor.revalidate_in_txn(self, &txn)?;
        party.bind_in(&self.store, &txn, &request.voice_id)?;
        record_target_clone_in(&self.store, txn, request, vendor_voice_id, cloned_at)
    }

    /// [`Self::evict_voice_target`] for the actor's own voice, under its
    /// proof revalidated in the writing transaction.
    pub fn evict_voice_target_as(
        &self,
        actor: &VoiceBankActor,
        voice_id: &str,
        target: &str,
    ) -> Result<Option<VoiceTargetRecord>> {
        let key = target_key(voice_id, target)?;
        let txn = self.store.env.write_txn()?;
        let party = actor.revalidate_in_txn(self, &txn)?;
        party.bind_in(&self.store, &txn, voice_id)?;
        let identity = read_identity(&self.store, &txn, voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?;
        evict_target_in(&self.store, txn, &key, identity.owner)
    }

    /// The actor's voice as the bank holds it, from one snapshot, for the
    /// named `target` at the `locality` its host states: the identity, each
    /// pack's metadata, the current render decision, and the target's clone
    /// while it is current. No provider call and no write. None when the
    /// bank holds nothing of the voice; another's voice refuses, and a
    /// corrupt row is an error, never a gap.
    pub fn inspect_voice_bank(
        &self,
        actor: &VoiceBankActor,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        locality: ModelLocality,
    ) -> Result<Option<VoiceBankInspection>> {
        valid_id(target)?;
        let txn = self.store.env.read_txn()?;
        let party = actor.revalidate_in_txn(self, &txn)?;
        if party.bind_in(&self.store, &txn, voice_id)?.is_none() {
            return Ok(None);
        }
        let identity = read_identity(&self.store, &txn, voice_id)?;
        let render_consent = read_render_consent(&self.store, &txn, voice_id)?;
        let mut packs = Vec::new();
        for id in identity.iter().flat_map(|identity| &identity.pack_ids) {
            let pack = read_pack(&self.store, &txn, id)?
                .ok_or_else(|| invalid("voice identity has missing refs"))?;
            let crossed = pack_intake_crossed(&pack, limits_for(&self.store, &txn, &pack.owner)?)
                .into_iter()
                .map(str::to_owned)
                .collect();
            packs.push(pack_summary(pack, crossed));
        }
        // A clone is current only under a render consent that reaches the
        // target, as a render admits it: a withdrawn or narrowed decision
        // shows none. The decision read above already surfaced a corrupt
        // row, so a refusal here is the consent's.
        let current = match &identity {
            Some(identity) => {
                match admit_render(&self.store, &txn, voice_id, &identity.owner, locality) {
                    Ok(_) => current_target(
                        &self.store,
                        &txn,
                        voice_id,
                        target,
                        include_generated,
                        locality,
                    )?
                    .map(|(record, _)| VoiceTargetCloneView::from(record)),
                    Err(Error::InvalidConfig(_)) => None,
                    Err(error) => return Err(error),
                }
            }
            None => None,
        };
        Ok(Some(VoiceBankInspection {
            voice_id: voice_id.to_owned(),
            identity: identity.as_ref().map(VoiceIdentityView::from),
            packs,
            render_consent: render_consent.map(VoiceRenderConsentView::from),
            target: VoiceTargetInspection {
                target: target.to_owned(),
                locality,
                include_generated,
                current,
            },
        }))
    }

    /// The actor's voice's render history (FIX 4396), from one snapshot:
    /// every decision recorded for it, granted or withdrawn, in the order
    /// they were recorded, with the target pointers each dropped. Metadata
    /// only, with no provider call. Empty when the bank holds nothing of the
    /// voice; another's voice refuses.
    pub fn voice_render_lineage_as(
        &self,
        actor: &VoiceBankActor,
        voice_id: &str,
    ) -> Result<Vec<VoiceRenderEventView>> {
        let txn = self.store.env.read_txn()?;
        let party = actor.revalidate_in_txn(self, &txn)?;
        if party.bind_in(&self.store, &txn, voice_id)?.is_none() {
            return Ok(Vec::new());
        }
        Ok(voice_render_lineage_in(&self.store, &txn, voice_id)?
            .into_iter()
            .map(VoiceRenderEventView::from)
            .collect())
    }
}
