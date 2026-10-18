//! The owner's own doors onto the voice bank (DOOR-143, e2e VOICE-02). Each
//! act takes the request-bound [`AuthenticatedOwner`] proof, revalidates it
//! in the transaction it writes in, and runs the same bank write the raw
//! methods run. The proven person is the voice's subject, its decision's
//! recorder and its packs' owner: a write naming anyone else refuses, so an
//! owner never banks, consents to or provisions another person's voice here.
//! A designed voice the owner holds is theirs. The inspection reads one
//! snapshot and answers metadata only: no reference audio, transcript or
//! provider configuration leaves it, and its ids, revisions and digests are
//! lowercase hex, as the doors' write receipts carry them.
use serde::{Deserialize, Serialize};

use super::{
    PACKS, VoiceIdentity, VoiceRefOrigin, VoiceRefPack, VoiceRenderConsent, VoiceRenderDecision,
    VoiceTargetClone, VoiceTargetRecord, admit_render, current_target, evict_target_in, invalid,
    read_identity, read_pack, read_render_consent, record_render_consent_in,
    record_target_clone_in, store_pack_in, target_key, valid_id,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::llm::ModelLocality;
use crate::voice_identity::{VoiceConsentBasis, VoiceConsentState};
use crate::{EntityId, Vault};

/// A banked voice identity: its owner (entity hex) and its packs' ids,
/// source and generated packs apart by their origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceIdentityView {
    pub version: u8,
    pub id: String,
    pub owner: String,
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

/// A voice's current render decision, granted or withdrawn: whose voice it
/// is and who recorded it (entity hex), when (unix seconds), how far a grant
/// lets the refs reach, how it was captured, and its revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderConsentView {
    pub event_id: String,
    pub subject: String,
    pub recorded_by: String,
    pub occurred_at: u64,
    pub reach: ModelLocality,
    pub basis: VoiceConsentBasis,
    pub state: VoiceConsentState,
    pub revision: String,
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

/// The owner's voice as the bank holds it, read from one snapshot: its
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
            recorded_by: decision.recorded_by.to_hex(),
            occurred_at: decision.occurred_at,
            reach: decision.reach,
            basis: decision.basis,
            state: decision.state,
            revision: bytes_to_hex_lower(&consent.revision),
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

impl From<VoiceRefPack> for VoicePackSummary {
    fn from(pack: VoiceRefPack) -> Self {
        Self {
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
        }
    }
}

/// The refusal of an owner's act on a voice that is another person's.
fn others_voice() -> Error {
    invalid("the voice is another person's: only its subject banks, consents to or provisions it")
}

/// `voice_id`'s subject as the bank holds it: its identity's owner, or,
/// before its first pack, its render decision's subject. None when the bank
/// holds nothing of the voice.
fn subject_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
) -> Result<Option<EntityId>> {
    if let Some(identity) = read_identity(store, txn, voice_id)? {
        return Ok(Some(identity.owner));
    }
    Ok(read_render_consent(store, txn, voice_id)?.map(|consent| consent.decision.subject))
}

/// Refuses unless `person` is the voice's subject, or the bank holds nothing
/// of the voice yet.
fn admit_person(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
    person: EntityId,
) -> Result<()> {
    match subject_in(store, txn, voice_id)? {
        Some(subject) if subject != person => Err(others_voice()),
        _ => Ok(()),
    }
}

impl Vault {
    /// [`Self::store_voice_ref_pack`] for the proven owner's own voice: the
    /// pack's owner is the proof's person, revalidated in the writing
    /// transaction, and the voice is nobody else's.
    pub fn store_voice_ref_pack_as(
        &self,
        owner: &AuthenticatedOwner,
        pack: &VoiceRefPack,
    ) -> Result<()> {
        valid_id(&pack.id)?;
        valid_id(&pack.voice_id)?;
        let bytes = PACKS.encode_value(pack)?;
        let txn = self.store.env.write_txn()?;
        let person = owner.revalidate_in_txn(self, &txn)?;
        if pack.owner != person {
            return Err(others_voice());
        }
        admit_person(&self.store, &txn, &pack.voice_id, person)?;
        store_pack_in(&self.store, txn, pack, &bytes)
    }

    /// [`Self::record_voice_render_consent`] for the proven owner's own
    /// voice: the decision's subject and its recorder are both the proof's
    /// person, revalidated in the writing transaction, and the voice is
    /// nobody else's. A withdrawal returns the dropped target pointers, so
    /// the host can delete the vendors' clones.
    pub fn record_voice_render_consent_as(
        &self,
        owner: &AuthenticatedOwner,
        decision: &VoiceRenderDecision,
    ) -> Result<(VoiceRenderConsent, Vec<VoiceTargetRecord>)> {
        decision.validate()?;
        let _guard = self
            .voice_ref_guard
            .write()
            .map_err(|_| Error::InvariantViolation("voice reference guard poisoned"))?;
        let txn = self.store.env.write_txn()?;
        let person = owner.revalidate_in_txn(self, &txn)?;
        if decision.subject != person || decision.recorded_by != person {
            return Err(others_voice());
        }
        admit_person(&self.store, &txn, &decision.voice_id, person)?;
        record_render_consent_in(&self.store, txn, decision)
    }

    /// The proven owner's own banked identity, read under the proof: a voice
    /// the bank holds no identity of refuses, as does another person's.
    pub fn owned_voice_identity(
        &self,
        owner: &AuthenticatedOwner,
        voice_id: &str,
    ) -> Result<VoiceIdentity> {
        let txn = self.store.env.read_txn()?;
        let person = owner.revalidate_in_txn(self, &txn)?;
        let identity = read_identity(&self.store, &txn, voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?;
        if identity.owner != person {
            return Err(others_voice());
        }
        Ok(identity)
    }

    /// [`Self::record_voice_target_clone`] for the proven owner's own voice,
    /// under the proof revalidated in the writing transaction.
    pub fn record_voice_target_clone_as(
        &self,
        owner: &AuthenticatedOwner,
        request: &VoiceTargetClone,
        vendor_voice_id: &str,
        cloned_at: u64,
    ) -> Result<VoiceTargetRecord> {
        let txn = self.store.env.write_txn()?;
        let person = owner.revalidate_in_txn(self, &txn)?;
        if read_identity(&self.store, &txn, &request.voice_id)?
            .is_some_and(|identity| identity.owner != person)
        {
            return Err(others_voice());
        }
        record_target_clone_in(&self.store, txn, request, vendor_voice_id, cloned_at)
    }

    /// [`Self::evict_voice_target`] for the proven owner's own voice, under
    /// the proof revalidated in the writing transaction.
    pub fn evict_voice_target_as(
        &self,
        owner: &AuthenticatedOwner,
        voice_id: &str,
        target: &str,
    ) -> Result<Option<VoiceTargetRecord>> {
        let key = target_key(voice_id, target)?;
        let txn = self.store.env.write_txn()?;
        let person = owner.revalidate_in_txn(self, &txn)?;
        let identity = read_identity(&self.store, &txn, voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?;
        if identity.owner != person {
            return Err(others_voice());
        }
        evict_target_in(&self.store, txn, &key, identity.owner)
    }

    /// The proven owner's voice as the bank holds it, from one snapshot, for
    /// the named `target` at the `locality` its host states: the identity,
    /// each pack's metadata, the current render decision, and the target's
    /// clone while it is current. No provider call and no write. None when
    /// the bank holds nothing of the voice; another person's voice refuses,
    /// and a corrupt row is an error, never a gap.
    pub fn inspect_voice_bank(
        &self,
        owner: &AuthenticatedOwner,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        locality: ModelLocality,
    ) -> Result<Option<VoiceBankInspection>> {
        valid_id(target)?;
        let txn = self.store.env.read_txn()?;
        let person = owner.revalidate_in_txn(self, &txn)?;
        let identity = read_identity(&self.store, &txn, voice_id)?;
        let render_consent = read_render_consent(&self.store, &txn, voice_id)?;
        let subject = match (&identity, &render_consent) {
            (Some(identity), _) => identity.owner,
            (None, Some(consent)) => consent.decision.subject,
            (None, None) => return Ok(None),
        };
        if subject != person {
            return Err(others_voice());
        }
        let mut packs = Vec::new();
        for id in identity.iter().flat_map(|identity| &identity.pack_ids) {
            let pack = read_pack(&self.store, &txn, id)?
                .ok_or_else(|| invalid("voice identity has missing refs"))?;
            packs.push(VoicePackSummary::from(pack));
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
}
