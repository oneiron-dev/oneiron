//! Private per-vault voice reference bank. Provider voice IDs are evictable pointers, not identities.
use std::collections::BTreeSet;

use crate::error::SideTableRowProblem;
use crate::llm::ModelLocality;
use crate::side_table::{self, CodecError, Named, Raw, RawValue, SideCodec, SideKey, SideTable};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ref_limits::VoiceRefLimits;
use super::{VoiceConsentBasis, VoiceConsentState};

/// Immutable voice reference pack. Key: string (the pack id).
const PACKS: SideTable<String, VoiceRefPack, Named> = SideTable::new(&side_table::VOICE_OWNER_REF);

/// A voice identity over its packs. Key: string (the voice id).
const IDENTITIES: SideTable<String, VoiceIdentity, Named> =
    SideTable::new(&side_table::VOICE_REF_IDENTITY);

/// An identity's incarnation, fresh at every birth and deleted with it. Key:
/// string (the voice id).
const INCARNATIONS: SideTable<String, [u8; 16], Raw> =
    SideTable::new(&side_table::VOICE_REF_INCARNATION);

/// A cached render-target pointer. Key: voice id `\0` target.
const TARGETS: SideTable<TargetKey, VoiceTargetRecord, Named> =
    SideTable::new(&side_table::VOICE_REF_TARGET);

/// A voice's current render/provisioning decision. Key: string (the voice id).
const RENDER_CONSENT: SideTable<String, VoiceRenderConsent, Named> =
    SideTable::new(&side_table::VOICE_REF_RENDER_CONSENT);

/// Per-owner index over the bank's rows, so erasure finds every row an owner holds. Key: id16
/// (owner) + the indexed row's full stored key. Value: that full stored key.
const OWNER_INDEX: SideTable<(EntityId, Vec<u8>), BankRow, Raw> =
    SideTable::new(&side_table::VOICE_OWNER_REF_OWNER_INDEX);

/// [`TARGETS`]' key: the voice id and target, joined by a NUL neither may contain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetKey {
    voice_id: String,
    target: String,
}

impl SideKey for TargetKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.voice_id.as_bytes());
        out.push(0);
        out.extend_from_slice(self.target.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let split = bytes.iter().position(|byte| *byte == 0)?;
        Some(Self {
            voice_id: String::decode_key(&bytes[..split])?,
            target: String::decode_key(&bytes[split + 1..])?,
        })
    }
}

/// One bank row an owner holds, stored in [`OWNER_INDEX`] as its full stored key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BankRow {
    Pack(String),
    Identity(String),
    Incarnation(String),
    Target(TargetKey),
    Consent(String),
}

impl BankRow {
    fn key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pack(id) => PACKS.key_bytes(id),
            Self::Identity(id) => IDENTITIES.key_bytes(id),
            Self::Incarnation(id) => INCARNATIONS.key_bytes(id),
            Self::Target(key) => TARGETS.key_bytes(key),
            Self::Consent(id) => RENDER_CONSENT.key_bytes(id),
        }
    }

    /// Deletes the row; `true` when it was present.
    fn delete(&self, store: &crate::store::Store, txn: &mut heed::RwTxn<'_>) -> Result<bool> {
        match self {
            Self::Pack(id) => PACKS.delete(store, txn, id),
            Self::Identity(id) => IDENTITIES.delete(store, txn, id),
            Self::Incarnation(id) => INCARNATIONS.delete(store, txn, id),
            Self::Target(key) => TARGETS.delete(store, txn, key),
            Self::Consent(id) => RENDER_CONSENT.delete(store, txn, id),
        }
    }

    /// Indexes the row under its owner.
    fn index(
        self,
        store: &crate::store::Store,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
    ) -> Result<()> {
        OWNER_INDEX.put(store, txn, &(owner, self.key_bytes()), &self)
    }
}

impl RawValue for BankRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.key_bytes())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row = if let Some(id) = bytes.strip_prefix(PACKS.decl().prefix) {
            String::decode_key(id).map(Self::Pack)
        } else if let Some(id) = bytes.strip_prefix(IDENTITIES.decl().prefix) {
            String::decode_key(id).map(Self::Identity)
        } else if let Some(id) = bytes.strip_prefix(INCARNATIONS.decl().prefix) {
            String::decode_key(id).map(Self::Incarnation)
        } else if let Some(key) = bytes.strip_prefix(TARGETS.decl().prefix) {
            TargetKey::decode_key(key).map(Self::Target)
        } else if let Some(id) = bytes.strip_prefix(RENDER_CONSENT.decl().prefix) {
            String::decode_key(id).map(Self::Consent)
        } else {
            None
        };
        row.ok_or(CodecError::Row(SideTableRowProblem::Undecodable))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(with = "crate::llm::entity_refs")]
    pub owner: EntityId,
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
/// neither grants the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderDecision {
    pub event_id: String,
    pub voice_id: String,
    /// Whose voice it is: the identity's owner.
    #[serde(with = "crate::llm::entity_refs")]
    pub subject: EntityId,
    #[serde(with = "crate::llm::entity_refs")]
    pub recorded_by: EntityId,
    pub occurred_at: u64,
    /// The farthest render target a grant lets the refs reach: the device,
    /// the owner's own server, or a third party.
    pub reach: ModelLocality,
    pub basis: VoiceConsentBasis,
    pub state: VoiceConsentState,
}

impl VoiceRenderDecision {
    fn validate(&self) -> Result<()> {
        valid_id(&self.event_id)?;
        valid_id(&self.voice_id)?;
        if self.occurred_at == 0 {
            return Err(invalid("a voice render decision needs its time"));
        }
        self.basis.validate()
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

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
fn valid_id(id: &str) -> Result<()> {
    if id.trim().is_empty() || id.len() > 128 || id.contains('\0') {
        return Err(invalid("invalid voice reference id"));
    }
    Ok(())
}
fn target_key(voice_id: &str, target: &str) -> Result<TargetKey> {
    valid_id(voice_id)?;
    valid_id(target)?;
    Ok(TargetKey {
        voice_id: voice_id.into(),
        target: target.into(),
    })
}
/// Reads one bank row; a row that does not decode is `corrupt`, an [`Error::InvalidConfig`].
fn read_row<K: SideKey, V>(
    table: SideTable<K, V, Named>,
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    key: &K,
    corrupt: &str,
) -> Result<Option<V>>
where
    Named: SideCodec<V>,
{
    table
        .get_bytes(store, txn, key)?
        .map(|bytes| table.decode_value(&bytes).map_err(|_| invalid(corrupt)))
        .transpose()
}
fn limits_for(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    owner: &EntityId,
) -> Result<VoiceRefLimits> {
    crate::gate::resolve_policy_manifest(store, txn)?
        .voice_ref_limits(owner)
        .ok_or_else(|| invalid("invalid voice reference policy"))
}

fn validate_provider_value(value: &str, max_bytes: u64) -> Result<()> {
    if value.trim().is_empty() || value.contains('\0') || value.len() as u64 > max_bytes {
        return Err(invalid("invalid voice provider value"));
    }
    Ok(())
}

fn validate_target_record(
    record: &VoiceTargetRecord,
    voice_id: &str,
    target: &str,
    limits: VoiceRefLimits,
) -> Result<()> {
    if record.voice_id != voice_id
        || record.target != target
        || record.cloned_at == 0
        || record.source_packs.is_empty()
        || validate_provider_value(&record.vendor_voice_id, limits.max_vendor_voice_id_bytes)
            .is_err()
    {
        return Err(invalid("corrupt voice target clone"));
    }
    Ok(())
}

impl VoiceRefPack {
    fn validate(&self, limits: VoiceRefLimits) -> Result<()> {
        valid_id(&self.id)?;
        valid_id(&self.voice_id)?;
        if self.version != 1 {
            return Err(invalid("unsupported voice reference pack version"));
        }
        match &self.origin {
            VoiceRefOrigin::Designed { vendor } => {
                validate_provider_value(vendor, limits.max_design_vendor_bytes)?;
            }
            VoiceRefOrigin::Captured { consent_event_ref } => valid_id(consent_event_ref)?,
            VoiceRefOrigin::Generated => {}
        }
        if self.clips.is_empty()
            || self.clips.len() as u64 > limits.max_clips_per_pack
            || self
                .clips
                .iter()
                .try_fold(0u64, |total, c| total.checked_add(c.audio.len() as u64))
                .is_none_or(|bytes| bytes > limits.max_audio_bytes_per_pack)
        {
            return Err(invalid("invalid voice reference pack size"));
        }
        let mut names = BTreeSet::new();
        for clip in &self.clips {
            if clip.register.trim().is_empty()
                || clip.register.len() as u64 > limits.max_register_bytes
                || !names.insert(&clip.register)
                || !clip.media_type.starts_with("audio/")
                || clip.audio.is_empty()
                || clip.transcript.len() as u64 > limits.max_transcript_bytes
            {
                return Err(invalid("invalid voice reference clip"));
            }
        }
        Ok(())
    }
}

pub(super) fn delete_owner_refs(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    owner: &EntityId,
) -> Result<usize> {
    let rows = OWNER_INDEX.scan_from(store, txn, owner.as_bytes())?;
    let mut deleted = 0;
    for (index, row) in rows {
        if row.delete(store, txn)? {
            deleted += 1;
        }
        OWNER_INDEX.delete(store, txn, &index)?;
    }
    Ok(deleted)
}

impl Vault {
    /// Creates an identity on its first captured/designed pack, then adds immutable packs.
    /// Generated refs need an existing source identity and remain separate tagged packs.
    pub fn store_voice_ref_pack(&self, pack: &VoiceRefPack) -> Result<()> {
        valid_id(&pack.id)?;
        valid_id(&pack.voice_id)?;
        let bytes = PACKS.encode_value(pack)?;
        let mut txn = self.store.env.write_txn()?;
        pack.validate(limits_for(&self.store, &txn, &pack.owner)?)?;
        if let Some(existing) = PACKS.get_bytes(&self.store, &txn, &pack.id)? {
            if existing != bytes {
                return Err(invalid("voice reference pack id already exists"));
            }
            return Ok(()); // An immutable retry; the original transaction already committed.
        }
        if let VoiceRefOrigin::Captured { consent_event_ref } = &pack.origin {
            let consented =
                read_render_consent(&self.store, &txn, &pack.voice_id)?.is_some_and(|consent| {
                    consent.decision.event_id == *consent_event_ref
                        && consent.decision.subject == pack.owner
                        && consent.decision.state == VoiceConsentState::Granted
                });
            if !consented {
                return Err(invalid(
                    "captured refs need the subject's current render consent",
                ));
            }
        }
        let mut identity = match read_identity(&self.store, &txn, &pack.voice_id)? {
            Some(identity) => identity,
            None if pack.origin == VoiceRefOrigin::Generated => {
                return Err(invalid("generated refs need an existing source identity"));
            }
            None => {
                // Fresh at every birth, so a withdrawn and identically re-banked
                // identity never matches a fence taken before the withdrawal.
                INCARNATIONS.put(
                    &self.store,
                    &mut txn,
                    &pack.voice_id,
                    uuid::Uuid::new_v4().as_bytes(),
                )?;
                BankRow::Incarnation(pack.voice_id.clone()).index(
                    &self.store,
                    &mut txn,
                    pack.owner,
                )?;
                VoiceIdentity {
                    version: 1,
                    id: pack.voice_id.clone(),
                    owner: pack.owner,
                    pack_ids: Vec::new(),
                }
            }
        };
        if identity.owner != pack.owner {
            return Err(invalid("voice identity owner mismatch"));
        }
        identity.pack_ids.push(pack.id.clone());
        PACKS.put(&self.store, &mut txn, &pack.id, pack)?;
        IDENTITIES.put(&self.store, &mut txn, &pack.voice_id, &identity)?;
        BankRow::Pack(pack.id.clone()).index(&self.store, &mut txn, pack.owner)?;
        BankRow::Identity(pack.voice_id.clone()).index(&self.store, &mut txn, pack.owner)?;
        txn.commit()?;
        Ok(())
    }

    pub fn voice_identity(&self, id: &str) -> Result<Option<VoiceIdentity>> {
        let txn = self.store.env.read_txn()?;
        read_identity(&self.store, &txn, id)
    }

    pub fn voice_ref_pack(&self, id: &str) -> Result<Option<VoiceRefPack>> {
        let txn = self.store.env.read_txn()?;
        read_pack(&self.store, &txn, id)
    }

    /// Records the subject's render decision for `voice_id`; the identity
    /// may not be banked yet, since captured refs cite the grant they were
    /// recorded under. A grant names the farthest target the refs may
    /// reach. Every decision is a new revision, so a selection or binding
    /// taken under an earlier one goes stale. A withdrawal also drops the
    /// voice's target pointers and returns them, so the host can delete the
    /// vendors' clones. Holds the ref guard, so no decision commits while
    /// refs are being uploaded.
    pub fn record_voice_render_consent(
        &self,
        decision: &VoiceRenderDecision,
    ) -> Result<(VoiceRenderConsent, Vec<VoiceTargetRecord>)> {
        decision.validate()?;
        let _guard = self
            .voice_ref_guard
            .write()
            .map_err(|_| Error::InvariantViolation("voice reference guard poisoned"))?;
        let mut txn = self.store.env.write_txn()?;
        let owner = read_identity(&self.store, &txn, &decision.voice_id)?.map(|i| i.owner);
        if owner.is_some_and(|owner| owner != decision.subject) {
            return Err(invalid("voice identity owner mismatch"));
        }
        if let Some(current) = read_render_consent(&self.store, &txn, &decision.voice_id)? {
            if current.decision.subject != decision.subject {
                return Err(invalid("voice identity owner mismatch"));
            }
            if current.decision.event_id == decision.event_id {
                if current.decision == *decision {
                    return Ok((current, Vec::new())); // A replay of the current decision.
                }
                return Err(invalid(
                    "voice render consent event id already names another decision",
                ));
            }
            if current.decision.occurred_at > decision.occurred_at {
                return Err(invalid("a later voice render decision is recorded"));
            }
        }
        let consent = VoiceRenderConsent {
            version: 1,
            decision: decision.clone(),
            revision: uuid::Uuid::new_v4().into_bytes(),
        };
        RENDER_CONSENT.put(&self.store, &mut txn, &decision.voice_id, &consent)?;
        BankRow::Consent(decision.voice_id.clone()).index(
            &self.store,
            &mut txn,
            decision.subject,
        )?;
        let mut evicted = Vec::new();
        if decision.state == VoiceConsentState::Withdrawn {
            let mut prefix = decision.voice_id.as_bytes().to_vec();
            prefix.push(0);
            for key in TARGETS.scan_keys(&self.store, &txn, &prefix)? {
                // A corrupt pointer is dropped all the same.
                if let Ok(Some(record)) = read_row(
                    TARGETS,
                    &self.store,
                    &txn,
                    &key,
                    "corrupt voice target clone",
                ) {
                    evicted.push(record);
                }
                TARGETS.delete(&self.store, &mut txn, &key)?;
                OWNER_INDEX.delete(
                    &self.store,
                    &mut txn,
                    &(decision.subject, TARGETS.key_bytes(&key)),
                )?;
            }
        }
        txn.commit()?;
        Ok((consent, evicted))
    }

    /// The voice's current render decision, granted or withdrawn.
    pub fn voice_render_consent(&self, voice_id: &str) -> Result<Option<VoiceRenderConsent>> {
        let txn = self.store.env.read_txn()?;
        read_render_consent(&self.store, &txn, voice_id)
    }

    /// Builds a clone from selected bank refs for a target at `locality`. A
    /// generated pack is optional, never the only source. The digest covers
    /// exact audio and metadata, not just pack IDs. The voice's render
    /// consent must reach the target.
    pub fn prepare_voice_clone(
        &self,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        locality: ModelLocality,
    ) -> Result<VoiceTargetClone> {
        let txn = self.store.env.read_txn()?;
        select_clone(
            &self.store,
            &txn,
            voice_id,
            target,
            include_generated,
            locality,
        )
    }

    /// Saves the vendor's return value only if this request still matches the
    /// bank and the render consent it was prepared under.
    pub fn record_voice_target_clone(
        &self,
        request: &VoiceTargetClone,
        vendor_voice_id: &str,
        cloned_at: u64,
    ) -> Result<VoiceTargetRecord> {
        let mut txn = self.store.env.write_txn()?;
        let selected = select_clone(
            &self.store,
            &txn,
            &request.voice_id,
            &request.target,
            request.include_generated,
            request.grant.locality,
        )?;
        if &selected != request {
            return Err(invalid("voice clone refs or render consent changed"));
        }
        let record = VoiceTargetRecord {
            voice_id: request.voice_id.clone(),
            target: request.target.clone(),
            vendor_voice_id: vendor_voice_id.into(),
            source_packs: request.source_packs.clone(),
            ref_digest: request.ref_digest,
            cloned_at,
            revision: uuid::Uuid::new_v4().into_bytes(),
        };
        let target_key = target_key(&request.voice_id, &request.target)?;
        let owner = read_identity(&self.store, &txn, &request.voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?
            .owner;
        let limits = limits_for(&self.store, &txn, &owner)?;
        validate_target_record(&record, &request.voice_id, &request.target, limits)?;
        if let Some(existing) = read_row(
            TARGETS,
            &self.store,
            &txn,
            &target_key,
            "corrupt voice target clone",
        )? {
            validate_target_record(&existing, &request.voice_id, &request.target, limits)?;
            if existing.source_packs == request.source_packs
                && existing.ref_digest == request.ref_digest
            {
                return Ok(existing); // A current target pointer is not replaced without new refs.
            }
        }
        TARGETS.put(&self.store, &mut txn, &target_key, &record)?;
        BankRow::Target(target_key).index(&self.store, &mut txn, owner)?;
        txn.commit()?;
        Ok(record)
    }

    /// The target's record and the render consent that reaches it at
    /// `locality`. None when the target was evicted or its chosen refs have
    /// changed; a voice whose render consent does not reach it refuses.
    pub fn voice_target_clone(
        &self,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        locality: ModelLocality,
    ) -> Result<Option<(VoiceTargetRecord, VoiceRenderGrant)>> {
        let txn = self.store.env.read_txn()?;
        current_target(
            &self.store,
            &txn,
            voice_id,
            target,
            include_generated,
            locality,
        )
    }

    /// Calls `admit` only while the target record at `revision` is still
    /// current, under the same render `grant`. The write transaction
    /// serializes admission against withdrawal and eviction, including
    /// writers in other processes.
    pub(crate) fn with_live_voice_target<R>(
        &self,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        revision: [u8; 16],
        grant: VoiceRenderGrant,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        let txn = self.store.env.write_txn()?;
        match current_target(
            &self.store,
            &txn,
            voice_id,
            target,
            include_generated,
            grant.locality,
        )? {
            Some((record, current)) if record.revision == revision && current == grant => {
                Ok(Some(admit(&txn)?))
            }
            _ => Ok(None),
        }
    }

    pub fn evict_voice_target(&self, voice_id: &str, target: &str) -> Result<()> {
        let key = target_key(voice_id, target)?;
        let identity = self
            .voice_identity(voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?;
        let mut txn = self.store.env.write_txn()?;
        TARGETS.delete(&self.store, &mut txn, &key)?;
        OWNER_INDEX.delete(
            &self.store,
            &mut txn,
            &(identity.owner, TARGETS.key_bytes(&key)),
        )?;
        txn.commit()?;
        Ok(())
    }

    /// The selection for a target at `locality` and its fence, read from one
    /// snapshot.
    pub(crate) fn prepare_fenced_voice_clone(
        &self,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        locality: ModelLocality,
    ) -> Result<(VoiceTargetClone, VoiceRefFence)> {
        let txn = self.store.env.read_txn()?;
        fenced_clone(
            &self.store,
            &txn,
            voice_id,
            target,
            include_generated,
            locality,
        )
    }

    /// Runs `operation` only while `fence` is current. Holds the ref guard, so
    /// neither a consent withdrawal nor a new render decision can commit
    /// while the refs are being uploaded.
    pub(crate) fn with_fenced_voice_clone<T>(
        &self,
        voice_id: &str,
        target: &str,
        fence: &VoiceRefFence,
        operation: impl FnOnce(&VoiceTargetClone) -> Result<T>,
    ) -> Result<T> {
        let _guard = self
            .voice_ref_guard
            .read()
            .map_err(|_| Error::InvariantViolation("voice reference guard poisoned"))?;
        let txn = self.store.env.read_txn()?;
        let (clone, current) = fenced_clone(
            &self.store,
            &txn,
            voice_id,
            target,
            fence.include_generated,
            fence.grant.locality,
        )?;
        if &current != fence {
            return Err(invalid(
                "voice identity or its render consent withdrawn, or its refs changed",
            ));
        }
        operation(&clone)
    }

    /// Nonblocking check for synchronous callers. A waiting withdrawal writer
    /// makes a new read lock unavailable; report stale rather than block.
    pub(crate) fn voice_ref_fence_current_now(
        &self,
        voice_id: &str,
        target: &str,
        fence: &VoiceRefFence,
    ) -> Result<bool> {
        let _guard = match self.voice_ref_guard.try_read() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(Error::InvariantViolation("voice reference guard poisoned"));
            }
        };
        let txn = self.store.env.read_txn()?;
        Ok(fenced_clone(
            &self.store,
            &txn,
            voice_id,
            target,
            fence.include_generated,
            fence.grant.locality,
        )
        .is_ok_and(|(_, current)| &current == fence))
    }

    /// One source clip of `voice_id` for a target at `locality` that renders
    /// from the bank's refs on each call and keeps no clone, with the fence
    /// it renders under: `register`'s clip, or the identity's first source
    /// clip when none is named. Generated refs never stand in for the
    /// identity here, and the voice's render consent must reach the target.
    /// The caller checks the fence again (`voice_ref_fence_current_now`)
    /// before the clip leaves and before its audio is played.
    pub fn fenced_voice_reference(
        &self,
        voice_id: &str,
        target: &str,
        register: Option<&str>,
        locality: ModelLocality,
    ) -> Result<(VoiceRegisterClip, VoiceRefFence)> {
        let txn = self.store.env.read_txn()?;
        let (clone, fence) = fenced_clone(&self.store, &txn, voice_id, target, false, locality)?;
        let clip = clone
            .clips
            .into_iter()
            .find(|clip| register.is_none_or(|register| clip.register == register))
            .ok_or_else(|| invalid("register is not banked"))?;
        Ok((clip, fence))
    }
}

fn fenced_clone(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
    target: &str,
    include_generated: bool,
    locality: ModelLocality,
) -> Result<(VoiceTargetClone, VoiceRefFence)> {
    let clone = select_clone(store, txn, voice_id, target, include_generated, locality)?;
    let owner = read_identity(store, txn, voice_id)?
        .ok_or_else(|| invalid("unknown voice identity"))?
        .owner;
    let incarnation = INCARNATIONS
        .get_bytes(store, txn, &voice_id.to_owned())?
        .map(|raw| {
            raw.as_slice()
                .try_into()
                .map_err(|_| invalid("corrupt voice identity incarnation"))
        })
        .transpose()?;
    let fence = VoiceRefFence {
        owner,
        incarnation,
        ref_digest: clone.ref_digest,
        include_generated,
        grant: clone.grant,
    };
    Ok((clone, fence))
}

fn current_target(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
    target: &str,
    include_generated: bool,
    locality: ModelLocality,
) -> Result<Option<(VoiceTargetRecord, VoiceRenderGrant)>> {
    let key = target_key(voice_id, target)?;
    let Some(record) = read_row(TARGETS, store, txn, &key, "corrupt voice target clone")? else {
        return Ok(None);
    };
    let selected = select_clone(store, txn, voice_id, target, include_generated, locality)?;
    let owner = read_identity(store, txn, voice_id)?
        .ok_or_else(|| invalid("unknown voice identity"))?
        .owner;
    validate_target_record(&record, voice_id, target, limits_for(store, txn, &owner)?)?;
    if record.source_packs != selected.source_packs || record.ref_digest != selected.ref_digest {
        return Ok(None);
    }
    Ok(Some((record, selected.grant)))
}

fn read_render_consent(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
) -> Result<Option<VoiceRenderConsent>> {
    valid_id(voice_id)?;
    let Some(consent) = read_row(
        RENDER_CONSENT,
        store,
        txn,
        &voice_id.to_owned(),
        "corrupt voice render consent",
    )?
    else {
        return Ok(None);
    };
    if consent.version != 1 || consent.decision.voice_id != voice_id {
        return Err(invalid("corrupt voice render consent"));
    }
    Ok(Some(consent))
}

/// The render consent that lets `voice_id`'s refs reach a target at
/// `locality`: the owner's current grant, reaching at least that far. A
/// recognition grant never stands in for it.
fn admit_render(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
    owner: &EntityId,
    locality: ModelLocality,
) -> Result<VoiceRenderGrant> {
    let consent = read_render_consent(store, txn, voice_id)?
        .ok_or_else(|| invalid("voice has no render consent"))?;
    if consent.decision.subject != *owner {
        return Err(invalid("voice render consent names another subject"));
    }
    if consent.decision.state != VoiceConsentState::Granted {
        return Err(invalid("voice render consent withdrawn"));
    }
    if locality > consent.decision.reach {
        return Err(invalid("voice render consent does not reach this target"));
    }
    Ok(VoiceRenderGrant {
        revision: consent.revision,
        locality,
    })
}

fn read_identity(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &str,
) -> Result<Option<VoiceIdentity>> {
    valid_id(id)?;
    let Some(identity) = read_row(
        IDENTITIES,
        store,
        txn,
        &id.to_owned(),
        "corrupt voice identity",
    )?
    else {
        return Ok(None);
    };
    if identity.id != id || identity.version != 1 || identity.pack_ids.is_empty() {
        return Err(invalid("corrupt voice identity"));
    }
    let mut seen = BTreeSet::new();
    let mut source = false;
    for pack_id in &identity.pack_ids {
        if !seen.insert(pack_id) {
            return Err(invalid("duplicate voice pack"));
        }
        let pack = read_pack(store, txn, pack_id)?
            .ok_or_else(|| invalid("voice identity has missing refs"))?;
        if pack.voice_id != id || pack.owner != identity.owner {
            return Err(invalid("voice identity pack mismatch"));
        }
        source |= pack.origin != VoiceRefOrigin::Generated;
    }
    if !source {
        return Err(invalid("voice identity has no source refs"));
    }
    Ok(Some(identity))
}

fn select_clone(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
    target: &str,
    include_generated: bool,
    locality: ModelLocality,
) -> Result<VoiceTargetClone> {
    valid_id(target)?;
    let identity = read_identity(store, txn, voice_id)?
        .ok_or_else(|| invalid("unknown voice identity or missing refs"))?;
    let grant = admit_render(store, txn, voice_id, &identity.owner, locality)?;
    let mut packs = Vec::new();
    for id in &identity.pack_ids {
        let pack =
            read_pack(store, txn, id)?.ok_or_else(|| invalid("voice identity has missing refs"))?;
        if pack.origin != VoiceRefOrigin::Generated || include_generated {
            packs.push(pack);
        }
    }
    let source_packs = packs.iter().map(|p| p.id.clone()).collect();
    let clips = packs.iter().flat_map(|p| p.clips.clone()).collect();
    let packs = rmp_serde::to_vec_named(&packs).map_err(|e| Error::InvalidConfig(e.to_string()))?;
    let digest = Sha256::digest(packs);
    Ok(VoiceTargetClone {
        voice_id: voice_id.into(),
        target: target.into(),
        source_packs,
        clips,
        ref_digest: digest.into(),
        include_generated,
        grant,
    })
}

fn read_pack(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &str,
) -> Result<Option<VoiceRefPack>> {
    valid_id(id)?;
    let Some(pack) = read_row(
        PACKS,
        store,
        txn,
        &id.to_owned(),
        "corrupt voice reference pack",
    )?
    else {
        return Ok(None);
    };
    pack.validate(limits_for(store, txn, &pack.owner)?)?;
    if pack.id != id {
        return Err(invalid("voice reference key mismatch"));
    }
    Ok(Some(pack))
}

#[cfg(test)]
#[path = "ref_bank/tests.rs"]
mod tests;
