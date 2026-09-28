//! Private per-vault voice reference bank. Provider voice IDs are evictable pointers, not identities.
use std::collections::BTreeSet;

use crate::error::SideTableRowProblem;
use crate::side_table::{self, CodecError, Named, Raw, RawValue, SideCodec, SideKey, SideTable};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ref_limits::VoiceRefLimits;

/// Immutable voice reference pack. Key: string (the pack id).
const PACKS: SideTable<String, VoiceRefPack, Named> = SideTable::new(&side_table::VOICE_OWNER_REF);

/// A voice identity over its packs. Key: string (the voice id).
const IDENTITIES: SideTable<String, VoiceIdentity, Named> =
    SideTable::new(&side_table::VOICE_REF_IDENTITY);

/// A cached render-target pointer. Key: voice id `\0` target.
const TARGETS: SideTable<TargetKey, VoiceTargetRecord, Named> =
    SideTable::new(&side_table::VOICE_REF_TARGET);

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
    Target(TargetKey),
}

impl BankRow {
    fn key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pack(id) => PACKS.key_bytes(id),
            Self::Identity(id) => IDENTITIES.key_bytes(id),
            Self::Target(key) => TARGETS.key_bytes(key),
        }
    }

    /// Deletes the row; `true` when it was present.
    fn delete(&self, store: &crate::store::Store, txn: &mut heed::RwTxn<'_>) -> Result<bool> {
        match self {
            Self::Pack(id) => PACKS.delete(store, txn, id),
            Self::Identity(id) => IDENTITIES.delete(store, txn, id),
            Self::Target(key) => TARGETS.delete(store, txn, key),
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
        } else if let Some(key) = bytes.strip_prefix(TARGETS.decl().prefix) {
            TargetKey::decode_key(key).map(Self::Target)
        } else {
            None
        };
        row.ok_or(CodecError::Row(SideTableRowProblem::Undecodable))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VoiceRefOrigin {
    /// The host has obtained the recorded person's consent before capture.
    Captured,
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
        if let VoiceRefOrigin::Designed { vendor } = &self.origin {
            validate_provider_value(vendor, limits.max_design_vendor_bytes)?;
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
        let mut identity = match read_identity(&self.store, &txn, &pack.voice_id)? {
            Some(identity) => identity,
            None if pack.origin == VoiceRefOrigin::Generated => {
                return Err(invalid("generated refs need an existing source identity"));
            }
            None => VoiceIdentity {
                version: 1,
                id: pack.voice_id.clone(),
                owner: pack.owner,
                pack_ids: Vec::new(),
            },
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

    /// Builds a clone from selected bank refs. A generated pack is optional, never
    /// the only source. The digest covers exact audio and metadata, not just pack IDs.
    pub fn prepare_voice_clone(
        &self,
        voice_id: &str,
        target: &str,
        include_generated: bool,
    ) -> Result<VoiceTargetClone> {
        let txn = self.store.env.read_txn()?;
        select_clone(&self.store, &txn, voice_id, target, include_generated)
    }

    /// Saves the vendor's return value only if this request still matches the bank.
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
        )?;
        if &selected != request {
            return Err(invalid("voice clone refs changed"));
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

    /// Returns None when a target was evicted or its chosen refs have changed.
    pub fn voice_target_clone(
        &self,
        voice_id: &str,
        target: &str,
        include_generated: bool,
    ) -> Result<Option<VoiceTargetRecord>> {
        let txn = self.store.env.read_txn()?;
        current_target(&self.store, &txn, voice_id, target, include_generated)
    }

    /// Calls `admit` only while the target record at `revision` is still
    /// current. The write transaction serializes admission against withdrawal
    /// and eviction, including writers in other processes.
    pub(crate) fn with_live_voice_target<R>(
        &self,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        revision: [u8; 16],
        admit: impl FnOnce(&heed::RoTxn<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        let txn = self.store.env.write_txn()?;
        match current_target(&self.store, &txn, voice_id, target, include_generated)? {
            Some(record) if record.revision == revision => Ok(Some(admit(&txn)?)),
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
}

fn current_target(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
    target: &str,
    include_generated: bool,
) -> Result<Option<VoiceTargetRecord>> {
    let key = target_key(voice_id, target)?;
    let Some(record) = read_row(TARGETS, store, txn, &key, "corrupt voice target clone")? else {
        return Ok(None);
    };
    let selected = select_clone(store, txn, voice_id, target, include_generated)?;
    let owner = read_identity(store, txn, voice_id)?
        .ok_or_else(|| invalid("unknown voice identity"))?
        .owner;
    validate_target_record(&record, voice_id, target, limits_for(store, txn, &owner)?)?;
    if record.source_packs != selected.source_packs || record.ref_digest != selected.ref_digest {
        return Ok(None);
    }
    Ok(Some(record))
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
) -> Result<VoiceTargetClone> {
    valid_id(target)?;
    let identity = read_identity(store, txn, voice_id)?
        .ok_or_else(|| invalid("unknown voice identity or missing refs"))?;
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
mod tests {
    use super::*;

    #[test]
    fn target_reader_and_writer_reject_the_same_corrupt_rows() -> Result<()> {
        let dir = tempfile::tempdir().expect("ref vault directory");
        let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
        let owner = EntityId::now();
        vault.store_voice_ref_pack(&VoiceRefPack {
            version: 1,
            id: "source".into(),
            voice_id: "our-voice".into(),
            owner,
            origin: VoiceRefOrigin::Captured,
            clips: vec![VoiceRegisterClip {
                register: "neutral".into(),
                media_type: "audio/wav".into(),
                audio: vec![1],
                transcript: String::new(),
            }],
        })?;
        let request = vault.prepare_voice_clone("our-voice", "host", false)?;
        let valid = vault.record_voice_target_clone(&request, "provider-id", 42)?;
        for (case, mut bad) in [valid.clone(), valid.clone(), valid]
            .into_iter()
            .enumerate()
        {
            match case {
                0 => bad.cloned_at = 0,
                1 => bad.vendor_voice_id = " ".into(),
                _ => bad.vendor_voice_id = "x".repeat(4_097),
            }
            // The writer must not silently replace corrupt persisted data either.
            let key = target_key("our-voice", "host")?;
            let mut txn = vault.store.env.write_txn()?;
            TARGETS.put(&vault.store, &mut txn, &key, &bad)?;
            txn.commit()?;
            assert!(matches!(
                vault.voice_target_clone("our-voice", "host", false),
                Err(Error::InvalidConfig(_))
            ));
            assert!(matches!(
                vault.record_voice_target_clone(&request, "replacement", 43),
                Err(Error::InvalidConfig(_))
            ));
        }
        Ok(())
    }
}
