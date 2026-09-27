//! Private per-vault voice reference bank. Provider voice IDs are evictable pointers, not identities.
use std::collections::BTreeSet;

use crate::{
    EntityId, Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ref_limits::VoiceRefLimits;

const OWNER_PREFIX: &[u8] = b"voice:owner_ref_owner:v1:";
const PACK_PREFIX: &[u8] = b"voice:owner_ref:v1:";
const IDENTITY_PREFIX: &[u8] = b"voice:ref_identity:v1:";
const TARGET_PREFIX: &[u8] = b"voice:ref_target:v1:";

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
fn key(prefix: &[u8], id: &str) -> Result<Vec<u8>> {
    valid_id(id)?;
    Ok([prefix, id.as_bytes()].concat())
}
fn target_key(voice_id: &str, target: &str) -> Result<Vec<u8>> {
    valid_id(voice_id)?;
    valid_id(target)?;
    Ok([TARGET_PREFIX, voice_id.as_bytes(), b"\0", target.as_bytes()].concat())
}
fn owner_index(owner: &EntityId, key: &[u8]) -> Vec<u8> {
    [OWNER_PREFIX, owner.as_bytes(), key].concat()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|e| Error::InvalidConfig(e.to_string()))
}
fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8], message: &str) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| invalid(message))
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
    let prefix = [OWNER_PREFIX, owner.as_bytes()].concat();
    let rows = store
        .vault_meta
        .prefix_iter(txn, &prefix)?
        .map(|row| row.map(|(key, value)| (key.to_vec(), value.to_vec())))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut deleted = 0;
    for (index, key) in rows {
        if store.vault_meta.delete(txn, &key)? {
            deleted += 1;
        }
        store.vault_meta.delete(txn, &index)?;
    }
    Ok(deleted)
}

impl Vault {
    /// Creates an identity on its first captured/designed pack, then adds immutable packs.
    /// Generated refs need an existing source identity and remain separate tagged packs.
    pub fn store_voice_ref_pack(&self, pack: &VoiceRefPack) -> Result<()> {
        let pack_key = key(PACK_PREFIX, &pack.id)?;
        let identity_key = key(IDENTITY_PREFIX, &pack.voice_id)?;
        let bytes = encode(pack)?;
        let mut txn = self.store.env.write_txn()?;
        pack.validate(limits_for(&self.store, &txn, &pack.owner)?)?;
        if let Some(existing) = self.store.vault_meta.get(&txn, &pack_key)? {
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
        self.store.vault_meta.put(&mut txn, &pack_key, &bytes)?;
        self.store
            .vault_meta
            .put(&mut txn, &identity_key, &encode(&identity)?)?;
        self.store
            .vault_meta
            .put(&mut txn, &owner_index(&pack.owner, &pack_key), &pack_key)?;
        self.store.vault_meta.put(
            &mut txn,
            &owner_index(&pack.owner, &identity_key),
            &identity_key,
        )?;
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
        };
        let target_key = target_key(&request.voice_id, &request.target)?;
        let owner = read_identity(&self.store, &txn, &request.voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?
            .owner;
        let limits = limits_for(&self.store, &txn, &owner)?;
        validate_target_record(&record, &request.voice_id, &request.target, limits)?;
        if let Some(raw) = self.store.vault_meta.get(&txn, &target_key)? {
            let existing: VoiceTargetRecord = decode(&raw, "corrupt voice target clone")?;
            validate_target_record(&existing, &request.voice_id, &request.target, limits)?;
            if existing.source_packs == request.source_packs
                && existing.ref_digest == request.ref_digest
            {
                return Ok(existing); // A current target pointer is not replaced without new refs.
            }
        }
        self.store
            .vault_meta
            .put(&mut txn, &target_key, &encode(&record)?)?;
        self.store
            .vault_meta
            .put(&mut txn, &owner_index(&owner, &target_key), &target_key)?;
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
        let key = target_key(voice_id, target)?;
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&txn, &key)? else {
            return Ok(None);
        };
        let record: VoiceTargetRecord = decode(&raw, "corrupt voice target clone")?;
        let selected = select_clone(&self.store, &txn, voice_id, target, include_generated)?;
        let owner = read_identity(&self.store, &txn, voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?
            .owner;
        validate_target_record(
            &record,
            voice_id,
            target,
            limits_for(&self.store, &txn, &owner)?,
        )?;
        if record.source_packs != selected.source_packs || record.ref_digest != selected.ref_digest
        {
            return Ok(None);
        }
        Ok(Some(record))
    }

    pub fn evict_voice_target(&self, voice_id: &str, target: &str) -> Result<()> {
        let key = target_key(voice_id, target)?;
        let identity = self
            .voice_identity(voice_id)?
            .ok_or_else(|| invalid("unknown voice identity"))?;
        let mut txn = self.store.env.write_txn()?;
        self.store.vault_meta.delete(&mut txn, &key)?;
        self.store
            .vault_meta
            .delete(&mut txn, &owner_index(&identity.owner, &key))?;
        txn.commit()?;
        Ok(())
    }
}

fn read_identity(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &str,
) -> Result<Option<VoiceIdentity>> {
    let identity_key = key(IDENTITY_PREFIX, id)?;
    let Some(bytes) = store.vault_meta.get(txn, &identity_key)? else {
        return Ok(None);
    };
    let identity: VoiceIdentity = decode(&bytes, "corrupt voice identity")?;
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
    let digest = Sha256::digest(encode(&packs)?);
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
    let key = key(PACK_PREFIX, id)?;
    let Some(bytes) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let pack: VoiceRefPack = decode(&bytes, "corrupt voice reference pack")?;
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
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
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
            vault.store.vault_meta.put(&mut txn, &key, &encode(&bad)?)?;
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
