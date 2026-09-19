//! Private per-vault owner reference bank. Providers receive clones, never own identity.
use serde::{Deserialize, Serialize};
use crate::{Vault, EntityId, error::{Error, Result}};
const PREFIX: &[u8] = b"voice:owner_ref:v1:";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="kind", rename_all="snake_case")]
pub enum VoiceRefOrigin { OwnerCapture, VendorIdentity { vendor: String } }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceRegisterClip { pub register: String, pub media_type: String, pub audio: Vec<u8>, pub transcript: String }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerVoiceRefPack { pub version: u8, pub id: String, pub owner: EntityId, pub origin: VoiceRefOrigin, pub clips: Vec<VoiceRegisterClip> }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceTargetClone { pub target: String, pub source_pack: String, pub owner: EntityId, pub clips: Vec<VoiceRegisterClip> }
fn invalid(message: &str) -> Error { Error::InvalidConfig(message.into()) }
fn key(id: &str) -> Result<Vec<u8>> {
    if id.trim().is_empty() || id.len()>128 || id.contains('\0') { return Err(invalid("invalid voice reference id")); }
    Ok([PREFIX,id.as_bytes()].concat())
}
impl OwnerVoiceRefPack {
    pub fn validate(&self) -> Result<()> {
        key(&self.id)?;
        if self.version != 1 || self.origin != VoiceRefOrigin::OwnerCapture { return Err(invalid("voice identity must originate in the owner ref bank")); }
        if self.clips.is_empty() || self.clips.len()>32 || self.clips.iter().map(|c| c.audio.len()).sum::<usize>() > 16*1024*1024 { return Err(invalid("invalid voice reference pack size")); }
        let mut names = std::collections::BTreeSet::new();
        for clip in &self.clips {
            if clip.register.trim().is_empty() || clip.register.len()>128 || !names.insert(&clip.register) || !clip.media_type.starts_with("audio/") || clip.audio.is_empty() || clip.transcript.len()>16_384 { return Err(invalid("invalid voice reference clip")); }
        }
        Ok(())
    }
}
impl Vault {
    /// The caller is the authenticated owner capture path. Vendor identities are refused.
    pub fn store_owner_voice_refs(&self, pack: &OwnerVoiceRefPack) -> Result<()> {
        pack.validate()?; let key = key(&pack.id)?;
        let bytes = rmp_serde::to_vec_named(pack).map_err(|e| Error::InvalidConfig(e.to_string()))?;
        let mut txn = self.store.env.write_txn()?;
        if let Some(existing) = self.store.vault_meta.get(&txn,&key)? {
            if existing != bytes { return Err(invalid("voice reference id already exists")); }
        } else { self.store.vault_meta.put(&mut txn,&key,&bytes)?; }
        txn.commit()?; Ok(())
    }
    pub fn owner_voice_refs(&self, id: &str) -> Result<Option<OwnerVoiceRefPack>> {
        let key = key(id)?; let txn = self.store.env.read_txn()?;
        let Some(bytes) = self.store.vault_meta.get(&txn,&key)? else { return Ok(None); };
        let pack: OwnerVoiceRefPack = rmp_serde::from_slice(&bytes).map_err(|_| invalid("corrupt voice reference pack"))?;
        pack.validate()?; if pack.id != id { return Err(invalid("voice reference key mismatch")); } Ok(Some(pack))
    }
    /// Each target receives its own owned copy. No target id can be written back
    /// as the identity's origin. Raw refs remain private, never retrieval entities.
    pub fn clone_voice_refs_into(&self, id: &str, target: &str) -> Result<VoiceTargetClone> {
        if target.trim().is_empty() || target.len()>128 { return Err(invalid("invalid voice render target")); }
        let pack = self.owner_voice_refs(id)?.ok_or_else(|| invalid("unknown owner voice reference"))?;
        Ok(VoiceTargetClone { target: target.into(), source_pack: pack.id, owner: pack.owner, clips: pack.clips })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_bank_is_private_per_vault_and_clones_into_two_targets() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let (_other_dir, other) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let mut pack = OwnerVoiceRefPack { version: 1, id: "owner-registers".into(), owner: EntityId::now(), origin: VoiceRefOrigin::OwnerCapture, clips: vec![VoiceRegisterClip { register: "neutral".into(), media_type: "audio/wav".into(), audio: vec![1,2,3], transcript: "reference".into() }] };
        vault.store_owner_voice_refs(&pack)?;
        assert!(other.owner_voice_refs(&pack.id)?.is_none());
        let a = vault.clone_voice_refs_into(&pack.id,"local-target")?; let b = vault.clone_voice_refs_into(&pack.id,"remote-target")?;
        assert_eq!(a.clips,b.clips); assert_ne!(a.target,b.target); assert_eq!(a.source_pack,b.source_pack);
        pack.id = "vendor-born".into(); pack.origin = VoiceRefOrigin::VendorIdentity { vendor: "test".into() };
        assert!(vault.store_owner_voice_refs(&pack).is_err()); assert!(vault.owner_voice_refs(&pack.id)?.is_none()); Ok(())
    }
}
