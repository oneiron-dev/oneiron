//! Account-sealed hosted derivations. Only explicitly public artifacts share keys.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::side_table::{self, Raw, SideTable};

/// The bound owner of this holding vault. Key: `()` (singleton); value: 32 raw bytes.
const DERIVATION_OWNER: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::DERIVATION_OWNER);
/// Stable account or organization id of the owner of the holding vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DerivationOwner(pub [u8; 32]);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivationKind {
    Replay,
    Content,
    Embedding,
    Gpu,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DerivationKey([u8; 32]);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedOutput {
    owner: DerivationOwner,
    key: DerivationKey,
    bytes: Vec<u8>,
}
impl SealedOutput {
    pub fn owner(&self) -> DerivationOwner {
        self.owner
    }
    pub fn read(&self, owner: DerivationOwner) -> Option<&[u8]> {
        (owner == self.owner).then_some(self.bytes.as_slice())
    }
}
/// The host obtains the owner from the holding vault, never from a GPU result.
#[derive(Clone, Copy, Debug)]
pub struct DerivationScope {
    owner: DerivationOwner,
}
impl DerivationScope {
    pub fn owner(&self) -> DerivationOwner {
        self.owner
    }
    pub fn key(&self, kind: DerivationKind, computation: &[u8], content: &[u8]) -> DerivationKey {
        key(Some(self.owner), kind, computation, content)
    }
    pub fn seal_gpu_output(
        &self,
        computation: &[u8],
        content: &[u8],
        output: Vec<u8>,
    ) -> SealedOutput {
        SealedOutput {
            owner: self.owner,
            key: self.key(DerivationKind::Gpu, computation, content),
            bytes: output,
        }
    }
}
fn key(
    owner: Option<DerivationOwner>,
    kind: DerivationKind,
    computation: &[u8],
    content: &[u8],
) -> DerivationKey {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:hosted-derivation:v1");
    match owner {
        Some(owner) => {
            hash.update(&[1]);
            hash.update(&owner.0);
        }
        None => {
            hash.update(&[0]);
        }
    }
    hash.update(&[match kind {
        DerivationKind::Replay => 0,
        DerivationKind::Content => 1,
        DerivationKind::Embedding => 2,
        DerivationKind::Gpu => 3,
    }]);
    for part in [computation, content] {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    DerivationKey(*hash.finalize().as_bytes())
}
/// Host-owned cache; entries cannot be read with another account's scope.
#[derive(Default)]
pub struct HostedDerivationCache {
    sealed: BTreeMap<DerivationKey, SealedOutput>,
    public: BTreeMap<DerivationKey, Vec<u8>>,
}
impl HostedDerivationCache {
    pub fn put(
        &mut self,
        scope: &DerivationScope,
        kind: DerivationKind,
        computation: &[u8],
        content: &[u8],
        bytes: Vec<u8>,
    ) {
        let key = scope.key(kind, computation, content);
        self.sealed.entry(key.clone()).or_insert(SealedOutput {
            owner: scope.owner,
            key,
            bytes,
        });
    }
    pub fn get(
        &self,
        scope: &DerivationScope,
        kind: DerivationKind,
        computation: &[u8],
        content: &[u8],
    ) -> Option<&[u8]> {
        let key = scope.key(kind, computation, content);
        let output = self.sealed.get(&key)?;
        if output.key != key {
            return None;
        }
        output.read(scope.owner)
    }
    /// Only the trusted public-artifact computation lane may use this door.
    pub fn put_public_artifact(&mut self, computation: &[u8], artifact: &[u8], output: Vec<u8>) {
        self.public
            .entry(key(None, DerivationKind::Content, computation, artifact))
            .or_insert(output);
    }
    pub fn public_artifact(&self, computation: &[u8], artifact: &[u8]) -> Option<&[u8]> {
        self.public
            .get(&key(None, DerivationKind::Content, computation, artifact))
            .map(Vec::as_slice)
    }
}
impl crate::Vault {
    /// Host-only initialization. The first owner binding is immutable.
    pub fn bind_derivation_owner(&self, owner: DerivationOwner) -> crate::Result<DerivationScope> {
        self.with_write_txn(|txn| {
            if let Some(existing) = DERIVATION_OWNER.get(&self.store, txn, &())? {
                if existing != owner.0 {
                    return Err(crate::Error::InvalidConfig(
                        "derivation owner already bound".into(),
                    ));
                }
            } else {
                self.store.seal_pending_embeddings_for_owner(txn, owner)?;
                DERIVATION_OWNER.put(&self.store, txn, &(), &owner.0)?;
            }
            Ok(DerivationScope { owner })
        })
    }
    pub fn derivation_scope(&self) -> crate::Result<DerivationScope> {
        let txn = self.store.env.read_txn()?;
        let owner = DERIVATION_OWNER
            .get(&self.store, &txn, &())?
            .ok_or_else(|| crate::Error::InvalidConfig("derivation owner is not bound".into()))?;
        Ok(DerivationScope {
            owner: DerivationOwner(owner),
        })
    }
}
/// Shared read primitive for derivation-bearing storage codecs.
pub(crate) fn owner_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> crate::Result<Option<DerivationOwner>> {
    Ok(DERIVATION_OWNER.get(store, txn, &())?.map(DerivationOwner))
}
pub(crate) fn sealed_digest(
    owner: DerivationOwner,
    kind: DerivationKind,
    computation: &[u8],
    content: &[u8],
) -> [u8; 32] {
    key(Some(owner), kind, computation, content).0
}

impl crate::Vault {
    /// Construct a derivation key from this holding vault's bytes and owner.
    pub fn derivation_key_for_entity(
        &self,
        kind: DerivationKind,
        computation: &[u8],
        entity: &crate::EntityId,
    ) -> crate::Result<Option<DerivationKey>> {
        let scope = self.derivation_scope()?;
        Ok(self
            .get(entity)?
            .map(|body| scope.key(kind, computation, &body)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_content_is_sealed_for_replay_cache_embedding_and_gpu() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = crate::Vault::open(a_dir.path(), crate::VaultConfig::device()).unwrap();
        let b = crate::Vault::open(b_dir.path(), crate::VaultConfig::device()).unwrap();
        let a_scope = a.bind_derivation_owner(DerivationOwner([1; 32])).unwrap();
        let b_scope = b.bind_derivation_owner(DerivationOwner([2; 32])).unwrap();
        let world = crate::EntityId::now();
        for vault in [&a, &b] {
            vault
                .put_entity(
                    &world,
                    crate::registry::ENTITY_TYPE_WORLD,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    b"byte-identical foreign WORLD",
                )
                .unwrap();
        }
        for kind in [
            DerivationKind::Replay,
            DerivationKind::Content,
            DerivationKind::Embedding,
        ] {
            assert_ne!(
                a.derivation_key_for_entity(kind, b"model-v1", &world)
                    .unwrap(),
                b.derivation_key_for_entity(kind, b"model-v1", &world)
                    .unwrap()
            );
        }
        let a = a_scope;
        let b = b_scope;
        let mut cache = HostedDerivationCache::default();
        for kind in [
            DerivationKind::Replay,
            DerivationKind::Content,
            DerivationKind::Embedding,
            DerivationKind::Gpu,
        ] {
            assert_ne!(
                a.key(kind, b"model-v1", b"foreign WORLD"),
                b.key(kind, b"model-v1", b"foreign WORLD")
            );
            cache.put(&a, kind, b"model-v1", b"foreign WORLD", vec![7]);
            assert_eq!(
                cache.get(&a, kind, b"model-v1", b"foreign WORLD"),
                Some([7].as_slice())
            );
            assert_eq!(cache.get(&b, kind, b"model-v1", b"foreign WORLD"), None);
        }
        let output = a.seal_gpu_output(b"model", b"foreign WORLD", vec![9]);
        assert_eq!(output.owner(), a.owner());
        assert_eq!(output.read(b.owner()), None);
        cache.put_public_artifact(b"compile", b"public source", vec![5]);
        assert_eq!(
            cache.public_artifact(b"compile", b"public source"),
            Some([5].as_slice())
        );
    }
}
