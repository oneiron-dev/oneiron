//! Account-sealed hosted derivations. Only explicitly public artifacts share keys.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
pub struct DerivationKey(pub [u8; 32]);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedOutput {
    pub owner: DerivationOwner,
    pub key: DerivationKey,
    pub bytes: Vec<u8>,
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
    pub owner: DerivationOwner,
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
    pub sealed: BTreeMap<DerivationKey, SealedOutput>,
    pub public: BTreeMap<DerivationKey, Vec<u8>>,
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
/// Why [`crate::Vault::bind_derivation_owner_checked`] did not bind.
#[derive(Debug)]
pub enum DerivationBindError {
    /// Another owner is bound already; nothing was written.
    Mismatch,
    /// Reading or writing the binding failed.
    Engine(oneiron_base::error::Error),
}
impl From<oneiron_base::error::Error> for DerivationBindError {
    fn from(error: oneiron_base::error::Error) -> Self {
        Self::Engine(error)
    }
}
pub fn sealed_digest(
    owner: DerivationOwner,
    kind: DerivationKind,
    computation: &[u8],
    content: &[u8],
) -> [u8; 32] {
    key(Some(owner), kind, computation, content).0
}
