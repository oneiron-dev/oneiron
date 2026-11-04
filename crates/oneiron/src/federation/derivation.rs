//! Account-sealed hosted derivations, defined in the storage layer.

pub use crate::store::derivation::{
    DerivationBindError, DerivationKey, DerivationKind, DerivationOwner, DerivationScope,
    HostedDerivationCache, SealedOutput,
};
pub(crate) use crate::store::derivation::{owner_in_txn, sealed_digest};

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
