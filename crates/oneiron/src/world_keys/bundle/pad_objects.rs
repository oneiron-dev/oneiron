//! Public access and rewrite operations on sealed key-pad objects.
//! The entry point is `OpenedKeyPads::without_world`.
//! `super` owns pad storage, opening and the private pad-body codec.

use super::*;

impl SealedKeyPads {
    /// Strict parse of a frame, as [`SealedVaultBundle::from_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let frame = parse_frame(PADS, bytes)?;
        Ok(Self(SealedObject {
            generation: frame.generation,
            bytes: bytes.to_vec(),
        }))
    }

    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.0.generation
    }

    /// The padded byte length.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.bytes.len()
    }

    /// BLAKE3 of the bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.0.bytes).as_bytes()
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.bytes
    }

    /// Opens the pads with the kit's root.
    pub fn open_with_kit(
        &self,
        vault_id: &[u8; 32],
        seed: &RecoveryRootSeed,
    ) -> Result<OpenedKeyPads> {
        self.open_with(vault_id, &seed.recovery_secret()?)
    }
}

impl std::fmt::Debug for OpenedKeyPads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedKeyPads")
            .field("generation", &self.generation)
            .field("pads", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl OpenedKeyPads {
    #[must_use]
    pub fn generation(&self) -> SealedBundleGeneration {
        self.generation
    }

    /// The keys whose pads this object holds.
    pub fn keys(&self) -> impl Iterator<Item = &WorldKeyId> {
        self.entries.iter().map(|(key, _, _)| key)
    }

    /// Erase's rewrite of one object: the same generation, capsules, outer key and
    /// length, sealed afresh without `world`'s pads. It replaces the old object,
    /// which the holder deletes.
    pub fn without_world(&self, world: EntityId) -> Result<SealedKeyPads> {
        let body = encode_pads_body(
            &self.vault_id,
            self.generation,
            &self.entries,
            &self.index,
            Some(world),
        )?;
        let bytes = seal_outer(
            PADS,
            &self.vault_id,
            self.generation,
            &self.outer,
            &self.slots,
            body,
            Some(self.total),
        )?;
        Ok(SealedKeyPads(SealedObject {
            generation: self.generation,
            bytes,
        }))
    }
}
