//! The clear parts of the engine's sealed checkpoint and backup artifacts
//! (`ONEIRONS` files): the artifact kinds, the key header's wire form, and the
//! signed commitment's codec, digest and dual-signature check. They live here,
//! once, so the engine that writes an artifact and a host that only holds one
//! (Hypnos, which never opens a vault) read it with one codec.
//!
//! Nothing here opens a sealed frame or holds a key: the engine keeps its keys,
//! keystore, chain, sealing, image and custody, and calls this module for the
//! clear bytes around them.

mod commitment;
mod wire;

pub use self::commitment::{
    CHECKPOINT_SIGNATURE_EPOCH, CHECKPOINT_SIGNATURE_SUITE, COMMITMENT_VERSION, CheckpointSigner,
    Commitment, ED25519_KEY_ID, MAX_SIGNED_FRAME, SLHDSA_KEY_ID, commitment_digest,
    verify_commitment_signature,
};
pub use self::wire::{
    ArtifactKind, BACKUP_MAGIC, KeyHeader, KeyHeaderWrap, MAX_KEY_HEADER_LEN, VaultKeyWrapInfo,
    VaultKeyWrapKind,
};
