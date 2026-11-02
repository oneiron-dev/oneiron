//! The clear parts of the engine's sealed checkpoint and backup artifacts
//! (`ONEIRONS` files): the artifact kinds, the key header's wire form, and the
//! signed commitment's codec, digest and dual-signature check. They live here,
//! once, so the engine that writes an artifact and a host that only holds one
//! (Hypnos, which never opens a vault) read it with one codec.
//!
//! Nothing here opens a sealed frame or holds a key: the engine keeps its keys,
//! keystore, chain, sealing, image and custody, and calls this module for the
//! clear bytes around them. The one exception is a hosted checkpoint's
//! host-private member ([`seal_host_holds`], FIX 6598), sealed to the host's
//! own recipient, which the host's restore worker opens with this codec.
//!
//! A host proving what it holds reads an artifact once with [`inspect_backup`]
//! (every byte hashed and counted, its clear parts kept) and checks the
//! evidence against the signers it pinned with [`verify_with_pins`]. A partial
//! file a crash left is read with [`inspect_backup_prefix`], which never
//! refuses one for being short. The engine writes and reads version 2 only;
//! version 1 is read here for a host still holding artifacts written before
//! it. Beside each backup the engine writes now, its checkpoint fact
//! ([`SignedCheckpointFact`], FIX 7326) names the artifact's checkpoint id,
//! and [`verify_checkpoint_fact`] checks it against the same pinned signer.

mod checkpoint_fact;
mod commitment;
mod host_holds;
mod inspect;
mod prelude;
mod wire;

pub use self::checkpoint_fact::{
    CHECKPOINT_FACT_DOMAIN, CHECKPOINT_FACT_FILE_VERSION, CHECKPOINT_FACT_MAGIC,
    CHECKPOINT_FACT_SUBJECT_LEN, CHECKPOINT_FACT_VERSION, CheckpointFact, SignedCheckpointFact,
    verify_checkpoint_fact,
};
pub use self::commitment::{
    CHECKPOINT_SIGNATURE_EPOCH, CHECKPOINT_SIGNATURE_SUITE, COMMITMENT_VERSION,
    COMMITMENT_VERSION_V1, CheckpointSigner, Commitment, CustodyRef, ED25519_KEY_ID,
    MAX_SIGNED_FRAME, SLHDSA_KEY_ID, commitment_digest, verify_commitment_signature,
};
pub use self::host_holds::{
    HOST_HOLDS_AEAD, HOST_HOLDS_BINDING_LEN, HOST_HOLDS_DOMAIN, HOST_HOLDS_KEM, HOST_HOLDS_MAGIC,
    HOST_HOLDS_SEAL_EPOCH, HOST_HOLDS_VERSION, HostHoldsBinding, SealedHostHolds,
    host_holds_recipient_id, open_host_holds_family, open_host_holds_key, seal_host_holds,
};
pub use self::inspect::{
    ARTIFACT_SEAL_EPOCH, ARTIFACT_SEAL_SUITE, BackupEvidence, BackupTailEvidence, IMAGE_STREAM,
    MANIFEST_PIECE_STREAM, MANIFEST_STREAM, MAX_FRAME_LEN, inspect_backup, inspect_backup_tail,
    verify_tail_with_pins, verify_with_pins,
};
pub use self::prelude::{
    ARTIFACT_VERSION_V1, ARTIFACT_VERSION_V2, ArtifactPrelude, BackupHead, IDENTITY_V1_LEN,
    IDENTITY_V2_LEN, PRELUDE_V1_LEN, PRELUDE_V2_LEN, REGISTRY_BINDING_CONTEXT, RegistryMatch,
    inspect_backup_prefix, registry_binding,
};
pub use self::wire::{
    ArtifactKind, BACKUP_MAGIC, KeyHeader, KeyHeaderWrap, MAX_KEY_HEADER_LEN, VaultKeyWrapInfo,
    VaultKeyWrapKind,
};
