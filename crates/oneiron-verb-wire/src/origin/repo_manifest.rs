//! Moved from `crates/oneiron/src/origin/repo_manifest.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
#[cfg(feature = "sync")]
use std::cmp::Ordering;

/// The manifest version this build writes and reads: 2 adds the refs
/// writer's signature (FIX 12765).
pub const REPO_MANIFEST_VERSION: u16 = 2;

/// The domain a manifest's writer signature is made in.
pub const WRITER_SIGNATURE_DOMAIN: &[u8] = b"oneiron/repo-manifest/writer/v2\0";

/// The refs writer's signature on a manifest (FIX 12765): the machine that
/// wrote it, and its Ed25519 signature over
/// [`RepoManifest::writer_signing_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoManifestWriter {
    /// The machine whose key signed.
    pub machine: EntityId,
    /// The 64-byte signature.
    pub signature: Vec<u8>,
}
