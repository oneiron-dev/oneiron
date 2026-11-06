//! The custody member drain's contract (FIX 5843, ruled 10-20): how the
//! owner takes a member out of the required set. Never a forced unpin.
//!
//! The owner's begin fences the member ([`DrainTicket`]): no head goes to it
//! and no publication ack from it is accepted any more. The member then
//! deletes every head, version, stage and alias it holds of the lineage,
//! lists it again, and answers a [`DrainAck`] that names exactly the drain
//! (member, set revision, position, operation), zero heads left, where it
//! keeps the lineage and whose lineage it is, MACed with the drain's
//! generation token, never with attester text. The owner's commit takes
//! the member out of the set at the next revision, with its history row and
//! evidence, in one write. The keyless log stays, and a member drained once
//! comes back only by an explicit re-enrolment at a newer revision.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::identity::encode_native_path;
use crate::key_custody::protocol::DeletionEvidence;
use crate::key_custody::protocol::TargetId;
use crate::key_custody::protocol::TargetSpec;
use crate::key_custody::protocol::hex;

/// The drain grammar's version.
pub const DRAIN_VERSION: u8 = 1;
pub const OPERATION_CONTEXT: &str = "oneiron/custody-drain/operation/v1";
const PLACEMENT_CONTEXT: &str = "oneiron/custody-drain/placement/v1";
pub const ORIGIN_CONTEXT: &str = "oneiron/custody-drain/origin/v1";
pub const MAC_DOMAIN: &[u8] = b"oneiron/custody-drain/ack-mac/v1";

/// One drain's generation token: the secret its member's ack is MACed
/// with, sent to the member on its own authenticated channel. A retry of
/// the same drain keeps it; a new drain of the member gets a new one. It
/// prints redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct DrainToken(pub Zeroizing<[u8; 32]>);

impl DrainToken {
    /// The token whose 32 bytes are `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Its 32 bytes, for the member's channel.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DrainToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DrainToken(..)")
    }
}

/// Where `spec`'s member keeps the lineage: its kind, its id and, for a
/// folder, its absolute folder's native bytes. A member answers with its
/// own; the owner's commit checks it against the set's record of it.
#[must_use]
pub fn drain_placement(spec: &TargetSpec) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PLACEMENT_CONTEXT);
    let kind = spec.kind().name();
    hasher.update(&(kind.len() as u64).to_be_bytes());
    hasher.update(kind.as_bytes());
    let id = spec.id().as_str();
    hasher.update(&(id.len() as u64).to_be_bytes());
    hasher.update(id.as_bytes());
    if let Some(folder) = spec
        .folder_path()
        .and_then(|folder| std::path::absolute(folder).ok())
        .and_then(|folder| encode_native_path(&folder))
    {
        hasher.update(&folder);
    }
    *hasher.finalize().as_bytes()
}
