//! Whether a kept checkpoint image was built under the root policy an
//! attestation signs (FIX 2994). An image built before a policy change names
//! the old policy; attested under the current one, its pin would fail
//! `VerifiedAuthorityCheckpoint::verify`, whose image policy must be the
//! pin's. A known mismatch is refused before the root signs and again before
//! the attestation is stored. An image this install does not keep, or whose
//! bytes do not read, keeps today's path: the image is rebuilt under the
//! chosen policy, never rewritten.

use serde::Deserialize;

use super::*;
use crate::authority::checkpoint::checkpoint_image_bytes_in_txn;
use crate::authority::checkpoint_image::{
    AUTHORITY_CHECKPOINT_V2_DOMAIN, AUTHORITY_CHECKPOINT_V2_MAX_BYTES, checkpoint_image_id,
};

/// What a known candidate/current policy mismatch does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointPolicyMismatch {
    /// The attestation is refused; the owner rebuilds the image under the
    /// policy the vault fixes now.
    RefuseKnownMismatch,
}

/// What an image whose policy cannot be read does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointPolicyUnknown {
    /// The attestation goes on as it does today; the unknown is noted, never
    /// read as a match.
    KeepCurrent,
}

/// The one rule for a known mismatch (CALLS `FIX 2994 checkpoint policy
/// bound before signing`, released by the Orchestrator 10-22 05:4x).
pub const CHECKPOINT_POLICY_MISMATCH: CheckpointPolicyMismatch =
    CheckpointPolicyMismatch::RefuseKnownMismatch;

/// The one rule for an image whose policy cannot be read (same CALLS row).
pub const CHECKPOINT_POLICY_UNKNOWN: CheckpointPolicyUnknown = CheckpointPolicyUnknown::KeepCurrent;

/// What a kept image says of the policy it was built under, against the
/// policy an attestation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ImagePolicy {
    /// Built under the named policy.
    Matches,
    /// Built under another policy.
    Mismatch,
    /// Not kept here, or its bytes, its id or its policy do not read.
    Unknown,
}

/// The policy an image's bytes name, read without the rest of the image.
#[derive(Deserialize)]
struct PolicyOnly {
    root_policy: CheckpointRootPolicy,
}

/// What kept image `image` says against the policy whose digest is
/// `policy`, read in `txn`. A storage or decode fault is
/// [`ImagePolicy::Unknown`], never a match.
pub(super) fn image_policy_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    image: &[u8; 32],
    policy: &[u8; 32],
) -> ImagePolicy {
    let Ok(Some(bytes)) = checkpoint_image_bytes_in_txn(store, txn, image) else {
        return ImagePolicy::Unknown;
    };
    if checkpoint_image_id(&bytes) != *image || bytes.len() > AUTHORITY_CHECKPOINT_V2_MAX_BYTES {
        return ImagePolicy::Unknown;
    }
    let built = bytes
        .strip_prefix(AUTHORITY_CHECKPOINT_V2_DOMAIN)
        .and_then(|body| rmp_serde::from_slice::<PolicyOnly>(body).ok())
        .and_then(|only| only.root_policy.digest().ok());
    match built {
        Some(built) if built == *policy => ImagePolicy::Matches,
        Some(_) => ImagePolicy::Mismatch,
        None => ImagePolicy::Unknown,
    }
}

impl ImagePolicy {
    /// Refuses a known mismatch ([`CHECKPOINT_POLICY_MISMATCH`]); a match
    /// and an unknown go on ([`CHECKPOINT_POLICY_UNKNOWN`]).
    pub(super) fn admit(self, image: &[u8; 32]) -> Result<()> {
        match self {
            Self::Matches => Ok(()),
            Self::Mismatch => match CHECKPOINT_POLICY_MISMATCH {
                CheckpointPolicyMismatch::RefuseKnownMismatch => Err(attest_refused(
                    "the image was built under another root policy; build one under this vault's policy",
                )),
            },
            Self::Unknown => match CHECKPOINT_POLICY_UNKNOWN {
                CheckpointPolicyUnknown::KeepCurrent => {
                    tracing::debug!(
                        image = %crate::entity_id::bytes_to_hex_lower(image),
                        "the checkpoint image's root policy did not read here; attesting as before"
                    );
                    Ok(())
                }
            },
        }
    }
}
