//! Moved from `crates/oneiron/src/note/fork_upload.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::note::documents::invalid;
use serde::Deserialize;
use serde::Serialize;

/// What identifies one fork upload: the fork, the parent head it forked
/// from, the frontier of that head it forked at, and whether it rewrites.
/// The NOTE is the frame's entity; the fork id is the request id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteForkUpload {
    #[serde(with = "super::id_codec")]
    pub fork: EntityId,
    #[serde(with = "super::id_codec")]
    pub parent: EntityId,
    pub frontier: Vec<u8>,
    pub rewrite: bool,
}

/// What the authority did with one fork upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NoteForkUploadOutcome {
    /// The fork is stored here, pending; a replay answers the same.
    Accepted,
    /// The fork cannot be admitted here as it is, for `reason`.
    Refused { reason: String },
}

/// The authority's answer to one fork upload: the fork, the hash of the
/// upload's identity as it was sent, and the outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteForkUploadReceipt {
    #[serde(with = "super::id_codec")]
    pub fork: EntityId,
    pub command_hash: [u8; 32],
    pub outcome: NoteForkUploadOutcome,
}

impl NoteForkUpload {
    /// The upload's payload: `[identity length: u32 BE][identity JSON]` then
    /// the fork's own operations. A queued upload keeps the payload with no
    /// operations.
    ///
    /// # Errors
    ///
    /// An identity that does not encode.
    pub fn encode_payload(&self, operations: &[u8]) -> oneiron_base::error::Result<Vec<u8>> {
        let identity = self.identity()?;
        let len = u32::try_from(identity.len()).map_err(|_| invalid("NOTE fork upload"))?;
        let mut payload = Vec::with_capacity(4 + identity.len() + operations.len());
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(&identity);
        payload.extend_from_slice(operations);
        Ok(payload)
    }

    /// The upload, its command hash and its operations, from `payload`. The
    /// identity must be the canonical encoding of what it decodes to.
    ///
    /// # Errors
    ///
    /// A payload that does not read.
    pub fn decode_payload(payload: &[u8]) -> oneiron_base::error::Result<(Self, [u8; 32], &[u8])> {
        let (len, rest) = payload
            .split_first_chunk::<4>()
            .ok_or(invalid("NOTE fork upload"))?;
        let (identity, operations) = rest
            .split_at_checked(u32::from_be_bytes(*len) as usize)
            .ok_or(invalid("NOTE fork upload"))?;
        let upload: Self =
            serde_json::from_slice(identity).map_err(|_| invalid("NOTE fork upload"))?;
        if upload.identity()? != identity {
            return Err(invalid("NOTE fork upload"));
        }
        Ok((upload, *blake3::hash(identity).as_bytes(), operations))
    }

    /// The hash a receipt names this upload by.
    ///
    /// # Errors
    ///
    /// An identity that does not encode.
    pub fn command_hash(&self) -> oneiron_base::error::Result<[u8; 32]> {
        Ok(*blake3::hash(&self.identity()?).as_bytes())
    }

    fn identity(&self) -> oneiron_base::error::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("NOTE fork upload"))
    }
}
