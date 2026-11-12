//! The value-free shapes a projected repo read carries (FIX 7608 slice 2a,
//! CALL P1): the opaque placeholder's bytes, the reply descriptor beside a
//! projected file, and the proof a real-byte file reveal would carry.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::GitOid;
use crate::secret_custody::RepoFileRevealDelivery;

/// The bytes a masked reader reads in place of a file whose marks hold
/// residue no span isolates (CALL P1, `RepoOpaqueRepresentation::SealedFile`):
/// never a raw prefix, an empty file or a rewritten original.
pub(crate) const REPO_OPAQUE_FILE_BYTES: &[u8] = b"[sealed file: reveal required]\n";

#[doc(hidden)]
use oneiron_verb_wire::origin::secret_projection::types::REPO_PROJECTION_WAY_OUT;
#[doc(hidden)]
pub use oneiron_verb_wire::origin::secret_projection::types::{
    RepoFileProjectionKind, RepoFileProjectionView,
};

/// An opaque file as a masked reader gets it: the placeholder, standing in
/// for the stored blob named here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoOpaqueFile {
    pub(crate) source_blob: GitOid,
}

/// A real-byte read of one marked file, committed by the shipped file reveal
/// (ConsentGrant ApproveOnce or a standing disclosure grant) with its
/// reason logged before any byte is released. Only that reveal's committed
/// delivery mints one ([`Self::from_delivery`], FIX 7608 2b-ii); no request
/// field, owner token or `SecretSight` value does. It binds the ORIGINAL
/// blob it was judged on, the exact source and recipient its receipts name,
/// and those receipts: it opens that blob for that read and no other.
#[allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: no repo reader takes a why until 2b-ii-B, so none asks for a file reveal"
)]
#[derive(Debug)]
pub(crate) struct RepoGrantedFileProof {
    source_blob: GitOid,
    raw_blake3: [u8; 32],
    source: [u8; 32],
    recipient: [u8; 32],
    reveals: Vec<EntityId>,
}

#[allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: no repo reader takes a why until 2b-ii-B, so none asks for a file reveal"
)]
impl RepoGrantedFileProof {
    /// The proof `delivery`, a committed real-byte file read, carries.
    ///
    /// # Errors
    /// A delivery whose blob id does not parse.
    pub(super) fn from_delivery(delivery: &RepoFileRevealDelivery) -> Result<Self> {
        let target = delivery.target();
        Ok(Self {
            source_blob: GitOid::parse_hex(target.blob())
                .map_err(|_| Error::CorruptedIndex("a repo file reveal's blob id"))?,
            raw_blake3: *delivery.raw_blake3(),
            source: *target.source(),
            recipient: *target.recipient(),
            reveals: delivery.reveals().to_vec(),
        })
    }

    /// Whether this proof opens the read of the marked blob `source_blob`
    /// whose marks keep `raw_blake3`: the very ORIGINAL it was committed
    /// for, never another blob, and never one whose marks disagree.
    pub(crate) fn covers(
        &self,
        source_blob: Option<&GitOid>,
        raw_blake3: Option<[u8; 32]>,
    ) -> bool {
        source_blob == Some(&self.source_blob) && raw_blake3 == Some(self.raw_blake3)
    }

    /// The exact source digest its receipts bind.
    pub(crate) const fn source(&self) -> &[u8; 32] {
        &self.source
    }

    /// The actual recipient digest its receipts bind.
    pub(crate) const fn recipient(&self) -> &[u8; 32] {
        &self.recipient
    }

    /// Each delivered reveal row: the read's receipts.
    pub(crate) fn reveals(&self) -> &[EntityId] {
        &self.reveals
    }
}
