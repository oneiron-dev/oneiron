//! The native terminal landing's byte-free canonical capture identity.

use crate::attempt_queue::AttemptId;
use crate::blob_artifact::BlobArtifactVersion;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// Written only after a first capture's native terminal settlement succeeds.
/// This is selection data, never erase or retry authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CanonicalCapture {
    artifact: EntityId,
    version: u64,
    claim: EntityId,
    content_hash: [u8; 32],
}

const CAPTURES: SideTable<[u8; 16], CanonicalCapture, Named> =
    SideTable::new(&side_table::BYOA_EXHAUST_CAPTURE);

impl CanonicalCapture {
    pub(crate) fn artifact(&self) -> EntityId {
        self.artifact
    }

    pub(crate) fn content_hash(&self) -> [u8; 32] {
        self.content_hash
    }
}

pub(super) fn record_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    artifact: EntityId,
    version: &BlobArtifactVersion,
) -> Result<()> {
    CAPTURES.put(
        store,
        txn,
        attempt.as_bytes(),
        &CanonicalCapture {
            artifact,
            version: version.version,
            claim: version.claim_id,
            content_hash: version.content_hash,
        },
    )
}

pub(crate) fn canonical_capture_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<CanonicalCapture>> {
    CAPTURES.get(store, txn, attempt.as_bytes())
}
