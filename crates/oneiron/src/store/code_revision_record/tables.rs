//! Finalized revision presence and immutable promotion receipt tables.

use heed::RoTxn;

use super::CodeRevision;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, LegacyCompact, Raw, SideTable};
use crate::store::Store;

/// Finalized code-revision row (hand-rolled MessagePack map). Key: revision id.
pub(crate) const RECORDS: SideTable<EntityId, CodeRevision, Raw> =
    SideTable::new(&side_table::CODE_REVISION_RECORD);

/// Immutable receipt of the file-mode-review proposal ids that promoted a revision, as their
/// sorted hex spellings. Key: revision id.
pub(crate) const PROMOTIONS: SideTable<EntityId, Vec<String>, LegacyCompact> =
    SideTable::new(&side_table::CODE_REVISION_PROMOTION);

pub(crate) fn has_finalized_code_revision_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<bool> {
    RECORDS.contains(store, rtxn, revision_id)
}

/// OF-222 (FIX 2768) archive seam: the promotion receipts a whole-vault archive carries beside
/// each revision, lent with their own key type and codec.
pub(crate) fn archive_promotion_table() -> crate::batch::export::LentSideTable {
    &PROMOTIONS
}
