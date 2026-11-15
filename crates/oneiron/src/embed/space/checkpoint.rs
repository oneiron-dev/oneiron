//! Media vectors, device provenance and refusals, under each source document's
//! entity tree. A restore that carried current LIVE rows preserves its refusal
//! rows and their absence instead of reviving captured refusals.

use super::{MEDIA_REFUSED, MEDIA_VECTOR};
use crate::embed::EmbeddingProvenance;
use crate::entity_id::EntityId;
use crate::side_table::{self, Named, SideTable};
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, Check, ExactTable, Join,
};
use crate::store::checkpoint_payload::rows::{OpenedOwnerRows, OwnerRef};

const MEDIA_DEVICE: SideTable<([u8; 16], EntityId), EmbeddingProvenance, Named> =
    SideTable::new(&side_table::EMBEDDING_MEDIA_DEVICE);

/// The source document a media row's key names.
fn source_document(key: &([u8; 16], EntityId)) -> OwnerRef {
    OwnerRef::entity(&key.1)
}

/// Every media vector, device provenance and refusal row, whole under its
/// source document's tree, restored exactly.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[
        &ExactTable {
            table: MEDIA_VECTOR,
            owner: source_document,
        },
        &ExactTable {
            table: MEDIA_DEVICE,
            owner: source_document,
        },
        &ExactTable {
            table: MEDIA_REFUSED,
            owner: source_document,
        },
    ],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::NoSplit,
};

/// The restore already carried the current LIVE rows, including absence. Leave
/// superseded refusal parts out before write budgeting and getter dispatch.
pub(crate) fn preserve_current_refusals(opened: &mut OpenedOwnerRows) {
    opened
        .rows
        .retain(|part| !part.at().in_table(MEDIA_REFUSED.decl()));
}
