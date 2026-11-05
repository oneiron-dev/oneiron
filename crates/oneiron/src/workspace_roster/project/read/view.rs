//! Project content from one composed snapshot, judged by the base history.

use super::{ProjectReader, ProjectRecord};
use crate::store::StoreRead;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, HostingPrivacyPosture, Result};

pub(crate) fn visible_project_in_read(
    read: &StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    id: EntityId,
) -> Result<Option<ProjectRecord>> {
    let Some(reader) = ProjectReader::new(read.base(), txn, posture)? else {
        return Ok(None);
    };
    if !read.is_union() {
        return reader.visible(id);
    }
    let LiveEntityRow::Live { entity_type, body } = live_entity_row_in_txn(read, txn, &id)? else {
        return Ok(None);
    };
    if entity_type != reader.kind {
        return Ok(None);
    }
    Ok(reader.visible_body(id, &body)?.map(|(record, _)| record))
}
