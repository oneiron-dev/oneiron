//! Original-source data from the entity bodies this snapshot actually captured.

use std::collections::BTreeMap;

use super::{BundleRole, Projected};
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::comm::ScopedTouchRecord;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::rows::{RowDb, RowPart};

impl Projected {
    pub(super) fn scoped_touch_source_originals(&self) -> BTreeMap<EntityId, EntityId> {
        let mut originals = BTreeMap::new();
        for (role, captured) in &self.captures {
            for rows in captured.owners() {
                for part in &rows.rows {
                    let RowPart::Exact { at, value } = part else {
                        continue;
                    };
                    let id_bytes = match (*role, at.db, at.path.is_empty()) {
                        (BundleRole::Window, RowDb::SyncState | RowDb::SyncQueue, false)
                            if rows.subtype == Subtype::EntityTree =>
                        {
                            &rows.owner32[..16]
                        }
                        (_, RowDb::Entities, true) => at.key.as_slice(),
                        (_, RowDb::SyncState, true)
                            if at.in_table(&crate::side_table::SYNC_RESIDENCE_ITEM_BLOB)
                                && rows.subtype == Subtype::EntityTree =>
                        {
                            &rows.owner32[..16]
                        }
                        _ => continue,
                    };
                    let Some(header) = EntityMetadataHeader::parse(value) else {
                        continue;
                    };
                    if header.entity_type != crate::registry::ENTITY_TYPE_COMM_RECORD {
                        continue;
                    }
                    let Ok(bytes) = <[u8; 16]>::try_from(id_bytes) else {
                        continue;
                    };
                    let Ok(id) = EntityId::from_bytes(bytes) else {
                        continue;
                    };
                    if let Ok(Some(source)) =
                        ScopedTouchRecord::decode(id, &value[ENTITY_METADATA_HEADER_LEN..])
                    {
                        originals.insert(id, source.original_head());
                    }
                }
            }
        }
        originals
    }
}
