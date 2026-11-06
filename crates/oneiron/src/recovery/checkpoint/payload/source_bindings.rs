//! Original-source data from the raw entity rows this snapshot actually captured.

use std::collections::BTreeMap;

use super::Projected;
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::comm::ScopedTouchRecord;
use crate::store::checkpoint_payload::rows::{RowDb, RowPart};

impl Projected {
    pub(super) fn scoped_touch_source_originals(&self) -> BTreeMap<EntityId, EntityId> {
        let mut originals = BTreeMap::new();
        for (_, captured) in &self.captures {
            for rows in captured.owners() {
                for part in &rows.rows {
                    let RowPart::Exact { at, value } = part else {
                        continue;
                    };
                    if at.db != RowDb::Entities || !at.path.is_empty() {
                        continue;
                    }
                    let Some(header) = EntityMetadataHeader::parse(value) else {
                        continue;
                    };
                    if header.entity_type != crate::registry::ENTITY_TYPE_COMM_RECORD {
                        continue;
                    }
                    let Ok(bytes) = <[u8; 16]>::try_from(at.key.as_slice()) else {
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
