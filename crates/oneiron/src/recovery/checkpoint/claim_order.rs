//! The CLAIM origin-write floor carried through an image's raw restore.

use super::{CanonicalRows, CheckpointImage, codec_error};
use crate::Result;
use crate::batch::EntityMetadataHeader;
use crate::ports::claim_order::{CLAIM_ROW_FLOOR, decode_floor};
use crate::registry::ENTITY_TYPE_CLAIM;

pub(super) fn floor(rows: &CanonicalRows) -> Result<u64> {
    decode_floor(
        rows.iter()
            .find(|(key, _)| key.as_slice() == CLAIM_ROW_FLOOR)
            .map(|(_, value)| value.as_slice()),
    )
}

pub(super) fn set_floor(rows: &mut CanonicalRows, version: u64) {
    let value = version.to_be_bytes().to_vec();
    if let Some((_, current)) = rows
        .iter_mut()
        .find(|(key, _)| key.as_slice() == CLAIM_ROW_FLOOR)
    {
        *current = value;
    } else {
        rows.push((CLAIM_ROW_FLOOR.to_vec(), value));
        rows.sort_by(|(left, _), (right, _)| left.cmp(right));
    }
}

/// Plan the fixed-size row before restore admission, including sealed rows.
pub(super) fn plan_floor(image: &mut CheckpointImage, opened: &CanonicalRows) -> Result<u64> {
    let mut version = floor(&image.databases["vault_meta"])?;
    for (_, raw) in image.databases["entities"].iter().chain(opened) {
        let header = EntityMetadataHeader::parse(raw).ok_or_else(codec_error)?;
        if header.entity_type == ENTITY_TYPE_CLAIM {
            version = version.max(header.row_version);
        }
    }
    set_floor(
        image
            .databases
            .get_mut("vault_meta")
            .ok_or_else(codec_error)?,
        version,
    );
    Ok(version)
}
