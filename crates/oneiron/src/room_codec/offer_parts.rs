//! Large Offer wording rides as parts; its actor fields stay editable inline.
//!
//! The empty inline `what` is a codec placeholder, never an admitted whole
//! Offer. Readers restore its canonical JSON string before returning a row.

use loro::LoroMap;
use serde::{Deserialize, Serialize};

use super::carrier_parts::{Parts, assembly_fits, join_parts, split_parts, write_parts};
use super::loro_bytes::map_insert_bytes;
use super::room_parts::ROOM_FACT_MAX_ROW_BYTES;
use crate::error::{Error, Result};
use crate::workspace_roster::RoomSideRow;

const MANIFEST: &[u8] = b"\0offer-parts\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfferManifest {
    pub(crate) header: RoomSideRow,
    what: Parts,
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("room offer parts refused: {reason}"))
}

pub(crate) fn is_manifest(bytes: &[u8]) -> bool {
    bytes.starts_with(MANIFEST)
}

impl OfferManifest {
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > ROOM_FACT_MAX_ROW_BYTES {
            return None;
        }
        let mut manifest: Self = serde_json::from_slice(bytes.strip_prefix(MANIFEST)?).ok()?;
        (manifest.valid() && manifest.encode().ok()? == bytes).then_some(manifest)
    }

    fn valid(&mut self) -> bool {
        self.header
            .offer_what_mut()
            .is_some_and(|what| what.is_empty())
            && self.header.place().is_some()
            && self.header.well_formed()
            && self.what.well_formed()
            && self.what.len > ROOM_FACT_MAX_ROW_BYTES as u64
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = MANIFEST.to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| refused("does not encode"))?);
        Ok(bytes)
    }

    pub(crate) fn parts(&self) -> Parts {
        self.what.clone()
    }

    /// The full canonical row length, not just the detached string's length.
    pub(crate) fn logical_len(&self) -> Option<u64> {
        let head = u64::try_from(serde_json::to_vec(&self.header).ok()?.len()).ok()?;
        head.checked_add(self.what.len)?.checked_sub(2)
    }

    pub(crate) fn joined(mut self, map: &LoroMap) -> Option<Vec<u8>> {
        let len = self.logical_len()?;
        if !assembly_fits(len) {
            return None;
        }
        let bytes = join_parts(map, &self.what)?;
        let what: String = serde_json::from_slice(&bytes).ok()?;
        if serde_json::to_vec(&what).ok()? != bytes {
            return None;
        }
        *self.header.offer_what_mut()? = what;
        let row = serde_json::to_vec(&self.header).ok()?;
        (u64::try_from(row.len()).ok()? == len).then_some(row)
    }

    /// Only the same actor-erasure transform replaces this inline header.
    pub(crate) fn with_header(mut self, header: RoomSideRow) -> Result<Vec<u8>> {
        self.header = header;
        if !self.valid() {
            return Err(refused("invalid erased header"));
        }
        let bytes = self.encode()?;
        if bytes.len() > ROOM_FACT_MAX_ROW_BYTES {
            return Err(refused("erased header exceeds its inline bound"));
        }
        Ok(bytes)
    }
}

/// Writes this representation only when the wording alone needs parts and
/// the remaining header fits inline. Every other row keeps its ordinary split.
pub(crate) fn write_row(map: &LoroMap, key: &str, row: &[u8], max: usize) -> Result<bool> {
    if max != ROOM_FACT_MAX_ROW_BYTES || row.len() <= max {
        return Ok(false);
    }
    let Ok(mut header) = serde_json::from_slice::<RoomSideRow>(row) else {
        return Ok(false);
    };
    if serde_json::to_vec(&header).map_err(|_| refused("row does not encode"))? != row {
        return Ok(false);
    }
    let Some(what) = header.offer_what_mut() else {
        return Ok(false);
    };
    let what = std::mem::take(what);
    let bytes = serde_json::to_vec(&what).map_err(|_| refused("wording does not encode"))?;
    if bytes.len() <= max {
        return Ok(false);
    }
    let (what, pieces) = split_parts(&bytes)?;
    let mut manifest = OfferManifest { header, what };
    if !manifest.valid() {
        return Ok(false);
    }
    let value = manifest.encode()?;
    if value.len() > max {
        return Ok(false);
    }
    map_insert_bytes(map, key, &value)?;
    write_parts(map, &pieces, || {})?;
    Ok(true)
}
