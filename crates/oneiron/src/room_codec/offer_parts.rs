//! Large Offer text rides as parts; its actor fields stay editable inline.
//!
//! The empty inline `what` and missing `artifact_ref` are codec placeholders,
//! never an admitted whole Offer. Readers restore their canonical JSON payload
//! before returning a row.

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
    text: Parts,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferText {
    what: String,
    artifact_ref: Option<String>,
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
        // No size gate: only the writer's whole-row bound decides production,
        // and a native header erase may shrink a live manifest's logical row
        // below it while its text parts are still missing.
        self.header
            .offer_what_mut()
            .is_some_and(|what| what.is_empty())
            && self
                .header
                .offer_artifact_mut()
                .is_some_and(|artifact| artifact.is_none())
            && self.header.place().is_some()
            && self.header.well_formed()
            && self.text.well_formed()
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = MANIFEST.to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| refused("does not encode"))?);
        Ok(bytes)
    }

    pub(crate) fn parts(&self) -> Parts {
        self.text.clone()
    }

    /// The full canonical row length, not just the detached payload's length.
    pub(crate) fn logical_len(&self) -> Option<u64> {
        let head = u64::try_from(serde_json::to_vec(&self.header).ok()?.len()).ok()?;
        let empty = OfferText {
            what: String::new(),
            artifact_ref: None,
        };
        let placeholder = u64::try_from(serde_json::to_vec(&empty).ok()?.len()).ok()?;
        head.checked_add(self.text.len)?.checked_sub(placeholder)
    }

    pub(crate) fn joined(mut self, map: &LoroMap) -> Option<Vec<u8>> {
        let len = self.logical_len()?;
        if !assembly_fits(len) {
            return None;
        }
        let bytes = join_parts(map, &self.text)?;
        let text: OfferText = serde_json::from_slice(&bytes).ok()?;
        if serde_json::to_vec(&text).ok()? != bytes {
            return None;
        }
        *self.header.offer_what_mut()? = text.what;
        *self.header.offer_artifact_mut()? = text.artifact_ref;
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

/// Writes this representation when the whole row is past its bound and the
/// empty-text header plus its Parts manifest fits inline; the text alone
/// may fit within the bound. Every other row keeps its ordinary split.
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
    let Some(artifact) = header.offer_artifact_mut() else {
        return Ok(false);
    };
    let artifact = std::mem::take(artifact);
    let text = OfferText {
        what,
        artifact_ref: artifact,
    };
    let bytes = serde_json::to_vec(&text).map_err(|_| refused("wording does not encode"))?;
    let (text, pieces) = split_parts(&bytes)?;
    let mut manifest = OfferManifest { header, text };
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
