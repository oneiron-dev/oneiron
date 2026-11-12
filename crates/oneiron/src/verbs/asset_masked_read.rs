//! `vault.assets.masked_read`: one admitted ASSET's bytes, always masked, as standard base64.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadResult;
use crate::memory::{EntityRequest, Memory, MemoryResult};

/// `vault.assets.masked_read`'s answer: the ASSET's hex ref with its bytes,
/// always masked, as standard base64. A repo file a mark covers, or a value
/// custody knows reads in, answers its projection, and a file stored with
/// keys in it its copy with each key overwritten; every other ASSET answers
/// its stored bytes. Missing, withheld and non-ASSET refs answer none, not
/// this, and so does an ASSET no masked copy is served of or whose bytes
/// the release scan still reads a credential in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MaskedAssetRead {
    /// The ASSET read, as 32 hex.
    pub entity_ref: String,
    /// Its bytes as a masked reader reads them, as standard base64.
    pub body_base64: String,
}

/// `vault.assets.masked_read` on a handle: `input.entity_ref` as its ASSET
/// bytes, always masked, under the caller's lane. The lane read refuses a
/// caller with no live owner Grant naming the verb, in the serving snapshot
/// itself; a missing, withheld or non-ASSET ref answers `None`, never an
/// error. The caller's retrieval filter only narrows what the ref reads.
pub fn vault_assets_masked_read_embedded(
    memory: &Memory<'_>,
    input: EntityRequest,
) -> MemoryResult<ScopedReadResult<Option<MaskedAssetRead>>> {
    let bound = memory.with_read_filter(input.filter.as_ref());
    let read = bound.masked_asset_read(&input.entity_ref)?;
    Ok(ScopedReadResult {
        value: read.value.map(|(id, body)| MaskedAssetRead {
            entity_ref: id.to_hex(),
            body_base64: base64::engine::general_purpose::STANDARD.encode(body),
        }),
        receipt: read.receipt,
    })
}
