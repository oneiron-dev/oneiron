//! `vault.assets.masked_read`: one admitted ASSET's bytes, always masked, as standard base64.

use base64::Engine as _;

use crate::claim::ScopedReadResult;
use crate::memory::{EntityRequest, Memory, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::asset_masked_read::MaskedAssetRead;

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
