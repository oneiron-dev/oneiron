//! Staging one sealed object on the home in parts (moved whole from the
//! bundle root; body byte-identical).

use base64::Engine as _;

use serde_json::json;

use super::super::ResidenceRpc;
use crate::sync::residence::{
    SEALED_BUNDLE_PUT_PART_MAX, SealedBundleObject, sealed_digest_hex, sealed_generation_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::SealedBundleGeneration;

/// Stages one object on the home in parts; `false` when the home refused a
/// part (FIX 3353). A part that did not reach the home is an error.
pub(super) async fn put_object(
    rpc: &mut ResidenceRpc,
    generation: &SealedBundleGeneration,
    object: SealedBundleObject,
    bytes: &[u8],
) -> Result<bool, TransportError> {
    let generation = sealed_generation_hex(generation);
    let digest = sealed_digest_hex(blake3::hash(bytes).as_bytes());
    let mut offset = 0;
    for part in bytes.chunks(SEALED_BUNDLE_PUT_PART_MAX) {
        let staged = rpc
            .call(
                "residence.bundle.put",
                json!({
                    "generation": generation.as_str(),
                    "object": object.name(),
                    "total": bytes.len(),
                    "digest": digest.as_str(),
                    "offset": offset,
                    "part": base64::engine::general_purpose::STANDARD.encode(part),
                }),
            )
            .await?;
        if staged.is_err() {
            return Ok(false);
        }
        offset += part.len();
    }
    Ok(true)
}

/// What a refused upload fails the slot with (FIX 3353).
pub(super) fn upload_refused() -> TransportError {
    TransportError::Storage("home refused the sealed bundle upload".into())
}
