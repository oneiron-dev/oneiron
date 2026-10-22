//! A kept object's read, typed, and a kept pad object's refill (FIX 9362, L03
//! half). A read of a kept pad object whose bytes the home lacks keeps the
//! home's typed answer, its generation, digest and offset
//! ([`ObjectRead::PadsUnavailable`]): never a missing generation, never its
//! end. Erase's sweep then offers the home the same object when this
//! machine's own store keeps it whole (`sync::residence::held_pad_object`):
//! staged through `residence.bundle.put` as any pad object is, then
//! `residence.bundle.pads.refill` under the revision the sweep listed. A home
//! whose index moved since answers `CURRENT_CHANGED` and the next upkeep lists
//! again; an object no machine here keeps stays owed, and no erase waits on
//! it.

use serde::Deserialize;
use serde_json::{Value, json};

use super::{PADS_UNAVAILABLE, ResidenceRpc, put_object, refused, storage};
use crate::Vault;
use crate::sync::residence::{
    BundlePartRead, PadObjectRefill, PadObjectUnavailable, SealedBundleObject, held_pad_object,
    sealed_digest_from_hex, sealed_digest_hex, sealed_generation_from_hex, sealed_generation_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::{SealedBundleGeneration, SealedKeyPads};

/// The home's door that fills a kept pad object again.
const REFILL_RPC: &str = "residence.bundle.pads.refill";

/// One read of a kept object.
pub(super) enum ObjectRead {
    /// The whole object, of the generation the home named.
    Whole(SealedBundleGeneration, Vec<u8>),
    /// The home keeps no such generation.
    Missing,
    /// The pad object is kept, and its bytes there are not (FIX 7106).
    PadsUnavailable(PadObjectUnavailable),
}

impl ObjectRead {
    /// The whole object, or `None` for a generation the home keeps no more; a
    /// kept pad object whose bytes the home lacks fails with
    /// [`PADS_UNAVAILABLE`].
    pub(super) fn whole(self) -> Result<Option<(SealedBundleGeneration, Vec<u8>)>, TransportError> {
        match self {
            Self::Whole(generation, bytes) => Ok(Some((generation, bytes))),
            Self::Missing => Ok(None),
            Self::PadsUnavailable(_) => Err(TransportError::InvalidPayload(PADS_UNAVAILABLE)),
        }
    }
}

/// The fields of a typed answer for a kept pad object whose bytes the home
/// lacks, as a machine's get and the kit door both send it.
#[derive(Deserialize)]
struct UnavailableReply {
    generation: String,
    digest: String,
    offset: u64,
}

/// The kept pad object `reply` names as unavailable, when it is the home's
/// typed answer for one; an answer that says so and does not decode is
/// refused.
pub(super) fn unavailable_of(
    reply: &Value,
) -> Option<Result<PadObjectUnavailable, TransportError>> {
    if reply.get("outcome").and_then(Value::as_str) != Some(BundlePartRead::PAD_OBJECT_UNAVAILABLE)
    {
        return None;
    }
    let typed = UnavailableReply::deserialize(reply).map_err(|_| refused());
    Some(typed.and_then(|typed| {
        Ok(PadObjectUnavailable {
            generation: sealed_generation_from_hex(&typed.generation).ok_or_else(refused)?,
            digest: sealed_digest_from_hex(&typed.digest).ok_or_else(refused)?,
            offset: typed.offset,
        })
    }))
}

/// Offers the home the kept pad object `unavailable` names, when this
/// machine's own store keeps it whole with that digest: staged, then refilled
/// under `revision`, the index the caller listed. The object, once the home
/// read it back; `None` when no object is kept here, the home refused the
/// stage or the refill, or its index moved since (the next list sees it).
///
/// # Errors
///
/// A call that did not reach the home; storage faults.
pub(super) async fn refill_held(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    unavailable: &PadObjectUnavailable,
    revision: [u8; 32],
) -> Result<Option<SealedKeyPads>, TransportError> {
    let generation = unavailable.generation;
    let Some(pads) = held_pad_object(vault, generation, &unavailable.digest).map_err(storage)?
    else {
        return Ok(None);
    };
    if !put_object(rpc, &generation, SealedBundleObject::Pads, pads.as_bytes()).await? {
        return Ok(None);
    }
    let reply = rpc
        .call(
            REFILL_RPC,
            json!({
                "generation": sealed_generation_hex(&generation),
                "digest": sealed_digest_hex(&unavailable.digest),
                "revision": sealed_digest_hex(&revision),
            }),
        )
        .await?;
    let outcome = reply
        .as_ref()
        .ok()
        .and_then(|reply| reply.get("outcome"))
        .and_then(Value::as_str);
    if outcome == Some(PadObjectRefill::REFILLED) {
        return Ok(Some(pads));
    }
    tracing::info!(
        outcome = outcome.unwrap_or("refused"),
        "a kept pad object's refill did not land; it stays owed"
    );
    Ok(None)
}
