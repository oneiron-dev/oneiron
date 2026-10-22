//! A kept pad object a get finds missing or short below its length (FIX
//! 7106): a typed answer, never the object's end and never a missing
//! generation, with the entry the same read found.

use oneiron::sync::residence::{
    BundlePartRead, PadObjectUnavailable, SealedBundleEntry, SealedBundleObject, sealed_digest_hex,
    sealed_generation_hex,
};
use serde_json::{Value, json};

/// The get's answer for `unavailable`, with `entry`, the generation's entry
/// as the read found it.
pub(super) fn unavailable(entry: &SealedBundleEntry, unavailable: &PadObjectUnavailable) -> Value {
    json!({
        "outcome": BundlePartRead::PAD_OBJECT_UNAVAILABLE,
        "generation": sealed_generation_hex(&unavailable.generation),
        "object": SealedBundleObject::Pads.name(),
        "total": entry.pads_len,
        "digest": sealed_digest_hex(&unavailable.digest),
        "commitOrder": entry.commit_order,
        "offset": unavailable.offset,
    })
}
