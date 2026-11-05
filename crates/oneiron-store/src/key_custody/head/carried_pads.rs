//! World pad compartments a restore left unopened, carried forward (PAD-3,
//! FIX 11133).
//!
//! A head's world compartment holds one pad: its live entry or its
//! retirement fact, named by its [`PadCompartmentIdentity`], which the
//! control compartment authenticates with the rest of the compartment's
//! wire. A restore whose opener does not open one keeps it as it came
//! ([`CarriedWorldPad`]): its sealed body and its key's wraps verbatim, at
//! the position and index of the head it came from, with that head's and
//! its control compartment's BLAKE3 as provenance. The restored vault keeps
//! it beside its custody, and each later head carries it, its wraps to
//! recipients no longer admitted dropped, never wrapped again, until the pad
//! opens here or is erased. No new seal: it opens under its origin key id,
//! as it would have in its own head, and the carrying head's control
//! compartment commits to its whole wire.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::key_custody::head::pad_scope::WorldPadScope;
use crate::key_custody::head::scope::CompartmentScope;
use crate::key_custody::head::scope::CustodyOpener;
use crate::key_custody::head::wire::DigestRoot;
use crate::key_custody::head::wire::WrapWire;
use crate::key_custody::identity::CustodyId;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySecret;

/// The derive-key context of a compartment's commitment in its head's
/// control compartment: the canonical encoding of its whole wire.
pub const COMPARTMENT_DIGEST_CONTEXT: &str = "oneiron/custody-head/compartment-digest/v2";
/// The derive-key context of a carried compartment's commitment.
pub const CARRIED_DIGEST_CONTEXT: &str = "oneiron/custody-head/carried-digest/v2";
/// The derive-key context of a control compartment's root over them all.
pub const DIGEST_ROOT_CONTEXT: &str = "oneiron/custody-head/digest-root/v3";
/// The derive-key context of the publication policy's carried-set digest.
pub const CARRIED_SET_CONTEXT: &str = "oneiron/custody-head/carried-set/v1";
pub const CARRIED_MAGIC: &[u8; 4] = b"OCCW";
/// The name a carried compartment's file takes beside its pad's entries.
pub const CARRIED_PREFIX: &str = ".carried-";

/// A pad's full id as msgpack bin.
pub mod pad_item {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(item: &[u8; 40], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(item)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<[u8; 40], D::Error> {
        let bytes = crate::key_custody::head::wire::serde_bytes_vec::deserialize(input)?;
        <[u8; 40]>::try_from(bytes.as_slice()).map_err(|_| {
            <D::Error as serde::de::Error>::invalid_length(bytes.len(), &"a 40-byte pad id")
        })
    }
}

/// What a compartment carried from `head`, whose sealed control compartment
/// is `control`, keeps of where it came from: the BLAKE3 of each.
pub fn provenance(head: &[u8], control: &[u8]) -> ([u8; 32], [u8; 32]) {
    (
        *blake3::hash(head).as_bytes(),
        *blake3::hash(control).as_bytes(),
    )
}
