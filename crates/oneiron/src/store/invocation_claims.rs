//! Durable client-named invocation claims (FIX 11889).
//!
//! A claim starts as an open intent with the call's digest and its caller's
//! stamps. Its route's grouped writes count themselves on that intent. A
//! successful JSON outcome settles beside the release the next caller
//! judges again. An expired open intent becomes a reply-not-kept outcome,
//! never a miss: zero counted writes does not prove that nothing landed.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, SideTableDbs};
use crate::store::{
    IdempotencyEntry, ResponseCarriage, ResponseFamily, ResponseRead, ResponseScan, ResponseStamps,
    opaque_retired_at,
};
use oneiron_base::machine_destination::PeerMachine;

#[doc(hidden)]
pub use oneiron_records::store::invocation_claims::{
    InvocationClaimEntry, InvocationClaimRelease, StoredPeerMachine,
};

impl From<StoredPeerMachine> for PeerMachine {
    fn from(peer: StoredPeerMachine) -> Self {
        match peer {
            StoredPeerMachine::Unknown => Self::Unknown,
            StoredPeerMachine::Proven { machine, key } => Self::Proven { machine, key },
        }
    }
}

/// What a checkpoint carries of an invocation claim: the whole row, with its
/// erased form as the stub a retired instance keeps. Undecodable rows use
/// the same opaque fallback as the other response families.
pub(crate) fn invocation_claim_scan(value: &[u8]) -> ResponseScan {
    let Ok(entry) = InvocationClaimEntry::decode(value) else {
        return ResponseScan::opaque_row();
    };
    if entry.erased {
        return ResponseScan::NotResponse;
    }
    match entry.erased_form().encode() {
        Ok(stub) => ResponseScan::Decoded(ResponseCarriage::whole(stub)),
        Err(_) => ResponseScan::opaque_row(),
    }
}

/// The live bytes of a claim row, or its typed erased response.
///
/// # Errors
///
/// `ResponseErased` for an erased retired marker.
#[doc(hidden)]
pub fn invocation_claim_response_read<'a>(key: &[u8], value: &'a [u8]) -> Result<&'a [u8]> {
    ResponseRead::of(ResponseFamily::InvocationClaim, key, value).present()
}

/// When an opaque retired claim was stamped, for expiry.
#[doc(hidden)]
pub fn invocation_claim_opaque_retired_at(value: &[u8]) -> Option<u64> {
    opaque_retired_at(value)
}

/// Who owns a decoded claim row; an undecodable row names no one here and is
/// handled by the opaque-owner path instead.
pub(crate) fn invocation_claim_owners(value: &[u8]) -> Vec<EntityId> {
    InvocationClaimEntry::decode(value)
        .map(|entry| entry.owners())
        .unwrap_or_default()
}

/// Scrubs every invocation claim that names `owner`, in the erase's writer.
/// Expiry and release are deletes, but an erase leaves the truthful marker.
pub(crate) fn erase_invocation_claim_owner_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    let hex = owner.to_hex();
    let prefix = std::str::from_utf8(side_table::INVOCATION_CLAIM.prefix)
        .map_err(|_| Error::InvariantViolation("non-UTF-8 invocation claim prefix"))?;
    let mut scrubbed = Vec::new();
    for row in dbs.side_sync_state()?.prefix_iter(wtxn, prefix)? {
        let (key, value) = row?;
        if !value
            .windows(hex.len())
            .any(|window| window == hex.as_bytes())
        {
            continue;
        }
        if let Ok(entry) = InvocationClaimEntry::decode(&value)
            && !entry.erased
            && entry.owners().contains(owner)
            && let Ok(stub) = entry.erased_form().encode()
        {
            scrubbed.push((key.into_owned(), stub));
        }
    }
    for (key, stub) in scrubbed {
        dbs.side_sync_state()?.put(wtxn, &key, &stub)?;
    }
    Ok(())
}
