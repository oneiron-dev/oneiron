//! Durable client-named invocation claims (FIX 11889).
//!
//! A claim starts as an open intent with the call's digest and its caller's
//! stamps. Its route's grouped writes count themselves on that intent. A
//! successful JSON outcome settles beside the release the next caller
//! judges again. An expired open intent becomes a reply-not-kept outcome,
//! never a miss: zero counted writes does not prove that nothing landed.

use serde::{Deserialize, Serialize};

use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, SideTableDbs};
use crate::store::{
    IdempotencyEntry, ResponseCarriage, ResponseFamily, ResponseRead, ResponseScan, ResponseStamps,
    opaque_retired_at,
};

/// The durable row for one client-named invocation.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationClaimEntry {
    pub created_at_secs: u64,
    /// The BLAKE3 digest of the caller and canonical call.
    pub request_body: Vec<u8>,
    /// Zero while the call is an open intent, then its HTTP-style status.
    pub status: u16,
    /// The settled JSON response body.
    #[serde(default)]
    pub response_body: Vec<u8>,
    /// The pre-release answer, peer and rows a replay judges again.
    #[serde(default)]
    pub release: Option<InvocationClaimRelease>,
    /// Who owns the claim and its response.
    #[serde(default)]
    pub stamps: ResponseStamps,
    #[serde(default)]
    pub erased: bool,
    /// Grouped writes that committed while the intent was open (FIX 10379).
    #[serde(default)]
    pub committed_writes: u32,
    /// An expired open intent reclaimed without making the call runnable
    /// again. The count remains truthful, including zero (FIX 11887).
    #[serde(default)]
    pub reply_not_kept: bool,
}

/// The serializable form of [`oneiron::runtime_hooks::verb::InvocationRelease`].
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationClaimRelease {
    pub peer: StoredPeerMachine,
    /// JSON bytes of the answer before its first destination release.
    pub value: Vec<u8>,
    #[serde(default)]
    pub rows: Option<Vec<EntityId>>,
}

/// `PeerMachine` deliberately has no serde surface; the claim row owns this
/// stable manual encoding instead of widening authority's wire types.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredPeerMachine {
    Unknown,
    Proven { machine: EntityId, key: [u8; 32] },
}

impl From<PeerMachine> for StoredPeerMachine {
    fn from(peer: PeerMachine) -> Self {
        match peer {
            PeerMachine::Unknown => Self::Unknown,
            PeerMachine::Proven { machine, key } => Self::Proven { machine, key },
        }
    }
}

impl From<StoredPeerMachine> for PeerMachine {
    fn from(peer: StoredPeerMachine) -> Self {
        match peer {
            StoredPeerMachine::Unknown => Self::Unknown,
            StoredPeerMachine::Proven { machine, key } => Self::Proven { machine, key },
        }
    }
}

impl InvocationClaimEntry {
    /// The entry a raw row holds.
    ///
    /// # Errors
    ///
    /// A row that does not decode exactly once with no trailing bytes.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(raw);
        let entry = rmp_serde::decode::from_read(&mut cursor)
            .map_err(|_| Error::CorruptedIndex("invocation claim entry"))?;
        if cursor.position() != raw.len() as u64 {
            return Err(Error::CorruptedIndex("invocation claim entry"));
        }
        Ok(entry)
    }

    /// The row this entry is kept as.
    ///
    /// # Errors
    ///
    /// An entry that does not encode.
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|_| Error::CorruptedIndex("invocation claim entry"))
    }

    /// Whether no outcome settled and no erase took this claim.
    #[must_use]
    pub fn is_open_intent(&self) -> bool {
        self.status == IdempotencyEntry::INTENT_STATUS && !self.erased
    }

    /// Every actor whose erase must scrub this row: its caller, subject,
    /// sources and every row its release named.
    pub(crate) fn owners(&self) -> Vec<EntityId> {
        let mut owners = self.stamps.ids();
        owners.extend(
            self.release
                .iter()
                .flat_map(|release| release.rows.iter().flatten()),
        );
        owners.sort_unstable();
        owners.dedup();
        owners
    }

    /// The content-free row an owner's erase leaves, still expiring from
    /// its original creation time.
    pub(crate) fn erased_form(&self) -> Self {
        Self {
            created_at_secs: self.created_at_secs,
            status: self.status,
            stamps: self.stamps.clone(),
            erased: true,
            ..Self::default()
        }
    }

    /// The terminal outcome an expired open intent takes. Its fresh timestamp
    /// gives the truthful 409 its own TTL; it never becomes a cache miss that
    /// would run the call again.
    pub(crate) fn reclaimed_form(&self, now_secs: u64) -> Self {
        Self {
            created_at_secs: now_secs,
            request_body: self.request_body.clone(),
            status: 409,
            stamps: self.stamps.clone(),
            committed_writes: self.committed_writes,
            reply_not_kept: true,
            ..Self::default()
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
