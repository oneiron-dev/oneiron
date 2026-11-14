//! Moved from `crates/oneiron/src/store/invocation_claims.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::sync_responses::IdempotencyEntry;
use crate::store::sync_responses::ResponseStamps;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::machine_destination::PeerMachine;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
    pub fn owners(&self) -> Vec<EntityId> {
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
    pub fn erased_form(&self) -> Self {
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
    pub fn reclaimed_form(&self, now_secs: u64) -> Self {
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
