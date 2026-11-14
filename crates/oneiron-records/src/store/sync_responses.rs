//! Moved from `crates/oneiron/src/store/sync_responses.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Who owns a host row's response, as the host stamps it in the write that
/// keeps the row: the actor that asked, the subject the response is about,
/// and the rows it was made from. A payer is never one. Each is absent when
/// the host could not name it, and the row is kept all the same.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseStamps {
    #[serde(default)]
    pub actor: Option<EntityId>,
    #[serde(default)]
    pub subject: Option<EntityId>,
    #[serde(default)]
    pub sources: Vec<EntityId>,
}

impl ResponseStamps {
    /// Every owner the stamps name, each once.
    pub fn ids(&self) -> Vec<EntityId> {
        let mut ids: Vec<EntityId> = self
            .actor
            .iter()
            .chain(self.subject.iter())
            .chain(self.sources.iter())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

/// One HTTP idempotency cache entry (`sync_state /
/// http:idempotency:<hex-principal>:<hex-key>`), in the compact encoding the
/// host keeps it in.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyEntry {
    pub created_at_secs: u64,
    /// The BLAKE3 digest of the request body this entry answers (ABC
    /// transport row T5): a retry under the key is the same request when its
    /// body has the same digest. The body itself is never kept.
    pub request_digest: Vec<u8>,
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub response_body: Vec<u8>,
    /// The method and request target this entry answers.
    #[serde(default)]
    pub request_target: Option<String>,
    /// The rows the response was derived from, as hex ids.
    #[serde(default)]
    pub served_rows: Vec<String>,
    /// The rows a replay re-admits, as hex ids.
    #[serde(default)]
    pub replay_admits: Option<Vec<String>>,
    /// Who owns the response beside those rows: its caller, when the
    /// request's credential names one (KS-2B2).
    #[serde(default)]
    pub stamps: ResponseStamps,
    /// An erase of an owner took the request and the response: the entry
    /// answers "response erased" until it expires (KS-2B2).
    #[serde(default)]
    pub erased: bool,
    /// The writes committed while this entry stood as its request's intent,
    /// on the threads that served the request, each counted in the write's
    /// own transaction (FIX 10379): an intent that counts any says they
    /// landed though its reply was never kept. Zero for any other entry.
    #[serde(default)]
    pub committed_writes: u32,
    /// The erase of its stamped caller drops the entry rather than leaving
    /// its erased form: a self-hosted non-core keyed route's verified
    /// individual caller's, as the host marks it (FIX 7357). Any other
    /// owner's erase leaves the erased form, as for every entry. Kept last
    /// and written only when set: the compact encoding is positional, so a
    /// field it skips must have none after it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub erase_drops: bool,
}

impl IdempotencyEntry {
    /// The entry a raw row holds.
    ///
    /// # Errors
    ///
    /// A row that does not decode.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("http idempotency entry"))
    }

    /// The row this entry is kept as.
    ///
    /// # Errors
    ///
    /// An entry that does not encode.
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|_| Error::CorruptedIndex("http idempotency entry"))
    }

    /// Who owns the response: the stamped caller, and the rows it served
    /// and re-admits. An id that does not parse names no one.
    fn owners(&self) -> Vec<EntityId> {
        let mut owners = self.stamps.ids();
        owners.extend(
            self.served_rows
                .iter()
                .chain(self.replay_admits.iter().flatten())
                .filter_map(|hex| EntityId::from_hex(hex).ok()),
        );
        owners.sort_unstable();
        owners.dedup();
        owners
    }

    /// Whether the erase of `owner` drops this entry rather than leaving
    /// its erased form: `owner` is the caller it is stamped with, and the
    /// host marked it [`Self::erase_drops`] (FIX 7357).
    fn dropped_by(&self, owner: &EntityId) -> bool {
        self.erase_drops && self.stamps.actor.as_ref() == Some(owner)
    }

    /// The entry an erase leaves: its time, so it still expires; its
    /// status and stamps; nothing of the request, its target or headers,
    /// or the response.
    fn erased_form(&self) -> Self {
        Self {
            created_at_secs: self.created_at_secs,
            status: self.status,
            stamps: self.stamps.clone(),
            erased: true,
            ..Self::default()
        }
    }
}
