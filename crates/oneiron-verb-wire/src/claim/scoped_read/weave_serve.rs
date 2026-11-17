//! Moved from `crates/oneiron/src/claim/scoped_read/weave_serve.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeKind;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::write_envelope::provenance::edge_ref::EdgeRef;
use serde::Deserialize;
use serde::Serialize;

/// `vault.weave.digest`'s input: one saved period, or the newest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestRequest {
    /// The period's due Unix second, as its inbox notice names it.
    #[serde(default)]
    pub scheduled_for: Option<u64>,
}

/// `vault.weave.link.wrong`'s input: one link, as the reader's report
/// serves it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveWrongLinkRequest {
    pub source_ref: String,
    pub kind: String,
    pub target_ref: String,
}

impl WeaveWrongLinkRequest {
    pub fn link(&self) -> MemoryResult<EdgeRef> {
        let entity = |hex: &str| {
            EntityId::from_hex(hex)
                .map_err(|_| MemoryError::bad_request("a weave link names entity ids"))
        };
        Ok(EdgeRef::new(
            entity(&self.source_ref)?,
            EdgeKind::from_name(&self.kind)
                .ok_or_else(|| MemoryError::bad_request("unknown weave edge kind"))?,
            entity(&self.target_ref)?,
        ))
    }
}

/// A SieveScore section's score (OF-499): of the sampled sieve audits the
/// section shows, how many agree with the expensive path. It is counted
/// from those items, never kept apart. `sampled: 0` is no samples: no
/// score, never a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WeaveSieveScoreView {
    pub sampled: u64,
    pub agreeing: u64,
    /// How many distinct discoveries the section's window audits found
    /// (FIX 7903): one found again by another audit counts once here, and
    /// each audit still lists its own occurrence.
    pub discoveries: u64,
}

/// Who a schedule is for, on the owner's wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeaveReaderKind {
    Person,
    Owner,
    Agent,
    /// A weave Admin's namespace (OF-499 A3): `reader_ref` is its exact
    /// Admin membership grant. Answer only: an Admin reader comes from its
    /// proof, never from a reader ref.
    Admin,
}
pub mod sieve_audit;
