//! Moved from `crates/oneiron/src/sync/quarantine/keys_classifier.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::sync::quarantine::keys_classifier::QuarantineContainer;
use serde::Deserialize;
use serde::Serialize;

/// A persisted quarantine record. Hash + metadata ONLY — GDPR-inert, never
/// the rejected bytes themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Window key (YYYY-MM) of the doc whose replay rejected the op.
    pub window_key: String,
    /// Which map the op targeted.
    pub container: QuarantineContainer,
    /// `xxh3_64` of the rejected op's CRDT map key bytes. The key itself is
    /// attacker-controlled and is NEVER stored — a crafted key string would
    /// smuggle content into the GDPR-inert `x:` family (and a prefix is
    /// still content). Hash + length only.
    pub crdt_key_hash: u64,
    /// Byte length of the rejected op's CRDT map key.
    pub crdt_key_len: u32,
    /// Typed error name of the rejecting gate (`ErrorKind` name, e.g.
    /// `InvalidEdgeWeight`, `InvalidTimeRange`, `EntityTypeImmutable`).
    pub reason_code: String,
    /// `xxh3_64` of the rejected value bytes (0-length input hashes the
    /// empty slice — e.g. a delete op carrying no payload).
    pub payload_hash: u64,
    /// Unix seconds when the op was quarantined.
    pub quarantined_at: u64,
}
