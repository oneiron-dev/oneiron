//! Moved from `crates/oneiron/src/dreamer_wake/sieve_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::sieve::policy::SievePolicy;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_wake_contract::dreamer_wake::recipes::WakeRecipePolicy;
use oneiron_wake_contract::dreamer_wake::sieve::SieveSpan;
use oneiron_wake_contract::dreamer_wake::sieve::SpanBand;
use oneiron_wake_contract::dreamer_wake::sieve::SpanKind;
use serde::Deserialize;
use serde::Serialize;

/// One page of the interest queue, its retained readings or its receipts.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SievePageRequest {
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One queued or retained span, by its durable handle and source ref.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveSpanView {
    /// The span's durably ordered handle, in lowercase hex.
    pub span: String,
    pub turn: String,
    pub source: String,
    pub start: u64,
    pub end: u64,
    pub kind: String,
    pub entity: Option<String>,
    pub novel: Option<bool>,
    pub confidence: u8,
    pub score: u32,
    pub band: String,
    /// The model rungs the span still owes: novelty and typing.
    pub owed: Vec<String>,
    pub queued_at: u64,
    pub source_digest: String,
    pub policy_digest: String,
}

/// The interest queue's first page, highest score first. Priority orders
/// the page; it never drops a span, so a span past the page stays queued.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveQueuePage {
    pub spans: Vec<SieveSpanView>,
    /// Queued spans passed over because the Dreamer may not read them now.
    pub skipped_unreadable: u64,
    /// Queued spans passed over because their source left its turn.
    pub skipped_detached: u64,
}

/// The retained original span readings. Spending keeps every reading, so a
/// later weave reads retained evidence, not only generated prose.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveRetainedPage {
    pub spans: Vec<SieveSpanView>,
}

/// One span nightly spending consumed, with the attempt that spent it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveReceiptView {
    pub span: String,
    pub turn: String,
    pub source: String,
    pub start: u64,
    pub end: u64,
    pub kind: String,
    pub score: u32,
    pub attempt: String,
    pub consumed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveReceiptsPage {
    pub receipts: Vec<SieveReceiptView>,
}

/// An empty request: the vault's one sieve or recipe policy row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SievePolicyRequest {}

/// The owner's replacement sieve policy row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SievePolicySetRequest {
    pub policy: SievePolicy,
}

/// The owner's replacement wake recipe policy row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SieveRecipePolicySetRequest {
    pub policy: WakeRecipePolicy,
}

/// One wake-budget lease counter, by the id its wake driver spends under.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SieveLeaseRequest {
    pub budget_id: String,
}

/// A replacement lease total, not an increment: replay adds nothing twice.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SieveLeaseRefillRequest {
    pub budget_id: String,
    pub total_units: u64,
}

/// `counter: None` means no wake has opened this lease on this vault yet.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveLeaseView {
    pub budget_id: String,
    pub counter: Option<SieveLeaseCounter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SieveLeaseCounter {
    pub total_units: u64,
    pub remaining_units: u64,
    pub reserved_units: u64,
    pub updated_at: u64,
}
