//! Typed owner doors over the sieve interest queue, its retained spans,
//! its consumed-span receipts, the sieve and recipe policy rows, and the
//! wake-budget lease that pays for spending the queue. No queue logic
//! lives here: reads project the sieve's own rows, policy writes go
//! through the owner-authenticated setters, and a refill only raises a
//! counter's total.

use serde::{Deserialize, Serialize};

use super::{SievePolicy, SieveSpan, SpanBand, SpanKind, WakeRecipePolicy};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::bytes_to_hex_lower;
use crate::{Result, Vault};

const MAX_PAGE: u32 = 1000;

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

fn page_limit(limit: Option<u32>) -> usize {
    usize::try_from(limit.unwrap_or(MAX_PAGE).min(MAX_PAGE)).unwrap_or(usize::MAX)
}

fn span_view(span: &SieveSpan) -> SieveSpanView {
    SieveSpanView {
        span: bytes_to_hex_lower(&span.id),
        turn: bytes_to_hex_lower(span.turn.as_bytes()),
        source: bytes_to_hex_lower(span.source.as_bytes()),
        start: span.start,
        end: span.end,
        kind: match span.kind {
            SpanKind::Date => "date".into(),
            SpanKind::Name => "name".into(),
        },
        entity: span
            .entity
            .map(|id| bytes_to_hex_lower(id.as_bytes())),
        novel: span.novel,
        confidence: span.confidence,
        score: span.score,
        band: match span.band {
            SpanBand::Low => "low".into(),
            SpanBand::Uncertain => "uncertain".into(),
            SpanBand::Sure => "sure".into(),
        },
        owed: span
            .owed
            .iter()
            .map(|rung| match rung {
                super::SieveRung::Novelty => "novelty".to_owned(),
                super::SieveRung::Typing => "typing".to_owned(),
            })
            .collect(),
        queued_at: span.queued_at,
        source_digest: bytes_to_hex_lower(&span.source_digest),
        policy_digest: bytes_to_hex_lower(&span.policy_digest),
    }
}

pub fn sieve_queue_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SievePageRequest,
) -> Result<SieveQueuePage> {
    owner.revalidate(vault)?;
    let queue = vault.sieve_queue(page_limit(input.limit))?;
    Ok(SieveQueuePage {
        spans: queue.spans.iter().map(span_view).collect(),
        skipped_unreadable: queue.skipped.unreadable as u64,
        skipped_detached: queue.skipped.detached as u64,
    })
}

pub fn sieve_retained_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SievePageRequest,
) -> Result<SieveRetainedPage> {
    owner.revalidate(vault)?;
    let spans = vault.sieve_retained(page_limit(input.limit))?;
    Ok(SieveRetainedPage {
        spans: spans.iter().map(span_view).collect(),
    })
}

pub fn sieve_receipts_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SievePageRequest,
) -> Result<SieveReceiptsPage> {
    owner.revalidate(vault)?;
    let receipts = vault.sieve_consumed(page_limit(input.limit))?;
    Ok(SieveReceiptsPage {
        receipts: receipts
            .iter()
            .map(|receipt| SieveReceiptView {
                span: bytes_to_hex_lower(&receipt.span),
                turn: bytes_to_hex_lower(receipt.turn.as_bytes()),
                source: bytes_to_hex_lower(receipt.source.as_bytes()),
                start: receipt.start,
                end: receipt.end,
                kind: match receipt.kind {
                    SpanKind::Date => "date".into(),
                    SpanKind::Name => "name".into(),
                },
                score: receipt.score,
                attempt: bytes_to_hex_lower(receipt.attempt.as_bytes()),
                consumed_at: receipt.at,
            })
            .collect(),
    })
}

pub fn sieve_policy_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &SievePolicyRequest,
) -> Result<SievePolicy> {
    owner.revalidate(vault)?;
    vault.dreamer_sieve_policy()
}

pub fn sieve_policy_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SievePolicySetRequest,
) -> Result<SievePolicy> {
    vault.set_dreamer_sieve_policy(owner, input.policy)?;
    vault.dreamer_sieve_policy()
}

pub fn sieve_recipe_policy_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &SievePolicyRequest,
) -> Result<WakeRecipePolicy> {
    owner.revalidate(vault)?;
    vault.dreamer_recipe_policy()
}

pub fn sieve_recipe_policy_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SieveRecipePolicySetRequest,
) -> Result<WakeRecipePolicy> {
    vault.set_dreamer_recipe_policy(owner, input.policy.clone())?;
    vault.dreamer_recipe_policy()
}

fn lease_view(
    budget_id: &str,
    record: Option<crate::dreamer_runner::DreamerBudgetRecord>,
) -> SieveLeaseView {
    SieveLeaseView {
        budget_id: budget_id.to_owned(),
        counter: record.map(|row| SieveLeaseCounter {
            total_units: row.total_units,
            remaining_units: row.remaining_units,
            reserved_units: row.reserved_units,
            updated_at: row.updated_at,
        }),
    }
}

pub fn sieve_lease_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SieveLeaseRequest,
) -> Result<SieveLeaseView> {
    owner.revalidate(vault)?;
    let record = DreamerRunnerStore::new(vault).budget(&input.budget_id)?;
    Ok(lease_view(&input.budget_id, record))
}

pub fn sieve_lease_refill_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SieveLeaseRefillRequest,
) -> Result<SieveLeaseView> {
    let record = DreamerRunnerStore::new(vault).refill_budget_as_owner(
        owner,
        &input.budget_id,
        input.total_units,
        crate::unix_seconds_now(),
    )?;
    Ok(lease_view(&input.budget_id, Some(record)))
}
