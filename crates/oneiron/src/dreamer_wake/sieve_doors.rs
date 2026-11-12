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

#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_wake::sieve_doors::{
    SieveLeaseCounter, SieveLeaseRefillRequest, SieveLeaseRequest, SieveLeaseView,
    SievePageRequest, SievePolicyRequest, SievePolicySetRequest, SieveQueuePage, SieveReceiptView,
    SieveReceiptsPage, SieveRecipePolicySetRequest, SieveRetainedPage, SieveSpanView,
};

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
        entity: span.entity.map(|id| bytes_to_hex_lower(id.as_bytes())),
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
