//! TASK-lane receipt pump: capture once, route, then resume both idempotent projections.

use super::codec::validate_evidence;
use super::manifest_entry_names_skill;
use super::projector::record_evidence_in_txn;
use super::{
    AttemptOutcome, AttributionDecisions, FollowedState, OutcomeEvidence, attribution_judgments,
    read_attribution_cursor, run_attribution_projector_with_decisions,
};
use crate::receipt::{ReceiptRecord, attempt_pack_receipt_page};
use crate::side_table::{self, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Resume cursor for the in-progress task-attribution receipt-page scan. Key: ().
const SCAN_CURSOR: SideTable<(), String, side_table::Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_SWEEP_SCAN_CURSOR);

/// Highest judgment sequence the sweep has already applied. Key: ().
const APPLIED_CURSOR: SideTable<(), u64, side_table::Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_SWEEP_APPLIED_CURSOR);

/// Idempotency marker recording that a receipt's attribution evidence has
/// already been captured. Key: receipt id text.
const CAPTURED: SideTable<String, [u8; 1], side_table::Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_SWEEP_RECEIPT_CAPTURED);

/// Receipts one read of the receipt pager takes (FIX 10109): the pager's own
/// page bound. It only paces the scan; a pass reads page after page until it
/// has read the receipts it was asked for or the ledger ends.
const RECEIPT_PAGE_CHUNK: usize = 1024;

/// Facts that a receipt does not carry. Hosts must resolve real actor/skill IDs;
/// neither a lease-owner string nor listing a tier-1 skill proves contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAttributionFacts {
    pub actor: EntityId,
    pub skill: Option<EntityId>,
    pub followed_state: FollowedState,
    pub skill_covered_step: bool,
}

pub trait ReceiptAttributionSource {
    /// `None` means facts are not yet available, not an abstention to spend forever.
    fn facts(&self, receipt: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>>;

    /// A terminal self-report is not an anchor. Return a later held-out,
    /// owner, world or audit receipt only when that observation has settled.
    /// Receipts are revisited, so a late outcome need not arrive at capture.
    fn anchored_outcome(
        &self,
        _receipt: &ReceiptRecord,
    ) -> Result<Option<super::AnchoredPackOutcome>> {
        Ok(None)
    }
}

#[derive(Debug, Default)]
pub struct AttributionSweepReport {
    pub scanned: usize,
    pub captured_evidence: usize,
    pub judgments: usize,
    pub skills: Vec<EntityId>,
    pub actor_claims: Vec<EntityId>,
    pub deferred: Vec<String>,
    pub failures: Vec<(String, Error)>,
}

/// One pass over up to `limit` receipts, read a page at a time. The rule tier
/// stays the default; fact resolution is a host seam because
/// execution/coverage facts cannot be invented from a failure.
pub fn run_task_attribution_sweep(
    vault: &Vault,
    limit: usize,
    source: &dyn ReceiptAttributionSource,
) -> Result<AttributionSweepReport> {
    run_task_attribution_sweep_with_decisions(vault, limit, source, None)
}

/// [`run_task_attribution_sweep`] through the host's decisions; `None` is the
/// rule tier.
pub fn run_task_attribution_sweep_with_decisions(
    vault: &Vault,
    limit: usize,
    source: &dyn ReceiptAttributionSource,
    decisions: Option<&AttributionDecisions<'_>>,
) -> Result<AttributionSweepReport> {
    let after = {
        let txn = vault.store.env.read_txn()?;
        SCAN_CURSOR.get(&vault.store, &txn, &())?
    };
    let page_limit = {
        let txn = vault.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
        let budget = policy
            .attribution_limits()
            .ok_or_else(|| {
                Error::InvalidConfig("attribution work budget policy is malformed".to_owned())
            })?
            .receipts_per_pass;
        limit.min(usize::try_from(budget).unwrap_or(usize::MAX))
    };
    let (receipts, complete) = receipt_pages(vault, after.as_deref(), page_limit)?;
    let mut report = AttributionSweepReport {
        scanned: receipts.len(),
        ..Default::default()
    };
    for receipt in &receipts {
        let outcome = match receipt.outcome.as_str() {
            "completed" => AttemptOutcome::Succeeded,
            "failed" => AttemptOutcome::Failed,
            _ => continue, // cancellation and abandonment are not evidence of blame
        };
        match capture_receipt(vault, receipt, outcome, source) {
            Ok(Some(count)) => report.captured_evidence += count,
            Ok(None) => report.deferred.push(receipt.receipt_id.clone()),
            Err(error) => report.failures.push((receipt.receipt_id.clone(), error)),
        }
    }
    // A crash before this cursor repeats captures safely. A full pass wraps, so
    // late terminal receipts and temporarily unknown facts are retried as well.
    vault.with_write_txn_grouped(|txn| {
        if complete {
            SCAN_CURSOR.delete(&vault.store, txn, &())?;
        } else if let Some(last) = receipts.last() {
            SCAN_CURSOR.put(&vault.store, txn, &(), &last.receipt_id)?;
        }
        Ok(())
    })?;
    let applied = {
        let txn = vault.store.env.read_txn()?;
        APPLIED_CURSOR.get(&vault.store, &txn, &())?.unwrap_or(0)
    };
    run_attribution_projector_with_decisions(vault, read_attribution_cursor(vault)?, decisions)?;
    let routed = read_attribution_cursor(vault)?;
    let judgments: Vec<_> = attribution_judgments(vault)?
        .into_iter()
        .filter(|row| row.sequence > applied && row.sequence <= routed)
        .collect();
    report.judgments = judgments.len();
    report.actor_claims =
        crate::actor_claims::project_actor_claims_from_judgments(vault, &judgments)?;
    for receipt in &receipts {
        let outcome = match source.anchored_outcome(receipt) {
            Ok(Some(outcome)) => outcome,
            Ok(None) => continue,
            Err(error) => {
                report.failures.push((receipt.receipt_id.clone(), error));
                continue;
            }
        };
        match super::project_anchored_pack_outcome(
            vault,
            &receipt.receipt_id,
            &outcome,
            crate::unix_seconds_now(),
        ) {
            Ok(credit) => {
                for subject in credit
                    .direct_subjects
                    .iter()
                    .chain(credit.shares.iter().map(|share| &share.subject))
                    .flatten()
                {
                    if vault.get_raw(subject)?.and_then(|raw| {
                        crate::batch::EntityMetadataHeader::parse(&raw)
                            .map(|header| header.entity_type)
                    }) == Some(crate::registry::ENTITY_TYPE_SKILL)
                        && !report.skills.contains(subject)
                    {
                        report.skills.push(*subject);
                    }
                }
            }
            Err(error) => report.failures.push((receipt.receipt_id.clone(), error)),
        }
    }
    // Separate from routing: an interrupted projector must be retried from durable
    // judgments, not silently skipped merely because the judge advanced its cursor.
    vault.with_write_txn_grouped(|txn| {
        let held = APPLIED_CURSOR.get(&vault.store, txn, &())?.unwrap_or(0);
        APPLIED_CURSOR.put(&vault.store, txn, &(), &held.max(routed))?;
        Ok(())
    })?;
    Ok(report)
}

/// Up to `limit` receipts after `after`, read [`RECEIPT_PAGE_CHUNK`] at a time
/// (FIX 10109), and whether the ledger ended before `limit`.
fn receipt_pages(
    vault: &Vault,
    after: Option<&str>,
    limit: usize,
) -> Result<(Vec<ReceiptRecord>, bool)> {
    let mut receipts: Vec<ReceiptRecord> = Vec::new();
    while receipts.len() < limit {
        let cursor = receipts
            .last()
            .map(|receipt| receipt.receipt_id.as_str())
            .or(after);
        let chunk = (limit - receipts.len()).min(RECEIPT_PAGE_CHUNK);
        let (page, complete) = attempt_pack_receipt_page(vault, cursor, chunk)?;
        receipts.extend(page);
        if complete {
            return Ok((receipts, true));
        }
    }
    Ok((receipts, false))
}

fn capture_receipt(
    vault: &Vault,
    receipt: &ReceiptRecord,
    outcome: AttemptOutcome,
    source: &dyn ReceiptAttributionSource,
) -> Result<Option<usize>> {
    {
        let txn = vault.store.env.read_txn()?;
        if CAPTURED.contains(&vault.store, &txn, &receipt.receipt_id)? {
            return Ok(Some(0));
        }
    }
    let Some(facts) = source.facts(receipt)? else {
        return Ok(None);
    };
    // A partial host answer must not mark this receipt captured forever. The
    // terminal manifest is the authority on which tier-2 skills were loaded.
    if let Some(manifest) = receipt.pack_manifest_skills() {
        let loaded: std::collections::BTreeSet<_> = manifest.iter().collect();
        let named = facts
            .iter()
            .map(|fact| {
                let skill = fact.skill.ok_or(Error::InvalidConfig(
                    "attribution fact must name a loaded skill".to_owned(),
                ))?;
                vault.get_skill_record(&skill)?.ok_or(Error::InvalidConfig(
                    "attribution fact names an unknown skill".to_owned(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let named_revisions: std::collections::BTreeSet<_> = named
            .iter()
            .map(|record| (record.skill_id.as_str(), record.version.as_str()))
            .collect();
        if named_revisions.len() != named.len()
            || loaded.len() != named.len()
            || loaded.iter().any(|wire| {
                named
                    .iter()
                    .filter(|record| manifest_entry_names_skill(wire, record))
                    .count()
                    != 1
            })
            || named.iter().any(|record| {
                loaded
                    .iter()
                    .filter(|wire| manifest_entry_names_skill(wire, record))
                    .count()
                    != 1
            })
        {
            return Err(Error::InvalidConfig(
                "attribution facts must cover every loaded skill revision exactly once".to_owned(),
            ));
        }
    }
    let mut unique = std::collections::BTreeSet::new();
    let mut evidence = Vec::new();
    for fact in facts {
        if !unique.insert((fact.actor, fact.skill)) {
            return Err(Error::InvalidConfig(
                "duplicate receipt attribution subject".to_owned(),
            ));
        }
        let mut row = OutcomeEvidence::new(
            &receipt.receipt_id,
            fact.actor,
            outcome,
            receipt.occurred_at,
        )
        .with_followed_state(fact.followed_state);
        row.skill_covered_step = Some(fact.skill_covered_step);
        row.skill = fact.skill;
        validate_evidence(vault, &row)?;
        evidence.push(row);
    }
    vault.with_write_txn_grouped(|txn| {
        if CAPTURED.contains(&vault.store, txn, &receipt.receipt_id)? {
            return Ok(Some(0));
        }
        for row in &evidence {
            record_evidence_in_txn(vault, txn, row)?;
        }
        CAPTURED.put(&vault.store, txn, &receipt.receipt_id, &[1u8])?;
        Ok(Some(evidence.len()))
    })
}
