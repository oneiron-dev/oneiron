//! The Coach's Issues work from both of its sources (OF-418 L3; ARCH-0066 §4, §6). A blocked
//! report waits in its own table, as before. A positive model finding, a T2a, T2b, T3 or
//! session DIAGNOSTIC, files a [`DiagnosticIssue`] in the write that emits it, whether or not
//! failure-signal export is on, and wakes the Coach's Issues job in that same write; the host
//! marks its window graded only after it. The row keeps the finding's exact source: its ordered
//! runs and their replay hashes, the decision receipts that raised it, the gate decisions its
//! results link, the producer its recorded links prove, if any, and the recipe it ran under.
//! The row is never rewritten when the Coach files it: an issue waits while no settled marker
//! names it. An owner's answer to its proposal is appended as evidence, read from the claim's
//! closed gate row, never from the answer's hook alone. A finding is also a judgment of its
//! window, appended to the open issues of its recurrence key, and one after a repair took
//! effect files as a recurrence of the issue it follows (`issue_evidence`). Nothing here
//! applies anything.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::blocked_reports::{self, BlockedIssue};
use super::issue_evidence::{self, WindowJudgment};
use super::tiered::{DetectorPolicy, FindingBasis, ProposedTier};
use super::{DiagnosticEvent, DiagnosticReplayCoordinate};
use crate::batch::EntityMetadataHeader;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::dreamer_runner::maintenance::coach_diagnostic::{
    COACH_ISSUE_RESOLUTION_PREDICATE, EffectProof, ProducerLinks, ProducerTarget, bind_producer,
};
use crate::limit_ask::EngineLimit;
use crate::llm::decision::DecisionReceipt;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, Named, SideTable};
use crate::store::RetrievalRunRecord;
use crate::{EntityId, Error, Result, Vault};

/// Every model finding's issue, kept after the Coach files it. Key: the issue.
pub(super) const ISSUES: SideTable<EntityId, DiagnosticIssue, Named> =
    SideTable::new(&side_table::COACH_DIAGNOSTIC_ISSUE);
/// What was observed of an issue, append-only. Key: the issue, then the fact's digest.
pub(super) const EVIDENCE: SideTable<(EntityId, [u8; 32]), IssueFact, Named> =
    SideTable::new(&side_table::COACH_ISSUE_EVIDENCE);

/// A closed gate row's outcome for an approved tray answer, as the gate bundle writes it.
const OUTCOME_APPROVED: &str = "approved";
/// A closed gate row's outcome for a declined tray answer, as the gate bundle writes it.
const OUTCOME_REJECTED: &str = "rejected";

/// One run of a finding's window as it was graded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WindowRun {
    /// The retrieval run's id.
    pub(crate) run: [u8; 16],
    /// blake3 of the run's whole record as the detector graded it.
    pub(crate) replay: [u8; 32],
}

/// The Coach's issue for one positive model finding (OF-418 L3): its exact source, kept whole.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DiagnosticIssue {
    /// The finding's DIAGNOSTIC.
    pub(crate) diagnostic: EntityId,
    /// The tier's token: `t2a`, `t2b`, `t3` or `session_judge`.
    pub(crate) tier: String,
    /// The detector's family.
    pub(crate) family: String,
    /// The detector's event class.
    pub(crate) class: String,
    /// The recipe it ran under.
    pub(crate) recipe_revision: [u8; 32],
    /// What it read, as [`FindingBasis::source_pins`].
    pub(crate) source_pins: Vec<String>,
    /// The exact states its questions read, as [`FindingBasis::context_digest`].
    pub(crate) context_digest: [u8; 32],
    /// The runs it names, oldest first, each with its replay hash.
    pub(crate) windows: Vec<WindowRun>,
    /// The finding's replay coordinate: its content hash.
    pub(crate) coordinate: [u8; 32],
    /// The finding's replay coordinate: its run.
    pub(crate) run_ref: Option<String>,
    /// The receipts of the decisions that raised it; none for the centroid rung.
    pub(crate) decisions: Vec<DecisionReceipt>,
    /// The gate decisions its results link, by id: the exact rows of every claim a run of its
    /// window returned. Empty when it links none; never made up.
    pub(crate) gate_decisions: Vec<[u8; 16]>,
    /// The producer its recorded links prove; `Unknown` when they prove none.
    pub(crate) producer: ProducerTarget,
    /// Its key under [`IssueCoalescingPolicy::recurrence_key`].
    pub(crate) recurrence_key: [u8; 32],
    /// The resolved issue this one is a recurrence of. None until resolution reads it.
    pub(crate) recurrence_of: Option<EntityId>,
    /// When it was filed.
    pub(crate) raised_at: u64,
    /// Issues runs whose decision failed on it.
    pub(crate) retries: u8,
}

/// One fact observed of an issue, appended once (OF-418 L3). An issue's resolution is folded
/// from these, never kept as a flag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum IssueFact {
    /// An owner's closed answer to a proposal the Coach filed for the issue, its repair or a
    /// resolution, as its gate row records it.
    OwnerReview {
        /// The answered proposal.
        proposal: EntityId,
        /// The closed gate row's decision id.
        decision: [u8; 16],
        /// Approved, or declined.
        approved: bool,
        /// When the answer was recorded.
        at: u64,
    },
    /// A complete judgment of a window under the issue's recurrence key, clean or not.
    Judgment(Box<WindowJudgment>),
    /// The issue's producer proved in force at a revision other than the issue's base.
    RepairEffective {
        /// The revision, as [`ProducerTarget::base_revision`] spells it.
        revision: String,
        /// The first second a record stamps it in force from, if one does.
        from: Option<u64>,
        /// The exact refs that prove it.
        proof: EffectProof,
        /// When an Issues pass first proved it.
        at: u64,
    },
    /// A resolution the Coach proposed for the owner to confirm, and what it cites.
    ResolutionProposed {
        /// The proposed `coach.issue.resolution` claim.
        proposal: EntityId,
        /// The repaired revision it rests on.
        revision: String,
        /// The first second its windows' runs count as fresh from.
        counts_from: u64,
        /// The digests of the judgments it cites.
        windows: Vec<[u8; 32]>,
        /// When it was proposed.
        at: u64,
    },
    /// A positive finding under the same key after `previous` was repaired or resolved,
    /// filed as the issue `next`; appended to both, neither row rewritten.
    Recurrence {
        /// The earlier issue.
        previous: EntityId,
        /// The issue the recurrence filed.
        next: EntityId,
        /// The recurrence's DIAGNOSTIC.
        diagnostic: EntityId,
        /// When it was filed.
        at: u64,
    },
}

/// The one hook that keys a model finding's issue (OF-418 L3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IssueCoalescingPolicy {
    /// One issue per exact finding and recipe: a replay of the same finding under the same
    /// recipe coalesces, and distinct windows or findings never fold into a count. A
    /// recurrence is keyed by the family, the recipe and the proved producer, or by the
    /// finding's exact source coordinate when no producer is proved: two causes are never
    /// guessed to be one.
    ExactFindingRecipe,
}

impl IssueCoalescingPolicy {
    /// The issue a finding files under: `derive("coach.diagnostic.issue.v1", diagnostic,
    /// recipe)`.
    pub(crate) fn issue_id(self, diagnostic: EntityId, recipe: &[u8; 32]) -> Result<EntityId> {
        match self {
            Self::ExactFindingRecipe => crate::codebase::entity_id_from_hash_material(
                b"coach.diagnostic.issue.v1",
                &[diagnostic.as_bytes(), recipe],
            ),
        }
    }

    /// The key two issues recur under: `(family, recipe, proved producer)`, or the exact
    /// source coordinate in place of a producer none proves. A producer is keyed by its
    /// [`ProducerTarget::identity`], whatever its revision.
    pub(crate) fn recurrence_key(
        self,
        vault: &Vault,
        family: &str,
        recipe: &[u8; 32],
        producer: &ProducerTarget,
        coordinate: &DiagnosticReplayCoordinate,
    ) -> Result<[u8; 32]> {
        let mut hash = blake3::Hasher::new();
        match self {
            Self::ExactFindingRecipe => {
                hash.update(b"oneiron.coach.diagnostic.recurrence.v1\0");
            }
        }
        hash.update(&(family.len() as u64).to_be_bytes());
        hash.update(family.as_bytes());
        hash.update(recipe);
        match producer.identity(vault)? {
            Some(identity) => {
                hash.update(b"producer\0");
                hash.update(&(identity.len() as u64).to_be_bytes());
                hash.update(&identity);
            }
            None => {
                hash.update(b"source\0");
                hash.update(&coordinate.content_hash);
                let run = coordinate.run_ref.as_deref().unwrap_or_default();
                hash.update(&(run.len() as u64).to_be_bytes());
                hash.update(run.as_bytes());
            }
        }
        Ok(*hash.finalize().as_bytes())
    }
}

/// One piece of an Issues run's waiting work (OF-418 L3).
pub(crate) enum PendingIssue {
    /// A blocked report, by its receipt.
    BlockedReport {
        receipt: EntityId,
        issue: BlockedIssue,
    },
    /// A model finding's issue, by its id.
    ModelDiagnostic {
        issue_id: EntityId,
        issue: Box<DiagnosticIssue>,
    },
}

/// Where an Issues run's read of its waiting work resumes: the blocked reports, then the model
/// issues, each by key.
#[derive(Clone, Copy, Debug)]
pub(crate) enum IssueCursor {
    /// Blocked reports after this receipt; from the first with none.
    Blocked(Option<EntityId>),
    /// Model issues after this one; from the first with none.
    Diagnostic(Option<EntityId>),
    /// Both read to the end.
    Done,
}

impl IssueCursor {
    /// The start of both reads.
    pub(crate) const START: Self = Self::Blocked(None);
}

/// The next page of waiting work after `cursor`, which it moves on: up to `limit` blocked
/// reports, oldest receipt first, then the model issues still waiting among the next `limit`
/// issue rows. A page, never a cap: the caller reads on until a page comes back empty, which
/// is only at the end of both (FIX 1554).
pub(crate) fn pending_issues(
    vault: &Vault,
    cursor: &mut IssueCursor,
    limit: usize,
) -> Result<Vec<PendingIssue>> {
    loop {
        match *cursor {
            IssueCursor::Blocked(after) => {
                let page = blocked_reports::pending_blocked_issues(vault, after, limit)?;
                let Some((last, _)) = page.last() else {
                    *cursor = IssueCursor::Diagnostic(None);
                    continue;
                };
                *cursor = IssueCursor::Blocked(Some(*last));
                return Ok(page
                    .into_iter()
                    .map(|(receipt, issue)| PendingIssue::BlockedReport { receipt, issue })
                    .collect());
            }
            IssueCursor::Diagnostic(after) => {
                let (page, last) = diagnostic_page(vault, after, limit)?;
                let Some(last) = last else {
                    *cursor = IssueCursor::Done;
                    return Ok(Vec::new());
                };
                *cursor = IssueCursor::Diagnostic(Some(last));
                if !page.is_empty() {
                    return Ok(page);
                }
            }
            IssueCursor::Done => return Ok(Vec::new()),
        }
    }
}

/// The issue rows after `after`, up to `limit` of them in one snapshot, as the ones still
/// waiting and the last key read.
fn diagnostic_page(
    vault: &Vault,
    after: Option<EntityId>,
    limit: usize,
) -> Result<(Vec<PendingIssue>, Option<EntityId>)> {
    let txn = vault.store.env.read_txn()?;
    let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let mut waiting = Vec::new();
    let mut last = None;
    for row in ISSUES
        .iter_range(&vault.store, &txn, start, Bound::Unbounded)?
        .take(limit.max(1))
    {
        let (issue_id, issue) = row?;
        last = Some(issue_id);
        if blocked_reports::settled_in_txn(vault, &txn, &issue_id)?.is_none() {
            waiting.push(PendingIssue::ModelDiagnostic {
                issue_id,
                issue: Box::new(issue),
            });
        }
    }
    Ok((waiting, last))
}

/// Whether any blocked report or model issue waits for the Coach.
pub(crate) fn any_pending_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    if blocked_reports::any_pending_in_txn(vault, txn)? {
        return Ok(true);
    }
    for issue_id in ISSUES.scan_keys(&vault.store, txn, &[])? {
        if blocked_reports::settled_in_txn(vault, txn, &issue_id)?.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One model finding's issue by its id, at `txn`'s revision, filed or not.
pub(crate) fn issue_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issue_id: &EntityId,
) -> Result<Option<DiagnosticIssue>> {
    ISSUES.get(&vault.store, txn, issue_id)
}

/// One more failed decision on a waiting model issue; returns the new count.
pub(crate) fn defer_diagnostic_issue(vault: &Vault, issue_id: &EntityId) -> Result<u8> {
    vault.with_write_txn_grouped(|txn| {
        let Some(mut issue) = ISSUES.get(&vault.store, &*txn, issue_id)? else {
            return Ok(0);
        };
        issue.retries = issue.retries.saturating_add(1);
        ISSUES.put(&vault.store, txn, issue_id, &issue)?;
        Ok(issue.retries)
    })
}

/// Counts an owner's answer to a proposal the Coach filed for a model issue as the issue's
/// review (ARCH-0066 #oversight), in the transaction that answers it, and appends what the
/// answer was: approved or declined, with the decision id, read from the claim's CLOSED gate
/// row. The hook firing proves no answer: with no closed row, none is appended. A claim whose
/// issue the Coach settled under another proposal counts nothing. An answer to a resolution
/// the Coach proposed (OF-418 L3) is appended the same way and counts no second review: the
/// repair's stands for both.
pub(crate) fn record_issue_owner_review_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    claim: EntityId,
    body: &crate::claim::ClaimBody,
    proposed_at: u64,
    now: u64,
) -> Result<()> {
    let Some(key) = body
        .value
        .as_str()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .and_then(|value| value.get("issue")?.as_str().map(str::to_owned))
    else {
        return Ok(());
    };
    let Ok(issue_id) = EntityId::from_hex(&key) else {
        return Ok(());
    };
    if !ISSUES.contains(&vault.store, &*txn, &issue_id)? {
        return Ok(());
    }
    let resolution = body.predicate == COACH_ISSUE_RESOLUTION_PREDICATE;
    let proposed = if resolution {
        issue_evidence::resolution_proposed_in_txn(vault, &*txn, issue_id, claim)?
    } else {
        blocked_reports::settled_in_txn(vault, &*txn, &issue_id)?
            .is_some_and(|settled| settled.proposal == claim)
    };
    if !proposed {
        return Ok(());
    }
    let closed = vault
        .store
        .gate_decisions_for_claim_in_txn(&*txn, claim.as_bytes())?
        .into_iter()
        .filter_map(|record| {
            let approved = match record.outcome.as_str() {
                OUTCOME_APPROVED => true,
                OUTCOME_REJECTED => false,
                _ => return None,
            };
            Some((record, approved))
        })
        .max_by_key(|(record, _)| (record.created_at, record.decision_id.as_bytes()));
    if let Some((record, approved)) = closed {
        let fact = IssueFact::OwnerReview {
            proposal: claim,
            decision: record.decision_id.as_bytes(),
            approved,
            at: now,
        };
        append_fact_in_txn(vault, txn, issue_id, &fact)?;
    }
    if resolution {
        return Ok(());
    }
    crate::failure_ladder::oversight::reviewed_in_txn(
        vault,
        txn,
        &issue_id.to_hex(),
        proposed_at,
        now,
        true,
    )
}

/// Appends `fact` to `issue`'s evidence once, keyed by its digest.
pub(crate) fn append_fact_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    issue: EntityId,
    fact: &IssueFact,
) -> Result<()> {
    let bytes = rmp_serde::to_vec_named(fact)
        .map_err(|_| Error::InvariantViolation("issue evidence encode"))?;
    let key = (issue, *blake3::hash(&bytes).as_bytes());
    if !EVIDENCE.contains(&vault.store, &*txn, &key)? {
        EVIDENCE.put(&vault.store, txn, &key, fact)?;
    }
    Ok(())
}

/// The gate decisions a finding's results link (OF-418 L3): the exact rows of every claim a
/// run of its window returned, by decision id, each once. A result that is no claim links
/// none; a claim whose rows do not read links none and is not a refusal.
fn linked_gate_decisions(vault: &Vault, runs: &[RetrievalRunRecord]) -> Result<Vec<[u8; 16]>> {
    let txn = vault.store.env.read_txn()?;
    let results: BTreeSet<[u8; 16]> = runs
        .iter()
        .flat_map(|run| run.result_ids.iter().copied())
        .collect();
    let mut decisions = BTreeSet::new();
    for result in &results {
        let Ok(id) = EntityId::from_bytes(*result) else {
            continue;
        };
        let Ok(Some(raw)) = EntityStoreRead::port_entity_raw(&vault.store, &txn, &id) else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_CLAIM)
        {
            continue;
        }
        let Ok(records) = vault.store.gate_decisions_for_claim_in_txn(&txn, result) else {
            continue;
        };
        decisions.extend(records.iter().map(|record| record.decision_id.as_bytes()));
    }
    // Every result is read: past its threshold row the read asks and reads on.
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, results.len() as u64);
    Ok(decisions.into_iter().collect())
}

/// One positive model finding as its producer files it (OF-418 L3).
pub(super) struct ModelFinding<'a> {
    pub(super) id: EntityId,
    pub(super) event: &'a DiagnosticEvent,
    pub(super) tier: ProposedTier,
    pub(super) policy: &'a DetectorPolicy,
    pub(super) runs: &'a [RetrievalRunRecord],
    pub(super) decisions: &'a [DecisionReceipt],
    pub(super) basis: FindingBasis,
}

impl Vault {
    /// Emits a positive model finding and files its Coach issue in one write, with the wake of
    /// the Coach's Issues job (OF-418 L3), whether or not failure-signal export is on. The
    /// issue is keyed under [`IssueCoalescingPolicy::ExactFindingRecipe`], so a replay of the
    /// same finding and recipe files nothing new; an error leaves the window to the next pass.
    /// In the same write the finding is a positive judgment of its window for the open issues
    /// of its recurrence key, and, after an earlier issue's repair took effect, a recurrence of
    /// it: the new row names it, and both carry the fact.
    pub(super) fn file_model_diagnostic(&self, finding: ModelFinding<'_>) -> Result<()> {
        let ModelFinding {
            id,
            event,
            tier,
            policy,
            runs,
            decisions,
            basis,
        } = finding;
        let policy_hook = IssueCoalescingPolicy::ExactFindingRecipe;
        let issue_id = policy_hook.issue_id(id, &basis.recipe_revision)?;
        let (observed, _) = issue_evidence::observed_window(runs)?;
        let windows = observed
            .iter()
            .map(|run| WindowRun {
                run: run.run,
                replay: run.replay,
            })
            .collect();
        let gate_decisions = linked_gate_decisions(self, runs)?;
        // A retrieval window records no link to an attempt or a manifest.
        let links = ProducerLinks {
            attempts: Vec::new(),
            manifests: Vec::new(),
        };
        let producer = bind_producer(self, runs, &links)?;
        let recurrence_key = policy_hook.recurrence_key(
            self,
            &policy.family,
            &basis.recipe_revision,
            &producer,
            &event.replay,
        )?;
        let now = self.now_recorded_at();
        let judgment = WindowJudgment {
            positive: true,
            tier: tier.token().to_owned(),
            recipe_revision: basis.recipe_revision,
            recurrence_key,
            producer: producer.clone(),
            runs: observed,
            decisions: decisions.to_vec(),
            diagnostic: Some(id),
            at: now,
        };
        let issue = DiagnosticIssue {
            diagnostic: id,
            tier: tier.token().to_owned(),
            family: policy.family.clone(),
            class: policy.class.as_str().to_owned(),
            recipe_revision: basis.recipe_revision,
            source_pins: basis.source_pins,
            context_digest: basis.context_digest,
            windows,
            coordinate: event.replay.content_hash,
            run_ref: event.replay.run_ref.clone(),
            decisions: decisions.to_vec(),
            gate_decisions,
            producer,
            recurrence_key,
            recurrence_of: None,
            raised_at: now,
            retries: 0,
        };
        // The row goes whole: past its threshold row the filing asks and reads on.
        let items = issue.windows.len() + issue.gate_decisions.len() + issue.decisions.len();
        let _ = self.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
        self.with_write_txn_grouped(|txn| {
            self.emit_diagnostic_event_in_txn(txn, &id, event)?;
            if ISSUES.contains(&self.store, &*txn, &issue_id)? {
                return Ok(());
            }
            let recurrence_of = issue_evidence::recurrence_of_in_txn(self, &*txn, &judgment)?;
            let issue = DiagnosticIssue {
                recurrence_of,
                ..issue
            };
            ISSUES.put(&self.store, txn, &issue_id, &issue)?;
            if let Some(previous) = recurrence_of {
                let fact = IssueFact::Recurrence {
                    previous,
                    next: issue_id,
                    diagnostic: id,
                    at: now,
                };
                append_fact_in_txn(self, txn, previous, &fact)?;
                append_fact_in_txn(self, txn, issue_id, &fact)?;
            }
            issue_evidence::observe_in_txn(self, txn, &judgment)?;
            DreamerRunnerStore::new(self).enqueue_coach_issues_in_txn(txn, None, None, now)
        })?;
        self.store.notify_attempt_observers();
        Ok(())
    }
}
