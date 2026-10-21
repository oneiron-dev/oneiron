//! What the Coach observes of its model issues after filing them, and when one resolves
//! (OF-418 L3; ARCH-0066 §6). A detector's complete judgment of a window, clean or not, is
//! appended to each open issue of its recurrence key, and a clean one wakes the Issues job
//! only then. An error, an abstention or a partial window is no judgment, and a centroid miss
//! leaves the verdict to the rung after it. An issue resolves on evidence, never on silence,
//! elapsed time, approval alone or counts: [`IssueResolutionPolicy::FreshCompleteWindow`] asks
//! for complete clean windows of fresh runs after a proved effective revision of the issue's
//! producer, under its recipe and key, with no recurrence, and the Coach then files a proposed
//! `coach.issue.resolution` for the owner to confirm. A finding under the key after a repair
//! took effect files a new issue naming the one it recurs after. Facts are appended, never
//! rewritten, and nothing here applies anything.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::DiagnosticReplayCoordinate;
use super::blocked_reports;
use super::issue_work::{
    DiagnosticIssue, EVIDENCE, ISSUES, IssueCoalescingPolicy, IssueFact, append_fact_in_txn,
};
use super::tiered::{DetectorPolicy, ProposedTier};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::dreamer_runner::maintenance::coach_diagnostic::{
    EffectProof, EffectiveRevision, ProducerLinks, ProducerTarget, bind_producer,
    issue_effective_revision,
};
use crate::limit_ask::EngineLimit;
use crate::llm::decision::DecisionReceipt;
use crate::store::RetrievalRunRecord;
use crate::{EntityId, Error, Result, Vault};

/// Complete clean windows a resolution needs at least (OF-418 L3).
pub(crate) const RESOLUTION_MIN_CLEAN_WINDOWS: usize = 1;

/// One run of an observed window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ObservedRun {
    /// The retrieval run's id.
    pub(crate) run: [u8; 16],
    /// blake3 of its whole record as the detector graded it.
    pub(crate) replay: [u8; 32],
    /// When it started.
    pub(crate) started_at: u64,
}

/// One complete model judgment of a window (OF-418 L3), as an issue's evidence keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct WindowJudgment {
    /// Whether it found the anomaly.
    pub(crate) positive: bool,
    /// The tier's token.
    pub(crate) tier: String,
    /// The recipe it ran under.
    pub(crate) recipe_revision: [u8; 32],
    /// Its key under [`IssueCoalescingPolicy::recurrence_key`].
    pub(crate) recurrence_key: [u8; 32],
    /// The producer the window's runs prove, at the revision they ran under.
    pub(crate) producer: ProducerTarget,
    /// Its runs, oldest first.
    pub(crate) runs: Vec<ObservedRun>,
    /// The receipt of every decision it took.
    pub(crate) decisions: Vec<DecisionReceipt>,
    /// The DIAGNOSTIC a positive judgment emitted.
    pub(crate) diagnostic: Option<EntityId>,
    /// When it was judged.
    pub(crate) at: u64,
}

/// A detector's complete judgment of a window with no finding, as it finishes the window.
pub(super) struct Observation<'a> {
    pub(super) tier: ProposedTier,
    pub(super) policy: &'a DetectorPolicy,
    pub(super) recipe: [u8; 32],
    pub(super) runs: &'a [RetrievalRunRecord],
    pub(super) decisions: &'a [DecisionReceipt],
}

/// The one hook that decides when a model issue may resolve (OF-418 L3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IssueResolutionPolicy {
    /// At least [`RESOLUTION_MIN_CLEAN_WINDOWS`] complete clean windows of fresh runs after a
    /// proved effective revision of the issue's producer, each under the issue's recipe and
    /// recurrence key at that revision, none sharing a run with the issue's own windows, with
    /// another or with a window an earlier resolution cited, and no positive judgment after
    /// the revision. A changed recipe is another key and needs its own baseline.
    FreshCompleteWindow,
}

impl IssueResolutionPolicy {
    /// The complete clean windows a resolution needs at least.
    pub(crate) const fn min_clean_windows(self) -> usize {
        match self {
            Self::FreshCompleteWindow => RESOLUTION_MIN_CLEAN_WINDOWS,
        }
    }

    /// The judgments that support resolving `issue` at `revision`, oldest first, with runs
    /// from `counts_from` on; empty while too few, or when a positive judgment has a run from
    /// `counts_from` on: the finding recurred.
    fn clean_windows<'e>(
        self,
        issue: &DiagnosticIssue,
        evidence: &'e IssueEvidence,
        revision: &str,
        counts_from: u64,
    ) -> Vec<&'e ([u8; 32], WindowJudgment)> {
        let after = |judgment: &WindowJudgment| {
            judgment
                .runs
                .iter()
                .any(|run| run.started_at >= counts_from)
        };
        if evidence
            .judgments
            .iter()
            .any(|(_, judgment)| judgment.positive && after(judgment))
        {
            return Vec::new();
        }
        let mut used: BTreeSet<[u8; 16]> = issue.windows.iter().map(|window| window.run).collect();
        for (_, _, cited) in &evidence.resolutions {
            for (digest, judgment) in &evidence.judgments {
                if cited.contains(digest) {
                    used.extend(judgment.runs.iter().map(|run| run.run));
                }
            }
        }
        let mut candidates: Vec<_> = evidence
            .judgments
            .iter()
            .filter(|(_, judgment)| {
                !judgment.positive
                    && judgment.recipe_revision == issue.recipe_revision
                    && judgment.recurrence_key == issue.recurrence_key
                    && judgment.producer.base_revision().as_deref() == Some(revision)
                    && !judgment.runs.is_empty()
                    && judgment
                        .runs
                        .iter()
                        .all(|run| run.started_at >= counts_from)
            })
            .collect();
        candidates.sort_by_key(|(digest, judgment)| {
            (judgment.runs.first().map(|run| run.started_at), *digest)
        });
        let mut clean = Vec::new();
        for candidate in candidates {
            if candidate.1.runs.iter().any(|run| used.contains(&run.run)) {
                continue;
            }
            used.extend(candidate.1.runs.iter().map(|run| run.run));
            clean.push(candidate);
        }
        if clean.len() < self.min_clean_windows() {
            clean.clear();
        }
        clean
    }
}

/// An issue's evidence, folded in key order (OF-418 L3).
#[derive(Default)]
struct IssueEvidence {
    /// Owner answers: the proposal, approved or not, the decision, when.
    reviews: Vec<(EntityId, bool, [u8; 16], u64)>,
    /// Every judgment, with its fact's digest.
    judgments: Vec<([u8; 32], WindowJudgment)>,
    /// Proved repairs: the revision, its stamp, when a pass first proved it.
    repairs: Vec<(String, Option<u64>, u64)>,
    /// Proposed resolutions: the claim, where its runs counted from, the judgments it cites.
    resolutions: Vec<(EntityId, u64, Vec<[u8; 32]>)>,
    /// Whether a later issue recurs after this one.
    recurred: bool,
}

impl IssueEvidence {
    /// The owner's latest answer to `proposal`: approved or not, and its decision.
    fn review(&self, proposal: EntityId) -> Option<(bool, [u8; 16])> {
        self.reviews
            .iter()
            .filter(|review| review.0 == proposal)
            .max_by_key(|review| (review.3, review.2))
            .map(|review| (review.1, review.2))
    }

    /// Where the runs of a resolution the owner approved counted from, if one was approved.
    fn resolved_from(&self) -> Option<u64> {
        self.resolutions
            .iter()
            .filter(|(proposal, ..)| self.review(*proposal).is_some_and(|(approved, _)| approved))
            .map(|(_, counts_from, _)| *counts_from)
            .min()
    }

    /// Open: no resolution approved, and no later issue recurs after it.
    fn open(&self) -> bool {
        self.resolved_from().is_none() && !self.recurred
    }

    /// When a pass first proved `revision` in force with stamp `from`, if one did.
    fn proved_at(&self, revision: &str, from: Option<u64>) -> Option<u64> {
        self.repairs
            .iter()
            .filter(|(proved, stamp, _)| proved == revision && *stamp == from)
            .map(|(.., at)| *at)
            .min()
    }
}

/// `issue`'s evidence as `txn` reads it.
fn issue_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issue: EntityId,
) -> Result<IssueEvidence> {
    let mut evidence = IssueEvidence::default();
    let mut rows = 0u64;
    for row in EVIDENCE.iter_from(&vault.store, txn, issue.as_bytes())? {
        let ((_, digest), fact) = row?;
        rows += 1;
        match fact {
            IssueFact::OwnerReview {
                proposal,
                decision,
                approved,
                at,
            } => evidence.reviews.push((proposal, approved, decision, at)),
            IssueFact::Judgment(judgment) => evidence.judgments.push((digest, *judgment)),
            IssueFact::RepairEffective {
                revision, from, at, ..
            } => evidence.repairs.push((revision, from, at)),
            IssueFact::ResolutionProposed {
                proposal,
                counts_from,
                windows,
                ..
            } => evidence.resolutions.push((proposal, counts_from, windows)),
            IssueFact::Recurrence { previous, .. } => evidence.recurred |= previous == issue,
        }
    }
    // Every fact is read: past its threshold row the read asks and reads on.
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, rows);
    Ok(evidence)
}

/// Every issue filed under `key`, read whole.
fn same_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Vec<(EntityId, DiagnosticIssue)>> {
    let mut rows = 0u64;
    let mut matched = Vec::new();
    for row in ISSUES.iter_from(&vault.store, txn, &[])? {
        let (issue_id, issue) = row?;
        rows += 1;
        if issue.recurrence_key == *key {
            matched.push((issue_id, issue));
        }
    }
    // Every issue is read: past its threshold row the read asks and reads on.
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, rows);
    Ok(matched)
}

/// `runs` as an observed window, each run with its replay hash, and the window's coordinate as
/// a finding's: the digest of every run's record, length-prefixed, and its newest run.
pub(super) fn observed_window(
    runs: &[RetrievalRunRecord],
) -> Result<(Vec<ObservedRun>, DiagnosticReplayCoordinate)> {
    let mut digest = blake3::Hasher::new();
    let mut observed = Vec::with_capacity(runs.len());
    for run in runs {
        let bytes = rmp_serde::to_vec_named(run)
            .map_err(|_| Error::InvariantViolation("retrieval telemetry encode"))?;
        digest.update(&(bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
        observed.push(ObservedRun {
            run: run.run_id.as_bytes(),
            replay: *blake3::hash(&bytes).as_bytes(),
            started_at: run.started_at,
        });
    }
    let coordinate = DiagnosticReplayCoordinate {
        content_hash: *digest.finalize().as_bytes(),
        run_ref: runs.last().map(|run| run.run_id.to_hex()),
        checkpoint_ref: None,
    };
    Ok((observed, coordinate))
}

/// Whether any issue filed under `key` is open.
fn any_open_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, key: &[u8; 32]) -> Result<bool> {
    for (issue_id, _) in same_key_in_txn(vault, txn, key)? {
        if issue_evidence_in_txn(vault, txn, issue_id)?.open() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Appends `judgment` to every open issue of its recurrence key (OF-418 L3); whether any did.
pub(super) fn observe_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    judgment: &WindowJudgment,
) -> Result<bool> {
    // The judgment goes whole: past its threshold row the write asks and reads on.
    let items = judgment.runs.len() + judgment.decisions.len();
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
    let fact = IssueFact::Judgment(Box::new(judgment.clone()));
    let mut took = false;
    for (issue_id, _) in same_key_in_txn(vault, &*txn, &judgment.recurrence_key)? {
        if issue_evidence_in_txn(vault, &*txn, issue_id)?.open() {
            append_fact_in_txn(vault, txn, issue_id, &fact)?;
            took = true;
        }
    }
    Ok(took)
}

/// An issue's producer proved in force at a revision other than the issue's base (OF-418 L3).
pub(crate) struct ProvedRepair {
    /// The revision in force.
    pub(crate) revision: String,
    /// The first second a record stamps it in force from, if one does.
    pub(crate) from: Option<u64>,
    /// The exact refs that prove it.
    pub(crate) proof: EffectProof,
    /// The first second whose runs count as fresh: from its stamp, else from the second after
    /// the pass that first proved it, and after the issue was raised. `None` while no stamp
    /// and no recorded proof gives one.
    pub(crate) counts_from: Option<u64>,
}

/// `issue`'s proved repair as `txn` reads it: its producer's revision in force, by
/// [`issue_effective_revision`] over the windows its evidence holds, when it is not the base.
fn proved_repair_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issue: &DiagnosticIssue,
    evidence: &IssueEvidence,
) -> Result<Option<ProvedRepair>> {
    let windows: Vec<&WindowJudgment> = evidence
        .judgments
        .iter()
        .map(|(_, judgment)| judgment)
        .collect();
    let EffectiveRevision::InForce {
        revision,
        from,
        proof,
    } = issue_effective_revision(vault, txn, &issue.producer, &windows)?
    else {
        return Ok(None);
    };
    if issue.producer.base_revision().as_deref() == Some(revision.as_str()) {
        return Ok(None);
    }
    let stamped = from.or_else(|| {
        evidence
            .proved_at(&revision, from)
            .map(|at| at.saturating_add(1))
    });
    Ok(Some(ProvedRepair {
        counts_from: stamped.map(|start| start.max(issue.raised_at.saturating_add(1))),
        revision,
        from,
        proof,
    }))
}

/// The issue a new positive judgment recurs after (OF-418 L3): of the issues under its key,
/// the latest raised whose approved resolution or proved repair took effect by the judgment's
/// first run. `None` when none had: a finding before any repair is another finding.
pub(super) fn recurrence_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    judgment: &WindowJudgment,
) -> Result<Option<EntityId>> {
    let Some(first) = judgment.runs.iter().map(|run| run.started_at).min() else {
        return Ok(None);
    };
    let mut latest: Option<(u64, EntityId)> = None;
    for (previous, issue) in same_key_in_txn(vault, txn, &judgment.recurrence_key)? {
        let evidence = issue_evidence_in_txn(vault, txn, previous)?;
        let from = match evidence.resolved_from() {
            Some(from) => Some(from),
            None => proved_repair_in_txn(vault, txn, &issue, &evidence)?
                .and_then(|repair| repair.counts_from),
        };
        if from.is_some_and(|from| first >= from)
            && latest.is_none_or(|best| (issue.raised_at, previous) > best)
        {
            latest = Some((issue.raised_at, previous));
        }
    }
    Ok(latest.map(|(_, previous)| previous))
}

/// Whether `claim` is a resolution the Coach proposed for `issue`.
pub(crate) fn resolution_proposed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issue: EntityId,
    claim: EntityId,
) -> Result<bool> {
    Ok(issue_evidence_in_txn(vault, txn, issue)?
        .resolutions
        .iter()
        .any(|(proposal, ..)| *proposal == claim))
}

/// The issue rows after `after`, up to `limit` of them in one snapshot: a page of the Issues
/// pass's read, never a cap.
pub(crate) fn issue_rows(
    vault: &Vault,
    after: Option<EntityId>,
    limit: usize,
) -> Result<Vec<(EntityId, DiagnosticIssue)>> {
    let txn = vault.store.env.read_txn()?;
    let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    ISSUES
        .iter_range(&vault.store, &txn, start, Bound::Unbounded)?
        .take(limit.max(1))
        .collect()
}

/// What reconciling one model issue would write now (OF-418 L3).
pub(crate) struct Reconcile {
    /// The repair proposal the Coach filed for the issue.
    pub(crate) repair_proposal: EntityId,
    /// The owner's latest answer to it, approved or not, with its decision.
    pub(crate) repair_review: Option<(bool, [u8; 16])>,
    /// The proved repair.
    pub(crate) repair: ProvedRepair,
    /// Whether no pass has recorded that repair yet.
    pub(crate) record_repair: bool,
    /// The first second the windows' runs count as fresh from.
    pub(crate) counts_from: u64,
    /// The judgments a resolution would cite, oldest first; empty while too few.
    pub(crate) windows: Vec<([u8; 32], WindowJudgment)>,
}

/// What the Issues pass would write for `issue` now (OF-418 L3), under
/// [`IssueResolutionPolicy::FreshCompleteWindow`]: `None` while the issue waits for its own
/// filing, is resolved or recurred, has a resolution waiting for the owner, or has no proved
/// repair that is new to record or has the windows to resolve on.
pub(crate) fn reconcile_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issue_id: EntityId,
    issue: &DiagnosticIssue,
    now: u64,
) -> Result<Option<Reconcile>> {
    let Some(settled) = blocked_reports::settled_in_txn(vault, txn, &issue_id)? else {
        return Ok(None);
    };
    let evidence = issue_evidence_in_txn(vault, txn, issue_id)?;
    if !evidence.open()
        || evidence
            .resolutions
            .iter()
            .any(|(proposal, ..)| evidence.review(*proposal).is_none())
    {
        return Ok(None);
    }
    let Some(repair) = proved_repair_in_txn(vault, txn, issue, &evidence)? else {
        return Ok(None);
    };
    let record_repair = evidence.proved_at(&repair.revision, repair.from).is_none();
    // A revision this pass is the first to prove counts from the next second.
    let counts_from = repair
        .counts_from
        .unwrap_or_else(|| now.saturating_add(1).max(issue.raised_at.saturating_add(1)));
    let windows: Vec<_> = IssueResolutionPolicy::FreshCompleteWindow
        .clean_windows(issue, &evidence, &repair.revision, counts_from)
        .into_iter()
        .cloned()
        .collect();
    if !record_repair && windows.is_empty() {
        return Ok(None);
    }
    Ok(Some(Reconcile {
        repair_proposal: settled.proposal,
        repair_review: evidence.review(settled.proposal),
        repair,
        record_repair,
        counts_from,
        windows,
    }))
}

impl Vault {
    /// Records a detector's complete judgment of a window with no finding (OF-418 L3): a clean
    /// observation of the producer its runs prove, appended to each open issue of its
    /// recurrence key, with the wake of the Coach's Issues job in the same write. With no such
    /// issue it writes nothing. An error leaves the window to the next pass.
    pub(super) fn record_issue_observation(&self, observed: Observation<'_>) -> Result<()> {
        // A retrieval window records no link to an attempt or a manifest.
        let links = ProducerLinks {
            attempts: Vec::new(),
            manifests: Vec::new(),
        };
        let producer = bind_producer(self, observed.runs, &links)?;
        let (runs, coordinate) = observed_window(observed.runs)?;
        let recurrence_key = IssueCoalescingPolicy::ExactFindingRecipe.recurrence_key(
            self,
            &observed.policy.family,
            &observed.recipe,
            &producer,
            &coordinate,
        )?;
        let judgment = WindowJudgment {
            positive: false,
            tier: observed.tier.token().to_owned(),
            recipe_revision: observed.recipe,
            recurrence_key,
            producer,
            runs,
            decisions: observed.decisions.to_vec(),
            diagnostic: None,
            at: self.now_recorded_at(),
        };
        // Most windows have no open issue of their key: a read decides before a write opens.
        {
            let txn = self.store.env.read_txn()?;
            if !any_open_in_txn(self, &txn, &judgment.recurrence_key)? {
                return Ok(());
            }
        }
        let woke = self.with_write_txn_grouped(|txn| {
            if !observe_in_txn(self, txn, &judgment)? {
                return Ok(false);
            }
            DreamerRunnerStore::new(self).enqueue_coach_issues_in_txn(
                txn,
                None,
                None,
                judgment.at,
            )?;
            Ok(true)
        })?;
        if woke {
            self.store.notify_attempt_observers();
        }
        Ok(())
    }
}
