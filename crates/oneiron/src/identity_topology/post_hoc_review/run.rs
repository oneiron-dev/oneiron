//! The Coach's drain of pending topology-audit candidates (FIX 7817): the
//! first selection kept before any review, the review read whole, the result
//! and its correction in one writer.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{
    INTENTS, RESULTS, SELECTIONS, TopologyAuditCorrection, TopologyAuditDecider,
    TopologyAuditEvidence, TopologyAuditIntent, TopologyAuditOutcome, TopologyAuditResult,
    TopologyAuditScope, TopologyAuditSelection,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_runner::maintenance::coach::COACH_TOPOLOGY_AUDIT_FACET;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::identity_topology::{
    EngineCause, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyAction,
    IdentityTopologyRejection, ReassignmentMap, ReassignmentTarget, StoredIdentityOpAction,
    StoredIdentityOpEvent, TopologySeal, fold_identity_topology_log,
};
use crate::vault::Vault;

/// The domain a recipe's id derives under.
const RECIPE_DOMAIN: &[u8] = b"oneiron/coach/topology-audit-recipe/v1";
/// The domain a recipe's revision derives under.
const RECIPE_REVISION_DOMAIN: &[u8] = b"oneiron/coach/topology-audit-recipe-revision/v1";

/// The topology-audit recipe a host runs, pinned: a stable id for its name
/// and the revision of its exact questions. A selection names both, and a
/// review runs only under the revision that selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologyAuditRecipe {
    pub recipe: EntityId,
    pub revision: [u8; 32],
}

impl TopologyAuditRecipe {
    /// The pin of the recipe `name` asking `questions`, in order: its id
    /// from the name, its revision from every question's exact bytes.
    ///
    /// # Errors
    ///
    /// Never in practice: the id derives from a fixed domain.
    pub fn pin(name: &str, questions: &[&str]) -> Result<Self> {
        let recipe = EntityId::derive(RECIPE_DOMAIN, &[name.as_bytes()])?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECIPE_REVISION_DOMAIN);
        hasher.update(recipe.as_bytes());
        for question in questions {
            hasher.update(&(question.len() as u64).to_be_bytes());
            hasher.update(question.as_bytes());
        }
        Ok(Self {
            recipe,
            revision: *hasher.finalize().as_bytes(),
        })
    }
}

/// One candidate as the recipe reads it: the decision and its scope's
/// history as data, and the records it names by ref, which the host reads
/// under the Coach's own scoped read.
#[derive(Debug, Clone, PartialEq)]
pub struct TopologyAuditCase {
    pub audit_id: [u8; 32],
    pub event: EntityId,
    pub scope: TopologyAuditScope,
    pub decided_by: TopologyAuditDecider,
    /// The decision's participants, then its evidence refs.
    pub evidence: Vec<EntityId>,
    /// `{decision, scope_history}`.
    pub state: Value,
}

/// What the recipe made of one question about one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyAuditAnswer {
    /// The ladder answered: yes or no, or `None` for an abstain, with its
    /// decision receipt as JSON.
    Answered {
        yes: Option<bool>,
        decision_receipt: Option<String>,
    },
    /// The ladder refused the case, by its stable code: an evidence ref the
    /// Coach cannot read, a question no rung takes.
    Refused { code: String },
    /// The recipe cannot be asked now: no rung serves, or the job's clock or
    /// line ran out. The candidate stays pending.
    Deferred,
}

/// What the host lends the Coach: the pinned recipe and its two questions,
/// asked under the admitted job's own line, payer, scoped read and clock.
pub trait TopologyAuditReviewer {
    /// The recipe this host runs.
    ///
    /// # Errors
    ///
    /// Host-defined.
    fn recipe(&self) -> Result<TopologyAuditRecipe>;

    /// Whether `case` is one to review now: yes selects it.
    ///
    /// # Errors
    ///
    /// Host-defined.
    fn select(&self, case: &TopologyAuditCase) -> Result<TopologyAuditAnswer>;

    /// Whether the evidence supports the decision: yes passes it, no raises
    /// a concern.
    ///
    /// # Errors
    ///
    /// Host-defined.
    fn review(&self, case: &TopologyAuditCase) -> Result<TopologyAuditAnswer>;
}

/// What one drain did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TopologyAuditReport {
    /// Candidates the recipe selected in this job.
    pub selected: u32,
    /// Candidates not selected, by the recipe or because their decision had
    /// already moved.
    pub skipped: u32,
    pub passed: u32,
    pub concerns: u32,
    /// Concerns whose undo landed.
    pub corrected: u32,
    pub unknown: u32,
    pub obsolete: u32,
    /// Candidates left pending because the recipe could not be asked.
    pub deferred: u32,
}

/// The job a drain runs in: the recipe its host runs, its attempt and its
/// clock reading.
#[derive(Clone, Copy)]
struct Job {
    recipe: TopologyAuditRecipe,
    attempt: [u8; 16],
    now: u64,
}

/// Where one candidate stands after this job.
enum Step {
    Done,
    Deferred,
}

/// One prior candidate of a scope, as the selection weighs it.
struct Prior {
    event: EntityId,
    created_at: u64,
    audit_id: [u8; 32],
    selected: Option<bool>,
    outcome: Option<TopologyAuditOutcome>,
    undone: bool,
}

/// Every scope's candidates, read once per job.
struct AuditHistory {
    by_scope: BTreeMap<TopologyAuditScope, Vec<Prior>>,
}

impl AuditHistory {
    /// The scope history `intent`'s selection weighs: its scope's earlier
    /// candidates, counted, and the decisions among them that drew a
    /// concern or were undone.
    fn of(&self, intent: &TopologyAuditIntent) -> (Value, Vec<EntityId>) {
        let earlier: Vec<&Prior> = self
            .by_scope
            .get(&intent.scope)
            .into_iter()
            .flatten()
            .filter(|prior| {
                prior.audit_id != intent.audit_id
                    && (prior.created_at, prior.audit_id) < (intent.created_at, intent.audit_id)
            })
            .collect();
        let state = json!({
            "decisions": earlier.len(),
            "selected": count(&earlier, |p| p.selected == Some(true)),
            "passed": count(&earlier, |p| p.outcome == Some(TopologyAuditOutcome::Pass)),
            "concerns": count(&earlier, |p| p.outcome == Some(TopologyAuditOutcome::Concern)),
            "unknown": count(&earlier, |p| p.outcome == Some(TopologyAuditOutcome::Unknown)),
            "undone": count(&earlier, |p| p.undone),
        });
        let evidence = earlier
            .iter()
            .filter(|p| p.undone || p.outcome == Some(TopologyAuditOutcome::Concern))
            .map(|p| p.event)
            .collect();
        (state, evidence)
    }
}

/// How many of `priors` `keep` holds for.
fn count(priors: &[&Prior], keep: fn(&Prior) -> bool) -> usize {
    priors.iter().filter(|prior| keep(prior)).count()
}

/// A review's outcome, engine code and evidence class, with what it read
/// when a recipe was asked: the case, the revision it read and the decision
/// receipt.
type Reviewed = (
    TopologyAuditOutcome,
    String,
    TopologyAuditEvidence,
    Option<(TopologyAuditCase, [u8; 32], Option<String>)>,
);

/// What the deterministic reads of a candidate found.
enum Read {
    /// The decision as declared, still current.
    Ready {
        case: TopologyAuditCase,
        revision: [u8; 32],
    },
    /// An outcome the reads settle with no recipe.
    Settled {
        outcome: TopologyAuditOutcome,
        reason: &'static str,
    },
}

impl Vault {
    /// The Coach's drain of pending topology-audit candidates, under a leased
    /// `coach.topology_audit` attempt (FIX 7817): oldest first, each one's
    /// first selection kept before its review, each review's result and
    /// correction in one writer. The first candidate the recipe cannot be
    /// asked about ends the drain; it and the rest stay pending for the next
    /// job.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, the host's own
    /// errors, or storage errors.
    pub fn run_coach_topology_audits(
        &self,
        attempt: &DreamerAdmittedAttempt,
        reviewer: &dyn TopologyAuditReviewer,
        now: u64,
    ) -> Result<TopologyAuditReport> {
        self.require_coach_attempt(attempt, COACH_TOPOLOGY_AUDIT_FACET)?;
        let pending = self.pending_topology_audits()?;
        let mut report = TopologyAuditReport::default();
        if pending.is_empty() {
            return Ok(report);
        }
        let job = Job {
            recipe: reviewer.recipe()?,
            attempt: *attempt.status.attempt.id.as_bytes(),
            now,
        };
        let history = self.topology_audit_history()?;
        for (index, intent) in pending.iter().enumerate() {
            let step =
                self.drain_one_topology_audit(intent, &history, reviewer, job, &mut report)?;
            if matches!(step, Step::Deferred) {
                report.deferred = u32::try_from(pending.len() - index).unwrap_or(u32::MAX);
                break;
            }
        }
        Ok(report)
    }

    /// Every candidate with no result and no skip, oldest first.
    fn pending_topology_audits(&self) -> Result<Vec<TopologyAuditIntent>> {
        let txn = self.store.env.read_txn()?;
        let mut pending = Vec::new();
        for (audit, intent) in INTENTS.scan(&self.store, &txn)? {
            if RESULTS.contains(&self.store, &txn, &audit)? {
                continue;
            }
            if SELECTIONS
                .get(&self.store, &txn, &audit)?
                .is_some_and(|selection| !selection.selected)
            {
                continue;
            }
            pending.push(intent);
        }
        pending.sort_by_key(|intent| (intent.created_at, intent.audit_id));
        Ok(pending)
    }

    /// Every scope's candidates with their selection, outcome and whether
    /// the effective ledger undid their decision.
    fn topology_audit_history(&self) -> Result<AuditHistory> {
        let txn = self.store.env.read_txn()?;
        let undone = undone_events(&self.fold_effective_identity_topology_events_in_txn(&txn)?);
        let mut by_scope: BTreeMap<TopologyAuditScope, Vec<Prior>> = BTreeMap::new();
        for (audit, intent) in INTENTS.scan(&self.store, &txn)? {
            let selected = SELECTIONS
                .get(&self.store, &txn, &audit)?
                .map(|selection| selection.selected);
            let outcome = RESULTS
                .get(&self.store, &txn, &audit)?
                .map(|result| result.outcome);
            by_scope.entry(intent.scope).or_default().push(Prior {
                event: intent.event,
                created_at: intent.created_at,
                audit_id: audit,
                selected,
                outcome,
                undone: undone.contains(&intent.event),
            });
        }
        Ok(AuditHistory { by_scope })
    }

    /// One candidate's step of the drain: its selection, kept first, then its
    /// review, result and correction.
    fn drain_one_topology_audit(
        &self,
        intent: &TopologyAuditIntent,
        history: &AuditHistory,
        reviewer: &dyn TopologyAuditReviewer,
        job: Job,
        report: &mut TopologyAuditReport,
    ) -> Result<Step> {
        // A home that froze its rows for a move reviews nothing more: the new
        // home drains what the move carried.
        #[cfg(feature = "sync")]
        if !super::keeps_audit_rows_in_txn(self, &self.store.env.read_txn()?)? {
            return Ok(Step::Deferred);
        }
        let selection = match self.topology_audit_selection(&intent.audit_id)? {
            Some(selection) => selection,
            None => {
                let Some(selection) = self.select_topology_audit(intent, history, reviewer, job)?
                else {
                    return Ok(Step::Deferred);
                };
                if selection.selected {
                    report.selected += 1;
                }
                selection
            }
        };
        if !selection.selected {
            report.skipped += 1;
            return Ok(Step::Done);
        }
        let Some(reviewed) =
            self.review_topology_audit(intent, history, reviewer, &selection, job)?
        else {
            return Ok(Step::Deferred);
        };
        // A candidate an erase took while it was reviewed keeps nothing.
        let Some(result) = self.record_topology_audit_result(intent, &selection, reviewed, job)?
        else {
            return Ok(Step::Done);
        };
        match result.outcome {
            TopologyAuditOutcome::Pass => report.passed += 1,
            TopologyAuditOutcome::Concern => {
                report.concerns += 1;
                if matches!(
                    result.correction,
                    Some(TopologyAuditCorrection::Undone { .. })
                ) {
                    report.corrected += 1;
                }
            }
            TopologyAuditOutcome::Unknown => report.unknown += 1,
            TopologyAuditOutcome::Obsolete => report.obsolete += 1,
        }
        Ok(Step::Done)
    }

    /// The review of a selected candidate: `None` when the recipe cannot be
    /// asked now. A review runs only under the revision that selected, so a
    /// host whose recipe moved since judges nothing it did not select, and a
    /// decision that moved since is settled with no question.
    fn review_topology_audit(
        &self,
        intent: &TopologyAuditIntent,
        history: &AuditHistory,
        reviewer: &dyn TopologyAuditReviewer,
        selection: &TopologyAuditSelection,
        job: Job,
    ) -> Result<Option<Reviewed>> {
        if (selection.recipe, selection.recipe_revision) != (job.recipe.recipe, job.recipe.revision)
        {
            return Ok(Some((
                TopologyAuditOutcome::Unknown,
                "recipe_revision_moved".to_owned(),
                TopologyAuditEvidence::EngineSettled,
                None,
            )));
        }
        let (case, revision) = match self.read_topology_audit_case(intent, history)? {
            Read::Settled { outcome, reason } => {
                return Ok(Some((
                    outcome,
                    reason.to_owned(),
                    TopologyAuditEvidence::EngineSettled,
                    None,
                )));
            }
            Read::Ready { case, revision } => (case, revision),
        };
        Ok(match reviewer.review(&case)? {
            TopologyAuditAnswer::Deferred => None,
            TopologyAuditAnswer::Answered {
                yes,
                decision_receipt,
            } => {
                let (outcome, reason) = match yes {
                    Some(true) => (TopologyAuditOutcome::Pass, "pass"),
                    Some(false) => (TopologyAuditOutcome::Concern, "concern"),
                    None => (TopologyAuditOutcome::Unknown, "review_abstained"),
                };
                Some((
                    outcome,
                    reason.to_owned(),
                    TopologyAuditEvidence::ModelJudgment,
                    Some((case, revision, decision_receipt)),
                ))
            }
            TopologyAuditAnswer::Refused { code } => Some((
                TopologyAuditOutcome::Unknown,
                format!("review_refused:{code}"),
                TopologyAuditEvidence::EngineSettled,
                Some((case, revision, None)),
            )),
        })
    }

    fn topology_audit_selection(&self, audit: &[u8; 32]) -> Result<Option<TopologyAuditSelection>> {
        let txn = self.store.env.read_txn()?;
        SELECTIONS.get(&self.store, &txn, audit)
    }

    /// Asks the recipe whether to review `intent` and keeps its first
    /// answer; `None` when the recipe cannot be asked now. A decision that
    /// already moved is skipped with no question. A selection another job
    /// kept first stands. The writer re-reads what the question ran under:
    /// on a node that froze its rows for a move since, or for a candidate an
    /// erase took or changed, it keeps nothing.
    fn select_topology_audit(
        &self,
        intent: &TopologyAuditIntent,
        history: &AuditHistory,
        reviewer: &dyn TopologyAuditReviewer,
        job: Job,
    ) -> Result<Option<TopologyAuditSelection>> {
        let (_, policy_evidence) = history.of(intent);
        let judged = TopologyAuditEvidence::ModelJudgment;
        let settled = TopologyAuditEvidence::EngineSettled;
        let (selected, reason, evidence, decision_receipt) =
            match self.read_topology_audit_case(intent, history)? {
                Read::Settled { reason, .. } => (false, reason.to_owned(), settled, None),
                Read::Ready { case, .. } => match reviewer.select(&case)? {
                    TopologyAuditAnswer::Deferred => return Ok(None),
                    TopologyAuditAnswer::Answered {
                        yes: Some(selected),
                        decision_receipt,
                    } => (
                        selected,
                        if selected { "selected" } else { "not_selected" }.to_owned(),
                        judged,
                        decision_receipt,
                    ),
                    // An undecided recipe reviews: skipping is the claim that
                    // needs a reason, and it gave none.
                    TopologyAuditAnswer::Answered {
                        yes: None,
                        decision_receipt,
                    } => (
                        true,
                        "selection_abstained".to_owned(),
                        judged,
                        decision_receipt,
                    ),
                    TopologyAuditAnswer::Refused { code } => {
                        (true, format!("selection_refused:{code}"), settled, None)
                    }
                },
            };
        let selection = TopologyAuditSelection {
            audit_id: intent.audit_id,
            recipe: job.recipe.recipe,
            recipe_revision: job.recipe.revision,
            policy_evidence,
            selected,
            evidence,
            reason,
            decision_receipt,
            selection_attempt: job.attempt,
            selected_at: job.now,
        };
        let kept = self.with_write_txn_grouped(|txn| {
            #[cfg(feature = "sync")]
            if !super::keeps_audit_rows_in_txn(self, &*txn)? {
                return Ok(None);
            }
            if INTENTS.get(&self.store, &*txn, &intent.audit_id)?.as_ref() != Some(intent) {
                return Ok(None);
            }
            if let Some(held) = SELECTIONS.get(&self.store, &*txn, &intent.audit_id)? {
                return Ok(Some(held));
            }
            SELECTIONS.put(&self.store, txn, &intent.audit_id, &selection)?;
            Ok(Some(selection.clone()))
        })?;
        // A candidate erased, changed or moved away while it was asked keeps
        // nothing here and is done.
        Ok(Some(kept.unwrap_or(TopologyAuditSelection {
            selected: false,
            ..selection
        })))
    }

    /// The candidate's decision as its intent declared it, read whole, and
    /// whether the effective ledger still holds it current.
    fn read_topology_audit_case(
        &self,
        intent: &TopologyAuditIntent,
        history: &AuditHistory,
    ) -> Result<Read> {
        let txn = self.store.env.read_txn()?;
        let Some(stored) = self.identity_topology_event_in_txn(&txn, &intent.event)? else {
            return Ok(settled(TopologyAuditOutcome::Unknown, "event_missing"));
        };
        if super::super::core_digest(&stored)? != intent.core_digest {
            return Ok(settled(TopologyAuditOutcome::Unknown, "core_changed"));
        }
        let Some(record) = self.identity_topology_decision_in_txn(&txn, &intent.event)? else {
            return Ok(settled(
                TopologyAuditOutcome::Unknown,
                "decision_incomplete",
            ));
        };
        let events = self.fold_effective_identity_topology_events_in_txn(&txn)?;
        let fold = fold_identity_topology_log(&events);
        let current = match &record.action {
            StoredIdentityOpAction::Merge { sources, .. } => {
                !sources.is_empty()
                    && sources
                        .iter()
                        .all(|source| fold.current_event.get(source) == Some(&intent.event))
            }
            StoredIdentityOpAction::Split { entity, .. } => {
                fold.current_event.get(entity) == Some(&intent.event)
            }
            StoredIdentityOpAction::Facet { .. } => fold.live_facets.contains(&intent.event),
            _ => false,
        };
        if !current {
            let reason = if undone_events(&events).contains(&intent.event) {
                "event_undone"
            } else {
                "event_superseded"
            };
            return Ok(settled(TopologyAuditOutcome::Obsolete, reason));
        }
        let revision = super::super::topology_seal_revision_for_store_in_txn(
            &self.store,
            &txn,
            &intent.event,
        )?;
        let (scope_history, _) = history.of(intent);
        // The whole decision, and every record it names to be read under
        // the Coach's scoped read: one the read cannot give refuses the
        // question, so no review judges part of a decision.
        let decision = decision_state(intent, &record)?;
        let evidence = super::decision_records(&intent.event, &record)?;
        Ok(Read::Ready {
            case: TopologyAuditCase {
                audit_id: intent.audit_id,
                event: intent.event,
                scope: intent.scope.clone(),
                decided_by: intent.decided_by,
                evidence,
                state: json!({
                    "decision": decision,
                    "scope_history": scope_history,
                }),
            },
            revision,
        })
    }

    /// Keeps one candidate's result, and on a concern the Coach's
    /// correction, in one writer. A result another job kept first stands,
    /// and so does its correction: none is made twice. The writer first
    /// requires this node to keep the rows still (it froze none for a move
    /// since), and the candidate and the selection the review ran under to
    /// be the kept ones still: a candidate an erase took, one whose kept
    /// rows differ, or one a move took, gets no correction and no result
    /// (`None`), so no undo ever lands without the result that receipts it.
    fn record_topology_audit_result(
        &self,
        intent: &TopologyAuditIntent,
        selection: &TopologyAuditSelection,
        (outcome, reason, evidence, read): Reviewed,
        job: Job,
    ) -> Result<Option<TopologyAuditResult>> {
        let selection_digest = selection.digest()?;
        let (reviewer, evidence_refs, revision, decision_receipt) = match read {
            Some((case, revision, decision_receipt)) => (
                Some(crate::dreamer_runner::authority::coach_actor_id()?),
                case.evidence,
                revision,
                decision_receipt,
            ),
            None => (None, Vec::new(), [0; 32], None),
        };
        self.with_write_txn_grouped(move |txn| {
            #[cfg(feature = "sync")]
            if !super::keeps_audit_rows_in_txn(self, &*txn)? {
                return Ok(None);
            }
            if let Some(held) = RESULTS.get(&self.store, &*txn, &intent.audit_id)? {
                return Ok(Some(held));
            }
            if INTENTS.get(&self.store, &*txn, &intent.audit_id)?.as_ref() != Some(intent)
                || SELECTIONS
                    .get(&self.store, &*txn, &intent.audit_id)?
                    .as_ref()
                    != Some(selection)
            {
                return Ok(None);
            }
            let correction = if outcome == TopologyAuditOutcome::Concern {
                Some(self.correct_topology_in_txn(txn, intent, revision, job.now)?)
            } else {
                None
            };
            let result = TopologyAuditResult {
                audit_id: intent.audit_id,
                selection_digest,
                review_attempt: job.attempt,
                reviewer,
                decision_receipt,
                reviewed_core: intent.core_digest,
                reviewed_revision: revision,
                evidence_refs,
                outcome,
                evidence,
                reason,
                correction,
                completed_at: job.now,
            };
            RESULTS.put(&self.store, txn, &intent.audit_id, &result)?;
            Ok(Some(result))
        })
    }

    /// The Coach's receipted correction of a concern: an undo of the
    /// reviewed decision through the existing door, under its current
    /// authority check and at the revision the review read, so a decision
    /// that moved since is refused, never guessed at. An owner's own
    /// decision is never undone here.
    fn correct_topology_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        intent: &TopologyAuditIntent,
        revision: [u8; 32],
        now: u64,
    ) -> Result<TopologyAuditCorrection> {
        let refused = |reason: &str| {
            Ok(TopologyAuditCorrection::Refused {
                reason: reason.to_owned(),
            })
        };
        if intent.decided_by == TopologyAuditDecider::Owner {
            return refused("owner_decision");
        }
        let coach = self.coach_authority_in_txn(txn)?;
        let write = IdentityOpWrite {
            source: ClaimSource::Inferred,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            actor: Some(coach),
        };
        // The runner's own inference, with no owner answer and no Grant
        // line, at the revision the review read.
        let seal = TopologySeal::engine(EngineCause::DreamerInference).with_seen(Some(revision));
        match self.undo_identity_topology_event_in_txn(txn, &intent.event, &write, &seal, now) {
            Ok(IdentityOpOutcome::Applied { event, .. }) => {
                Ok(TopologyAuditCorrection::Undone { event })
            }
            Ok(IdentityOpOutcome::Parked { .. } | IdentityOpOutcome::Noop) => {
                refused("not_applied")
            }
            Err(Error::Sync(SyncError::IdentityTopologyRejected(rejection))) => {
                refused(rejection_code(&rejection))
            }
            Err(error) => Err(error),
        }
    }
}

/// An outcome the reads settle, under its engine code.
const fn settled(outcome: TopologyAuditOutcome, reason: &'static str) -> Read {
    Read::Settled { outcome, reason }
}

/// The decisions an effective undo the fold admits reverted.
fn undone_events(events: &[crate::identity_topology::IdentityTopologyEvent]) -> BTreeSet<EntityId> {
    let rejected: BTreeSet<EntityId> = fold_identity_topology_log(events)
        .rejections
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    events
        .iter()
        .filter(|event| !rejected.contains(&event.event_id))
        .filter_map(|event| match &event.action {
            IdentityTopologyAction::Undo { target } => Some(*target),
            _ => None,
        })
        .collect()
}

/// The decision as the recipe reads it, whole: its scope, who decided, its
/// source, confidence and rationale, and its complete action. A split's and
/// a facet's every reassignment row names its item and where it went, and a
/// facet names each fork it birthed beside its origin, so two decisions that
/// route one claim differently never read alike.
///
/// # Errors
///
/// Never in practice: a fork id derives from a fixed domain.
fn decision_state(intent: &TopologyAuditIntent, record: &StoredIdentityOpEvent) -> Result<Value> {
    let hexes = |ids: &[EntityId]| ids.iter().map(EntityId::to_hex).collect::<Vec<_>>();
    let action = match &record.action {
        StoredIdentityOpAction::Merge { sources, survivor } => json!({
            "sources": hexes(sources),
            "survivor": survivor.to_hex(),
        }),
        StoredIdentityOpAction::Split {
            entity,
            heads,
            reassignment,
            applied_assigned,
            applied_residue,
        } => json!({
            "entity": entity.to_hex(),
            "heads": hexes(heads),
            "reassignment": reassignment_state(reassignment, &[]),
            "applied_assigned": applied_assigned,
            "applied_residue": applied_residue,
        }),
        StoredIdentityOpAction::Facet {
            entity,
            facets,
            reassignment,
            applied_assigned,
            applied_residue,
            forked,
        } => {
            let forks = forked
                .iter()
                .map(|origin| {
                    Ok(json!({
                        "origin": origin.to_hex(),
                        "fork": super::super::op_apply::facet_fork_id(&intent.event, origin)?
                            .to_hex(),
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            json!({
                "entity": entity.to_hex(),
                "facets": hexes(facets),
                "reassignment": reassignment_state(reassignment, facets),
                "applied_assigned": applied_assigned,
                "applied_residue": applied_residue,
                "forks": forks,
            })
        }
        _ => Value::Null,
    };
    Ok(json!({
        "op_kind": intent.scope.op_kind,
        "target_class": intent.scope.target_class,
        "decided_by": intent.decided_by,
        "source": record.source.as_str(),
        "confidence": record.confidence,
        "rationale": record.evidence.as_ref().map(|evidence| evidence.rationale.as_str()),
        "action": action,
    }))
}

/// Every row of a reassignment map, in its canonical order: the item (a
/// claim, or an edge by its endpoints and kind) and its destination (a
/// split head, a facet mask by its minted id among `facets`, or residue).
fn reassignment_state(map: &ReassignmentMap, facets: &[EntityId]) -> Value {
    Value::Array(
        map.entries
            .iter()
            .map(|entry| {
                let item = match entry.item {
                    ClaimSubject::Entity(id) => json!({ "claim": id.to_hex() }),
                    ClaimSubject::Edge {
                        source,
                        kind,
                        target,
                    } => json!({ "edge": {
                        "source": source.to_hex(),
                        "kind": kind.name(),
                        "target": target.to_hex(),
                    }}),
                };
                let to = match entry.target {
                    ReassignmentTarget::Head(head) => json!({ "head": head.to_hex() }),
                    ReassignmentTarget::Facet { index } => json!({
                        "facet": usize::try_from(index)
                            .ok()
                            .and_then(|index| facets.get(index))
                            .map(EntityId::to_hex),
                        "index": index,
                    }),
                    ReassignmentTarget::Residue => json!("residue"),
                };
                json!({ "item": item, "to": to })
            })
            .collect(),
    )
}

/// The stable code of an undo door refusal.
fn rejection_code(rejection: &IdentityTopologyRejection) -> &'static str {
    match rejection {
        IdentityTopologyRejection::NotCurrent { .. } => "not_current",
        IdentityTopologyRejection::NotUndoable { .. } => "not_undoable",
        IdentityTopologyRejection::SealRevisionStale { .. } => "revision_stale",
        IdentityTopologyRejection::SealAuthorityRefused { .. } => "seal_refused",
        _ => "refused",
    }
}
