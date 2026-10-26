//! The writers of a long revision's work graph (FIX 7549). The revision's
//! own `coach.feedback_triage` job owns it: each step it plans lands in one
//! write with every child that step owes and the job's park on them, and
//! only while the job still holds its lease. Each part or synthesis child
//! answers its node in a write of its own, under its own lease; the child
//! whose answer completes a level (or that finds its pinned arm or window
//! gone) wakes the job as the same try. No child files or acknowledges
//! anything: the job alone files the final answer. The sweep queues again
//! each owed child that settled without an answer, and wakes a job owed
//! nothing that no child woke.
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::jobs::{attempt_id, attempt_ref, invalid_job, job_item};
use super::work::{self, FeedbackTriageNodeAnswer, FeedbackTriageStep, FeedbackTriageWork};
use super::{
    COACH_FEEDBACK_TRIAGE_FACET, COACH_FEEDBACK_TRIAGE_PARK_OWNER,
    COACH_FEEDBACK_TRIAGE_PART_FACET, COACH_FEEDBACK_TRIAGE_SYNTHESIS_FACET, FeedbackTriageHandoff,
    FeedbackTriageOutput, FeedbackTriageSourceRef, FeedbackTriageWorkNode, HANDOFFS,
    check_feedback_triage_findings, erased, handoff_in_txn, handoff_key, job_handoff_in_txn,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerParkCause, DreamerRunnerStore,
    DreamerTryLease, EnqueueDreamerAttemptOutcome, ParkDreamerAttempt,
};
use crate::limit_ask::EngineLimit;
use crate::{EntityId, Error, Result, Vault};

/// Why a revision's job is parked.
const PARK_REASON: &str = "the feedback triage waits on its part and synthesis children";

/// A part or synthesis child's input as it rides the queue.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeInput {
    source: String,
    id: String,
    revision: String,
    evidence: EntityId,
    generation: u32,
    node: u32,
}

/// The node a child's input names.
struct NodeTarget {
    source_ref: FeedbackTriageSourceRef,
    evidence: EntityId,
    generation: u32,
    node: u32,
}

/// The revision a child is queued for: its item, evidence and job, and the
/// run the job rides.
struct Owner<'a> {
    source_ref: &'a FeedbackTriageSourceRef,
    evidence: EntityId,
    parent: AttemptId,
    run_id: Option<&'a str>,
}

/// One part or synthesis child's work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedbackTriageNodeJob {
    /// Nothing to answer: the node is answered or no longer current, the
    /// revision is acknowledged, or the owner erased its evidence.
    Settled,
    /// The node waits on this child.
    Pending(Box<FeedbackTriageNodeInput>),
}

/// What one part or synthesis child answers. It is the source's data, never
/// an instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackTriageNodeInput {
    /// The item and revision.
    pub source_ref: FeedbackTriageSourceRef,
    /// The evidence ASSET the item was retained as; every finding cites it.
    pub evidence: EntityId,
    /// The revision's own job, whose run every child spends under.
    pub parent: EntityId,
    /// The arm the child loads exactly, and the window it was cut for.
    pub pin: work::FeedbackTriagePin,
    /// The item text's length in bytes.
    pub item_bytes: u64,
    /// The node.
    pub node: FeedbackTriageWorkNode,
    /// A part's span of the item text, checked against its digest.
    pub text: Option<String>,
    /// A synthesis node's input answers, in order.
    pub answers: Vec<FeedbackTriageOutput>,
}

fn lost_lease() -> Error {
    Error::InvalidConfig("the feedback triage job no longer holds its lease".into())
}

fn node_target(input: &Value) -> Result<NodeTarget> {
    let node: NodeInput = rmpv::ext::from_value(input.clone()).map_err(|_| invalid_job())?;
    Ok(NodeTarget {
        source_ref: FeedbackTriageSourceRef {
            source: node.source,
            id: node.id,
            revision: node.revision,
        },
        evidence: node.evidence,
        generation: node.generation,
        node: node.node,
    })
}

/// The leased child's facet, a part's or a synthesis's, stamped for the
/// Coach.
fn require_node_attempt(vault: &Vault, attempt: &DreamerAdmittedAttempt) -> Result<&'static str> {
    let facet = match attempt.status.payload.attempt_type.as_str() {
        COACH_FEEDBACK_TRIAGE_PART_FACET => COACH_FEEDBACK_TRIAGE_PART_FACET,
        COACH_FEEDBACK_TRIAGE_SYNTHESIS_FACET => COACH_FEEDBACK_TRIAGE_SYNTHESIS_FACET,
        _ => return Err(invalid_job()),
    };
    vault.require_coach_attempt(attempt, facet)?;
    Ok(facet)
}

fn target_handoff_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: &NodeTarget,
) -> Result<FeedbackTriageHandoff> {
    let handoff = handoff_in_txn(vault, txn, &target.source_ref)?
        .ok_or(Error::CorruptedIndex("feedback triage handoff missing"))?;
    if handoff.evidence != target.evidence {
        return Err(invalid_job());
    }
    Ok(handoff)
}

/// The node `target` names, while it is current, unanswered and owed to
/// `child` under `facet`.
fn owed_node<'h>(
    handoff: &'h FeedbackTriageHandoff,
    target: &NodeTarget,
    child: EntityId,
    facet: &str,
) -> Option<&'h FeedbackTriageWorkNode> {
    let work = handoff.work.as_ref()?;
    if work.generation != target.generation {
        return None;
    }
    work.node(target.node).filter(|node| {
        node.answer.is_none()
            && node.attempt == Some(child)
            && (node.level == 0) == (facet == COACH_FEEDBACK_TRIAGE_PART_FACET)
    })
}

/// Whether `parent` is parked on its graph.
fn parked_on_graph_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, parent: AttemptId) -> Result<bool> {
    Ok(DreamerRunnerStore::new(vault)
        .parked_attempt_in_txn(txn, parent)?
        .is_some_and(|park| park.park_owner == COACH_FEEDBACK_TRIAGE_PARK_OWNER))
}

/// Wakes `parent`, parked on its graph, as the same try.
fn wake_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: AttemptId,
    now: u64,
) -> Result<bool> {
    Ok(DreamerRunnerStore::new(vault)
        .resume_parked_in_txn(txn, parent, COACH_FEEDBACK_TRIAGE_PARK_OWNER, now)?
        .is_some())
}

/// Queues one node's child under `owner`'s job. The key holds one live
/// child per node; a settled child holds none, so a sweep can queue it
/// again.
fn enqueue_node_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &Owner<'_>,
    generation: u32,
    node: &FeedbackTriageWorkNode,
    now: u64,
) -> Result<EntityId> {
    let facet = if node.level == 0 {
        COACH_FEEDBACK_TRIAGE_PART_FACET
    } else {
        COACH_FEEDBACK_TRIAGE_SYNTHESIS_FACET
    };
    let source_ref = owner.source_ref;
    let input = rmpv::ext::to_value(NodeInput {
        source: source_ref.source.clone(),
        id: source_ref.id.clone(),
        revision: source_ref.revision.clone(),
        evidence: owner.evidence,
        generation,
        node: node.id,
    })
    .map_err(|_| invalid_job())?;
    let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HOST_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: facet.into(),
            input,
            parent_attempt: Some(owner.parent),
        },
        Some(format!(
            "{facet}:{}:{}:{}:{generation}:{}",
            source_ref.source, source_ref.id, source_ref.revision, node.id
        )),
        owner.run_id.map(str::to_owned),
        now,
    )?;
    let status = match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };
    attempt_ref(status.attempt.id)
}

/// Queues a child for each unanswered current node whose child settled or
/// is gone; a live child keeps its node. Answers how many it queued.
fn enqueue_owed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &Owner<'_>,
    work: &mut FeedbackTriageWork,
    now: u64,
) -> Result<usize> {
    let queue = AttemptQueue::new(vault);
    let level = work.level();
    let generation = work.generation;
    let mut queued = 0;
    for node in &mut work.nodes {
        if node.level != level || node.answer.is_some() {
            continue;
        }
        if let Some(child) = &node.attempt
            && queue
                .get_in_txn(txn, attempt_id(child)?)?
                .is_some_and(|record| !record.state.is_terminal())
        {
            continue;
        }
        node.attempt = Some(enqueue_node_in_txn(
            vault, txn, owner, generation, node, now,
        )?);
        queued += 1;
    }
    Ok(queued)
}

/// The sweep's turn at a revision whose live job has a graph, in the
/// sweep's write: while the job is parked on it, each owed child that
/// settled without an answer or is gone is queued again, and a job owed
/// nothing, or whose evidence the owner erased, is woken. `true` when it
/// queued or woke.
pub(super) fn reconcile_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    handoff: &mut FeedbackTriageHandoff,
    now: u64,
) -> Result<bool> {
    let parent = attempt_id(&handoff.attempt)?;
    if !parked_on_graph_in_txn(vault, txn, parent)? {
        return Ok(false);
    }
    let erased = erased::evidence_erased_in_txn(vault, txn, handoff)?;
    let run_id = AttemptQueue::new(vault)
        .get_in_txn(txn, parent)?
        .and_then(|record| record.run_id);
    let Some(work) = handoff.work.as_mut() else {
        return Ok(false);
    };
    if erased || !work.owed() {
        return wake_in_txn(vault, txn, parent, now);
    }
    let owner = Owner {
        source_ref: &handoff.source_ref,
        evidence: handoff.evidence,
        parent,
        run_id: run_id.as_deref(),
    };
    let queued = enqueue_owed_in_txn(vault, txn, &owner, work, now)?;
    if queued > 0 {
        HANDOFFS.put(&vault.store, txn, key, handoff)?;
    }
    Ok(queued > 0)
}

/// Whether `step` cuts the item text, which its writer then reads.
fn cuts_text(step: &FeedbackTriageStep) -> bool {
    match step {
        FeedbackTriageStep::Generation { .. } => true,
        FeedbackTriageStep::Repartition { splits, .. } => {
            splits.iter().any(|split| !split.spans.is_empty())
        }
        FeedbackTriageStep::Synthesis { .. } | FeedbackTriageStep::Wait => false,
    }
}

impl Vault {
    /// Plans one step of a long revision's triage as the Coach, under its
    /// leased `coach.feedback_triage` job (FIX 7549), and parks the job on
    /// its children: the step, a child for every node it owes, and the park
    /// commit in one write, and only while the job holds its lease. The job
    /// stays the revision's owner; the child that completes a level, or the
    /// next sweep, wakes it as the same try.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, not the revision's
    /// current job or no longer leased; a step whose spans or batches do not
    /// cover what they replace, whole and in order; [`Error::Refused`] once
    /// the owner erased the revision's evidence; storage errors.
    pub fn park_coach_feedback_triage(
        &self,
        attempt: &DreamerAdmittedAttempt,
        step: FeedbackTriageStep,
        now: u64,
    ) -> Result<FeedbackTriageWork> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_TRIAGE_FACET)?;
        let record = &attempt.status.attempt;
        let lease_owner = record.lease_owner.as_deref().ok_or_else(lost_lease)?;
        // The item's revision fixes its text, so it is read before the write.
        let text = if cuts_text(&step) {
            let handoff = {
                let txn = self.store.env.read_txn()?;
                job_handoff_in_txn(self, &txn, attempt)?
            };
            Some(job_item(self, &handoff)?.text()?)
        } else {
            None
        };
        let work = self.with_write_txn_grouped(|txn| {
            let mut handoff = job_handoff_in_txn(self, txn, attempt)?;
            if handoff.result.is_some() || handoff.attempt != attempt_ref(record.id)? {
                return Err(invalid_job());
            }
            erased::refuse_erased_in_txn(self, txn, &handoff)?;
            // The park fence lands on a terminal row too; a plan lands only
            // on the job's live lease.
            let queue = AttemptQueue::new(self);
            if !queue.holds_lease_in_txn(txn, record.id, lease_owner, record.attempt_count)? {
                return Err(lost_lease());
            }
            // The park renews the lease it parks under: a lease reclaim that
            // read the parked set before this write finds the lease live
            // under its own writer and leaves it (FIX 10304).
            queue.renew_lease_in_txn(txn, record.id, lease_owner, record.attempt_count, now)?;
            let mut work = work::apply(handoff.work.take(), step, text.as_deref(), now)?;
            let owner = Owner {
                source_ref: &handoff.source_ref,
                evidence: handoff.evidence,
                parent: record.id,
                run_id: record.run_id.as_deref(),
            };
            enqueue_owed_in_txn(self, txn, &owner, &mut work, now)?;
            let parked = DreamerRunnerStore::new(self).park_if_current_lease_in_txn(
                txn,
                ParkDreamerAttempt {
                    attempt_id: record.id,
                    reason: PARK_REASON.to_owned(),
                    cause: DreamerParkCause::Signal,
                    park_owner: COACH_FEEDBACK_TRIAGE_PARK_OWNER.to_owned(),
                    now,
                },
                DreamerTryLease {
                    owner: lease_owner,
                    generation: record.attempt_count,
                },
            )?;
            if parked.is_none() {
                return Err(lost_lease());
            }
            handoff.work = Some(work.clone());
            HANDOFFS.put(
                &self.store,
                txn,
                &handoff_key(&handoff.source_ref),
                &handoff,
            )?;
            Ok(work)
        })?;
        self.store.notify_attempt_observers();
        Ok(work)
    }

    /// What a leased part or synthesis child answers (FIX 7549): a part's
    /// span of the item, read back from the item its revision names and
    /// checked against the graph's digests, or a synthesis node's input
    /// answers, with the arm its job pinned; or nothing, once the node is
    /// answered or no longer current, the revision is acknowledged, or the
    /// owner erased its evidence.
    ///
    /// # Errors
    ///
    /// An attempt that is not a part or synthesis Coach attempt; a child
    /// naming no handoff, or an item that no longer matches its revision or
    /// digests; storage errors.
    pub fn feedback_triage_node(
        &self,
        attempt: &DreamerAdmittedAttempt,
    ) -> Result<FeedbackTriageNodeJob> {
        let facet = require_node_attempt(self, attempt)?;
        let target = node_target(&attempt.status.payload.input)?;
        let child = attempt_ref(attempt.status.attempt.id)?;
        let (handoff, node) = {
            let txn = self.store.env.read_txn()?;
            let handoff = target_handoff_in_txn(self, &txn, &target)?;
            if handoff.result.is_some() || erased::evidence_erased_in_txn(self, &txn, &handoff)? {
                return Ok(FeedbackTriageNodeJob::Settled);
            }
            let Some(node) = owed_node(&handoff, &target, child, facet).cloned() else {
                return Ok(FeedbackTriageNodeJob::Settled);
            };
            (handoff, node)
        };
        let work = handoff
            .work
            .as_ref()
            .ok_or(Error::CorruptedIndex("feedback triage work missing"))?;
        let text = if node.span.is_some() {
            let item = job_item(self, &handoff)?.text()?;
            Some(work::span_text(work, &node, &item)?.to_owned())
        } else {
            None
        };
        let answers = node
            .inputs
            .iter()
            .map(|id| {
                work.node(*id)
                    .and_then(|input| input.answer.as_ref())
                    .map(|answer| answer.output.clone())
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::CorruptedIndex("feedback triage synthesis input"))?;
        Ok(FeedbackTriageNodeJob::Pending(Box::new(
            FeedbackTriageNodeInput {
                source_ref: handoff.source_ref,
                evidence: handoff.evidence,
                parent: handoff.attempt,
                pin: work.pin.clone(),
                item_bytes: work.item_bytes,
                node,
                text,
                answers,
            },
        )))
    }

    /// Records a leased part or synthesis child's answer on its node, as the
    /// Coach (FIX 7549), and wakes the revision's job once its level owes
    /// nothing more. `None` answers nothing and wakes the job at once: the
    /// child's pinned arm no longer loads, or its window shrank under its
    /// node. A node no longer current takes nothing. Nothing is filed and
    /// nothing acknowledged here.
    ///
    /// # Errors
    ///
    /// An attempt that is not a part or synthesis Coach attempt or no longer
    /// leased; a finding that cites anything but the item it was given or
    /// names no problem (nothing is recorded); [`Error::Refused`] once the
    /// owner erased the revision's evidence; storage errors.
    pub fn record_coach_feedback_triage_node(
        &self,
        attempt: &DreamerAdmittedAttempt,
        answer: Option<(&FeedbackTriageOutput, &str)>,
        now: u64,
    ) -> Result<()> {
        let facet = require_node_attempt(self, attempt)?;
        let target = node_target(&attempt.status.payload.input)?;
        let record = &attempt.status.attempt;
        let lease_owner = record.lease_owner.as_deref().ok_or_else(lost_lease)?;
        let child = attempt_ref(record.id)?;
        if let Some((output, _)) = answer {
            // Every finding is kept; how many is measured (Rule 5).
            let _ = self.measure_limit(
                EngineLimit::MaintenanceRowItems,
                output.findings.len() as u64,
            );
        }
        let woke = self.with_write_txn_grouped(|txn| {
            let mut handoff = target_handoff_in_txn(self, txn, &target)?;
            if handoff.result.is_some() {
                return Ok(false);
            }
            erased::refuse_erased_in_txn(self, txn, &handoff)?;
            if !AttemptQueue::new(self).holds_lease_in_txn(
                txn,
                record.id,
                lease_owner,
                record.attempt_count,
            )? {
                return Err(lost_lease());
            }
            if owed_node(&handoff, &target, child, facet).is_none() {
                return Ok(false);
            }
            if let Some((output, served)) = answer {
                check_feedback_triage_findings(output, &handoff.source_ref)?;
                let node = handoff
                    .work
                    .as_mut()
                    .and_then(|work| work.nodes.iter_mut().find(|node| node.id == target.node))
                    .ok_or(Error::CorruptedIndex("feedback triage node missing"))?;
                node.answer = Some(FeedbackTriageNodeAnswer {
                    output: output.clone(),
                    attempt: child,
                    served_model: served.to_owned(),
                    recorded_at: now,
                });
                HANDOFFS.put(
                    &self.store,
                    txn,
                    &handoff_key(&handoff.source_ref),
                    &handoff,
                )?;
            }
            let owed = handoff.work.as_ref().is_some_and(FeedbackTriageWork::owed);
            let parent = attempt_id(&handoff.attempt)?;
            if (answer.is_some() && owed) || !parked_on_graph_in_txn(self, txn, parent)? {
                return Ok(false);
            }
            wake_in_txn(self, txn, parent, now)
        })?;
        if woke {
            self.store.notify_attempt_observers();
        }
        Ok(())
    }
}
