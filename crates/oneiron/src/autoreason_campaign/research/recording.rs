//! Research fork, weave, measurement and prune recording.
//! Entry function: `record_fork`.
//! The research parent owns experiment records and typed tables.

use super::*;

/// The child must be an existing attempt of the campaign's run, enqueued
/// under one of `parents` on the run tree.
fn check_child(
    vault: &Vault,
    binding: &ResearchBinding,
    child: AttemptId,
    parents: &[AttemptId],
) -> Result<()> {
    let record = AttemptQueue::new(vault)
        .get(child)?
        .ok_or(invalid("the experiment attempt is missing"))?;
    if record.run_id.as_deref() != Some(binding.run_id.as_str()) {
        return Err(invalid(
            "the experiment attempt is not on the campaign's run",
        ));
    }
    let parent = crate::run_tree::effective_parent(&record);
    if !parent.is_some_and(|parent| parents.contains(&parent)) {
        return Err(invalid(
            "the experiment attempt is not a run-tree child of its parent",
        ));
    }
    Ok(())
}

fn put_new_node(
    vault: &Vault,
    root: AttemptId,
    node: &ExperimentNode,
    parents: &[AttemptId],
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| put_new_node_in_txn(vault, txn, root, node, parents))
}

fn put_new_node_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    node: &ExperimentNode,
    parents: &[AttemptId],
) -> Result<()> {
    let key = (*root.as_bytes(), *node.attempt.as_bytes());
    if NODE.contains(&vault.store, txn, &key)? {
        return Err(invalid("the experiment is already recorded"));
    }
    // A parent pruned while the child was checked cannot take it.
    let nodes = nodes_in_txn(vault, txn, root)?;
    if parents.iter().any(|parent| pruned_lineage(&nodes, parent)) {
        return Err(invalid("a pruned branch takes no new experiments"));
    }
    NODE.put(&vault.store, txn, &key, node)
}

/// The weave claim's approval and the gate's recorded decision on its
/// landing. The claim must be live and have landed through the gated claim
/// door: its locally attested writer, and that writer's latest decision on
/// it that let a row land. A controller weaves only a claim it wrote. A claim
/// past Proposed stands for anyone but the owner only on an Allow for its
/// writer: the owner's Grant (actor ceilings, source trust) let this writer
/// land it there, which is the auto-weave grant ([`auto_weave_granted`]).
fn weave_claim_landing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    writer: WeaveWriter,
    claim: &EntityId,
) -> Result<(ClaimApprovalStatus, String)> {
    let body = vault
        .get_claim_in_txn(txn, claim)?
        .ok_or(invalid("the weave's claim is missing"))?;
    if body.lifecycle != ClaimLifecycleStatus::Active
        || body.approval == ClaimApprovalStatus::Rejected
    {
        return Err(invalid("the weave's claim was rejected or closed"));
    }
    let author = crate::batch::authenticated_claim_author_in_txn(&vault.store, txn, claim, &body)?
        .ok_or(invalid("the weave's claim has no attested writer"))?
        .entity_ref();
    if let WeaveWriter::Controller { actor } = writer
        && actor != author
    {
        return Err(invalid(
            "a campaign controller weaves only a claim it wrote",
        ));
    }
    let author = author.to_hex();
    let decision = vault
        .store
        .gate_decisions_for_claim_in_txn(txn, claim.as_bytes())?
        .into_iter()
        .filter(|record| {
            record.redacted_at.is_none()
                && record.content_kind == WEAVE_CONTENT_KIND
                && record.actor_ref.as_deref() == Some(author.as_str())
                && record.outcome != OUTCOME_DENY
        })
        .last()
        .ok_or(invalid("the weave's claim did not land through the gate"))?;
    if body.approval != ClaimApprovalStatus::Proposed
        && writer != WeaveWriter::Owner
        && !auto_weave_granted(&decision)
    {
        return Err(invalid(
            "a weave lands past Proposed only under an owner auto-weave grant",
        ));
    }
    Ok((body.approval, decision.decision_id.to_hex()))
}

/// Whether the gate's decision on a weave claim carries an owner auto-weave
/// grant: an Allow for its writer, which the owner's Grant alone gives a
/// non-owner landing past Proposed. A narrower, weave-scoped grant changes
/// this one test.
fn auto_weave_granted(decision: &crate::store::GateDecisionRecord) -> bool {
    decision.outcome == OUTCOME_ALLOW
}

/// Record a fork: a variation of a live parent, or a debug child of a buggy
/// one. The child attempt was enqueued by the workflow; this registers its
/// candidate and calls no worker.
/// # Errors
/// An unbound campaign, an unknown, pruned or wrong-state parent, a child not
/// under that parent on the run, a recorded child, or storage errors.
pub fn record_fork(
    vault: &Vault,
    root: AttemptId,
    input: ForkInput,
    at: u64,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    input.candidate.validate()?;
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    drop(txn);
    let parent = nodes.get(input.parent.as_bytes()).ok_or(invalid(
        "the fork parent is not an experiment of this campaign",
    ))?;
    if pruned_lineage(&nodes, &input.parent) {
        return Err(invalid("a pruned branch takes no new experiments"));
    }
    match (input.kind, parent.invalid.is_some()) {
        (ForkKind::Variation, true) => {
            return Err(invalid("a buggy node takes debug children, not variations"));
        }
        (ForkKind::Debug, false) => {
            return Err(invalid("only a buggy node takes a debug child"));
        }
        _ => {}
    }
    check_child(vault, &binding, input.child, &[input.parent])?;
    let node = ExperimentNode {
        attempt: input.child,
        kind: match input.kind {
            ForkKind::Variation => ExperimentKind::Variation,
            ForkKind::Debug => ExperimentKind::Debug,
        },
        parents: vec![input.parent],
        candidate: input.candidate,
        search: None,
        held_out: None,
        invalid: None,
        weave: None,
        pruned: None,
        recorded_at: at,
    };
    put_new_node(vault, root, &node, &[input.parent])?;
    Ok(node)
}

/// Record a weave: a crossover child of several measured parents with a
/// common ancestor, landed as a claim through the gate. Refused until a
/// held-out win in this campaign turned merge crossover on. The receipt
/// binds the gate's decision on the claim, read in the node's transaction.
/// # Errors
/// Crossover not requested or not yet earned, fewer than two or duplicate
/// parents, an unmeasured, buggy or pruned parent, an ancestor common to not
/// every parent, an overlap under the floor, a child not under a parent on
/// the run, a missing, retracted or rejected claim, a claim the controller
/// did not write or that has no gate decision, a non-owner landing past
/// Proposed without an auto-weave grant, or storage errors.
pub fn record_weave(
    vault: &Vault,
    root: AttemptId,
    writer: WeaveWriter,
    input: WeaveInput,
    at: u64,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    input.candidate.validate()?;
    let crossover = binding.config.knobs.merge_crossover;
    if !crossover.requested {
        return Err(invalid("this campaign did not request merge crossover"));
    }
    if !promotion::crossover_earned(vault, root)? {
        return Err(invalid("merge crossover stays off until a held-out win"));
    }
    let distinct: BTreeSet<[u8; 16]> = input.parents.iter().map(|p| *p.as_bytes()).collect();
    if input.parents.len() < 2
        || input.parents.len() > MAX_WEAVE_PARENTS
        || distinct.len() != input.parents.len()
    {
        return Err(invalid("a weave has two to eight distinct parents"));
    }
    if !input.validation_overlap.is_finite()
        || input.validation_overlap < crossover.min_validation_overlap
        || input.validation_overlap > 1.0
    {
        return Err(invalid(
            "the weave's validation overlap is under the campaign floor",
        ));
    }
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    drop(txn);
    for parent in &input.parents {
        let node = nodes.get(parent.as_bytes()).ok_or(invalid(
            "a weave parent is not an experiment of this campaign",
        ))?;
        if node.search.is_none() || node.invalid.is_some() || pruned_lineage(&nodes, parent) {
            return Err(invalid(
                "a weave parent must be measured, sound and unpruned",
            ));
        }
        if !ancestors_or_self(&nodes, parent).contains(input.common_ancestor.as_bytes()) {
            return Err(invalid(
                "the common ancestor is not an ancestor of every parent",
            ));
        }
    }
    check_child(vault, &binding, input.child, &input.parents)?;
    vault.with_write_txn_grouped(|txn| {
        let (claim_approval, gate_decision) =
            weave_claim_landing_in_txn(vault, txn, writer, &input.claim)?;
        let node = ExperimentNode {
            attempt: input.child,
            kind: ExperimentKind::Weave,
            parents: input.parents.clone(),
            candidate: input.candidate.clone(),
            search: None,
            held_out: None,
            invalid: None,
            weave: Some(WeaveReceipt {
                common_ancestor: input.common_ancestor,
                validation_overlap: input.validation_overlap,
                claim: input.claim,
                claim_approval,
                gate_decision,
                at,
            }),
            pruned: None,
            recorded_at: at,
        };
        put_new_node_in_txn(vault, txn, root, &node, &input.parents)?;
        Ok(node)
    })
}

fn check_measurement(
    config: &CampaignConfig,
    measurement: &Measurement,
    split: &CampaignDatasetRef,
) -> Result<()> {
    if measurement.dataset != *split
        || measurement.metric_set_id != config.metric_set.set_id
        || measurement.metric_set_revision != config.metric_set.revision
        || measurement.scores.len() != config.metric_set.axes.len()
        || config.metric_set.axes.iter().any(|axis| {
            !measurement
                .scores
                .get(&axis.name)
                .is_some_and(|value| value.is_finite())
        })
    {
        return Err(invalid(
            "the measurement's split or metric set does not match the campaign",
        ));
    }
    Ok(())
}

fn update_node(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    change: impl FnOnce(&mut ExperimentNode) -> Result<()>,
) -> Result<ExperimentNode> {
    vault.with_write_txn_grouped(|txn| {
        let key = (*root.as_bytes(), *attempt.as_bytes());
        let mut node = NODE
            .get(&vault.store, txn, &key)?
            .ok_or(invalid("the attempt is not an experiment of this campaign"))?;
        change(&mut node)?;
        NODE.put(&vault.store, txn, &key, &node)?;
        Ok(node)
    })
}

/// Record a node's search-split evidence, its selection signal. Recorded once.
/// # Errors
/// An unbound campaign or unknown node, evidence off the search split or
/// ruler, non-finite or out-of-range numbers, a buggy or already-measured
/// node, or storage errors.
pub fn record_search_measurement(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    evidence: SearchEvidence,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    check_measurement(
        &binding.config,
        &evidence.measurement,
        &binding.config.splits.search,
    )?;
    bounded(
        &evidence.estimator_version,
        "search evidence names its estimator",
    )?;
    bounded_refs(&evidence.receipt_refs, true)?;
    if !evidence.confirmed_hits.is_finite()
        || evidence.confirmed_hits < 0.0
        || !evidence.attribution.is_finite()
        || !(0.0..=1.0).contains(&evidence.attribution)
        || !evidence.hop_cost.is_finite()
        || evidence.hop_cost < 0.0
        || !evidence.expected_gain.is_finite()
        || evidence.expected_gain < 0.0
        || !evidence.reward().is_finite()
        || evidence
            .knob_reliability
            .is_some_and(|reliability| !(0.0..=1.0).contains(&reliability))
    {
        return Err(invalid("search evidence is out of range"));
    }
    update_node(vault, root, attempt, |node| {
        if node.search.is_some() || node.invalid.is_some() {
            return Err(invalid("the node is already measured or buggy"));
        }
        node.search = Some(evidence);
        Ok(())
    })
}

/// Record a node's held-out evidence. It is read only by the promotion basis,
/// and recorded once: a second held-out look would be search feedback.
/// # Errors
/// An unbound campaign or unknown node, evidence off the held-out split or
/// ruler, a buggy node or one already held out, or storage errors.
pub fn record_held_out_measurement(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    measurement: Measurement,
    receipt_refs: Vec<String>,
    at: u64,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    check_measurement(
        &binding.config,
        &measurement,
        &binding.config.splits.held_out,
    )?;
    bounded_refs(&receipt_refs, true)?;
    update_node(vault, root, attempt, |node| {
        if node.held_out.is_some() || node.invalid.is_some() {
            return Err(invalid("the node is already held out or buggy"));
        }
        node.held_out = Some(HeldOutEvidence {
            measurement,
            receipt_refs,
            recorded_at: at,
        });
        Ok(())
    })
}

/// Mark a node buggy. It stays in the tree as evidence and takes debug
/// children; it never supplies selection signal.
/// # Errors
/// An unbound campaign or unknown node, the root, an unbounded reason or
/// refs, a node already measured or buggy, or storage errors.
pub fn record_invalid_experiment(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    reason: &str,
    evidence_refs: Vec<String>,
    at: u64,
) -> Result<ExperimentNode> {
    binding(vault, root)?;
    if attempt == root {
        return Err(invalid(
            "the incumbent root is not an experiment to mark buggy",
        ));
    }
    bounded(reason, "a buggy node names a bounded reason")?;
    bounded_refs(&evidence_refs, true)?;
    update_node(vault, root, attempt, |node| {
        if node.search.is_some() || node.invalid.is_some() {
            return Err(invalid("the node is already measured or buggy"));
        }
        node.invalid = Some(InvalidReceipt {
            reason: reason.to_owned(),
            evidence_refs,
            at,
        });
        Ok(())
    })
}

/// Stop exploring a branch for a stated cause. Its attempts, claims and
/// outputs are untouched; the node and its descendants leave selection.
/// # Errors
/// An unbound campaign or unknown node, the root, a dominating node that is
/// not a measured, unpruned experiment beating it, a floor axis not in the
/// ruler, a node already pruned, or storage errors.
pub fn prune_branch(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    reason: PruneReason,
    evidence_refs: Vec<String>,
    at: u64,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    if attempt == root {
        return Err(invalid("the incumbent root is never pruned"));
    }
    bounded_refs(&evidence_refs, true)?;
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    drop(txn);
    let node = nodes
        .get(attempt.as_bytes())
        .ok_or(invalid("the attempt is not an experiment of this campaign"))?;
    match &reason {
        PruneReason::Dominated { by } => {
            let reward = |n: &ExperimentNode| n.search.as_ref().map(SearchEvidence::reward);
            let winner = nodes
                .get(by.as_bytes())
                .filter(|_| *by != attempt && !pruned_lineage(&nodes, by));
            let beats = winner
                .and_then(reward)
                .zip(reward(node))
                .is_some_and(|(winner, loser)| winner > loser);
            if !beats {
                return Err(invalid(
                    "the dominating branch must be measured, live and better",
                ));
            }
        }
        PruneReason::FloorRegression { axis } => {
            if !binding
                .config
                .metric_set
                .axes
                .iter()
                .any(|row| row.name == *axis && row.role == MetricRole::Floor)
            {
                return Err(invalid(
                    "a floor regression names a floor axis of the ruler",
                ));
            }
        }
        PruneReason::GainBelowFloor | PruneReason::Stopped { .. } => {}
    }
    update_node(vault, root, attempt, |node| {
        if node.pruned.is_some() {
            return Err(invalid("the branch is already pruned"));
        }
        node.pruned = Some(PruneReceipt {
            reason,
            evidence_refs,
            at,
        });
        Ok(())
    })
}

pub(super) fn find_node<'a>(nodes: &'a [RunTreeNode], attempt: &str) -> Option<&'a RunTreeNode> {
    nodes.iter().find_map(|node| {
        if node.attempt_id == attempt {
            Some(node)
        } else {
            find_node(&node.children, attempt)
        }
    })
}
