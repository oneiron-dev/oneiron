//! Research campaign binding, goal pins and binding reads.
//! Entry function: `bind_research`.
//! The research parent owns the shared binding and node vocabulary.

use super::*;

/// The ruler of a skill campaign is the skill's goal: the same axes, each in
/// the same role. A campaign cannot add, drop or re-role one.
fn check_ruler(config: &CampaignConfig, goal: &[GoalAxisSpec]) -> Result<()> {
    let role = |kind: GoalAxisKind| match kind {
        GoalAxisKind::Primary => MetricRole::Primary,
        GoalAxisKind::Floor => MetricRole::Floor,
        GoalAxisKind::Cost => MetricRole::Cost,
    };
    let mut want: Vec<(&str, MetricRole)> = goal
        .iter()
        .map(|axis| (axis.name.as_str(), role(axis.kind)))
        .collect();
    let mut have: Vec<(&str, MetricRole)> = config
        .metric_set
        .axes
        .iter()
        .map(|axis| (axis.name.as_str(), axis.role))
        .collect();
    want.sort_by(|a, b| a.0.cmp(b.0));
    have.sort_by(|a, b| a.0.cmp(b.0));
    if want != have {
        return Err(invalid(
            "a skill campaign's metric set must be the skill's goal axes",
        ));
    }
    Ok(())
}

/// The goal a skill campaign was bound under must still be the goal in force.
pub(in crate::autoreason_campaign) fn check_goal_current(
    vault: &Vault,
    binding: &ResearchBinding,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    check_goal_current_in_txn(vault, &txn, binding)
}

pub(in crate::autoreason_campaign) fn check_goal_current_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &ResearchBinding,
) -> Result<()> {
    if !goal_pin_current_in_txn(vault, txn, binding)? {
        return Err(invalid(
            "the skill's goal moved since the campaign was bound; bind a new campaign",
        ));
    }
    Ok(())
}

/// The current-pin check: whether a skill campaign's pinned goal is still
/// the goal in force. A campaign that pins no goal has none to move.
fn goal_pin_current_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &ResearchBinding,
) -> Result<bool> {
    if let (ResearchTarget::Skill { skill }, Some(pin)) = (&binding.target, &binding.goal) {
        let goal = crate::skill_optimize::skill_edit_goal_in_txn(vault, txn, skill)?;
        return Ok(goal.goal_id == pin.goal_id && goal.revision == pin.revision);
    }
    Ok(true)
}

/// What a host judges a skill campaign's goal on (FIX 1331): the governed
/// skill, the goal record the campaign was bound under, the campaign's
/// incumbent (its latest promoted candidate, else the root) and the receipts
/// the incumbent's search measurement is grounded on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResearchGoalBasis {
    pub root: AttemptId,
    pub skill: EntityId,
    pub pin: ResearchGoalPin,
    pub incumbent: AttemptId,
    /// Empty when the incumbent holds no search measurement.
    pub receipts: Vec<String>,
}

/// The basis `root`'s goal is judged on, read in one snapshot. `None` for a
/// campaign with no goal to meet: a config campaign, a skill campaign bound
/// without a goal, or one whose goal moved since it was bound (the
/// current-pin check). It reads; it judges nothing.
/// # Errors
/// An unbound campaign, an unreadable goal, or storage errors.
pub fn research_goal_basis(vault: &Vault, root: AttemptId) -> Result<Option<ResearchGoalBasis>> {
    let txn = vault.store.env.read_txn()?;
    let binding = binding_in_txn(vault, &txn, root)?;
    let (ResearchTarget::Skill { skill }, Some(pin)) = (&binding.target, &binding.goal) else {
        return Ok(None);
    };
    if !goal_pin_current_in_txn(vault, &txn, &binding)? {
        return Ok(None);
    }
    let incumbent = research_incumbent_in_txn(vault, &txn, root)?;
    let receipts = nodes_in_txn(vault, &txn, root)?
        .remove(incumbent.as_bytes())
        .and_then(|node| node.search)
        .map_or_else(Vec::new, |search| search.receipt_refs);
    Ok(Some(ResearchGoalBasis {
        root,
        skill: *skill,
        pin: pin.clone(),
        incumbent,
        receipts,
    }))
}

/// Bind a campaign to an existing root attempt: validate its configuration,
/// pin its ruler, its trusted selection policy and its confirmation cohort,
/// and record the incumbent as the root node. A root binds once.
/// # Errors
/// An invalid config or candidate, a missing root or run, a skill metric set
/// that is not the skill's goal, a missing selection policy, a missing or
/// retired cohort, an execution spec with a zero unit count, a referee
/// without a confirmation seat (or the reverse) or an agent that is not a
/// dispatchable AGENT_DEF, an already-bound root, or storage errors.
pub fn bind_research(
    vault: &Vault,
    request: ResearchBindRequest,
    at: u64,
) -> Result<ResearchBinding> {
    request.config.validate().map_err(campaign_error)?;
    request.incumbent.validate()?;
    if let Some(execution) = &request.execution {
        execution.validate(vault, request.confirmation.is_some())?;
    }
    if let Some(holder) = &request.holder {
        bounded(holder, "a campaign holder is a bounded id")?;
    }
    if let Some(share) = &request.share {
        bounded(share, "a campaign budget share is a bounded key")?;
    }
    estimator::validate_ladder(&request.prior_ladder)?;
    let record = AttemptQueue::new(vault)
        .get(request.root)?
        .ok_or(invalid("the campaign root attempt is missing"))?;
    let run_id = record
        .run_id
        .ok_or(invalid("the campaign root attempt carries no run"))?;
    let goal = match &request.target {
        ResearchTarget::Skill { skill } => {
            let goal = skill_edit_goal(vault, skill)?;
            check_ruler(&request.config, &goal.axes)?;
            Some(ResearchGoalPin {
                goal_id: goal.goal_id,
                revision: goal.revision,
                project: goal.project,
            })
        }
        ResearchTarget::Config { subject } => {
            bounded(subject, "a config campaign names a bounded subject")?;
            None
        }
    };
    let policy = selection_policy_for(
        vault,
        &request.config.campaign_id,
        request.holder.as_deref(),
    )?;
    if let Some(seat) = &request.confirmation {
        let cohort = vault
            .eval_cohorts(&seat.seat)?
            .into_iter()
            .find(|cohort| cohort.id == seat.cohort)
            .ok_or(invalid("the confirmation cohort is not the seat's"))?;
        if cohort.retired_at.is_some() {
            return Err(invalid("a retired cohort cannot confirm a campaign"));
        }
    }
    let binding = ResearchBinding {
        root: request.root,
        run_id,
        config_sha256: sha256_json(&request.config, "campaign config cannot be serialized")?,
        config: request.config,
        target: request.target,
        goal,
        holder: request.holder,
        policy_digest: policy_digest(&policy)?,
        confirmation: request.confirmation,
        share: request.share,
        prior_ladder: request.prior_ladder,
        execution: request.execution,
        bound_at: at,
    };
    let root = ExperimentNode {
        attempt: request.root,
        kind: ExperimentKind::Root,
        parents: Vec::new(),
        candidate: request.incumbent,
        search: None,
        held_out: None,
        invalid: None,
        weave: None,
        pruned: None,
        recorded_at: at,
    };
    vault.with_write_txn_grouped(|txn| {
        if BINDING.contains(&vault.store, txn, request.root.as_bytes())? {
            return Err(invalid(
                "a campaign root binds once; its ruler is never rewritten",
            ));
        }
        BINDING.put(&vault.store, txn, request.root.as_bytes(), &binding)?;
        NODE.put(
            &vault.store,
            txn,
            &(*request.root.as_bytes(), *request.root.as_bytes()),
            &root,
        )?;
        Ok(binding)
    })
}

/// The binding of a campaign root, if bound.
/// # Errors
/// Storage errors.
pub fn research_binding(vault: &Vault, root: AttemptId) -> Result<Option<ResearchBinding>> {
    let txn = vault.store.env.read_txn()?;
    BINDING.get(&vault.store, &txn, root.as_bytes())
}

pub(in crate::autoreason_campaign) fn binding(
    vault: &Vault,
    root: AttemptId,
) -> Result<ResearchBinding> {
    research_binding(vault, root)?.ok_or(invalid("no campaign is bound to this root"))
}

pub(crate) fn has_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
) -> Result<bool> {
    BINDING.contains(&vault.store, txn, root.as_bytes())
}

pub(crate) fn binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
) -> Result<ResearchBinding> {
    BINDING
        .get(&vault.store, txn, root.as_bytes())?
        .ok_or(invalid("no campaign is bound to this root"))
}

pub(in crate::autoreason_campaign) fn nodes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
) -> Result<BTreeMap<[u8; 16], ExperimentNode>> {
    Ok(NODE
        .scan_from(&vault.store, txn, root.as_bytes())?
        .into_iter()
        .map(|((_, attempt), node)| (attempt, node))
        .collect())
}

/// Every experiment node of a campaign, in attempt order.
/// # Errors
/// Storage errors.
pub fn research_nodes(vault: &Vault, root: AttemptId) -> Result<Vec<ExperimentNode>> {
    let txn = vault.store.env.read_txn()?;
    Ok(nodes_in_txn(vault, &txn, root)?.into_values().collect())
}

/// Every selection round of a campaign, in round order.
/// # Errors
/// Storage errors.
pub fn research_rounds(vault: &Vault, root: AttemptId) -> Result<Vec<SelectionReceipt>> {
    let txn = vault.store.env.read_txn()?;
    Ok(ROUND
        .scan_from(&vault.store, &txn, root.as_bytes())?
        .into_iter()
        .map(|(_, round)| round)
        .collect())
}

/// Every bound campaign's root, in root order: the scheduler's worklist.
/// # Errors
/// Storage errors.
pub fn bound_research_roots(vault: &Vault) -> Result<Vec<AttemptId>> {
    let txn = vault.store.env.read_txn()?;
    BINDING
        .scan(&vault.store, &txn)?
        .into_iter()
        .map(|(root, _)| AttemptId::from_bytes(&root))
        .collect()
}
