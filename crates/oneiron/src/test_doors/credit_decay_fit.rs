//! Doors to the `credit_decay` fit (FIX-LIST
//! CREDIT-DECAY-FIT-DROPS-OWNER-AND-WORLD-ANCHORS): one credited outcome of
//! a run, and one matched contribution check on the used edge from the run's
//! output, recorded as the contribution admission records it once the run's
//! kept forks prove the pair. The pair carries its credit's anchor, as every
//! pair does (`credited_candidate_in_txn` requires it).

use crate::entity_id::EntityId;
use crate::learning::{Anchor, LearningCell, LearningPredicate, TypeRef};
use crate::learning_setting::global_setting_subject;
use crate::receipt::{ContributionCheck, CreditOptions, PackAttributionFields, UsedProvenanceEdge};
use crate::skill_attribution::{
    CheckedEdge, ContributionCheckRecord, ContributionFork, ContributionPair, LateCreditReceipt,
    contributed,
};
use crate::store::setting_seed::CREDIT_DECAY;
use crate::{Result, Vault};

/// The scored axis of the door's credited outcome.
const AXIS: &str = "quality";

/// The vault-wide fit's task type: the root of the vault's type tree.
fn root_type(vault: &Vault) -> Result<TypeRef> {
    Ok(TypeRef::root(
        crate::task_type::type_tree(vault, None)?.version(),
    ))
}

/// Credits one fresh run's outcome under `anchor`, then records one matched
/// check on the used edge from the run's output to an input: the fork with
/// that ancestor `with_ancestor_passed`, the fork without it
/// `without_ancestor_passed`. The run's output is a root of its credit, so
/// the edge is adjacent and the check observes `credit_decay`. The check's
/// receipt.
///
/// # Errors
///
/// The vault's.
pub fn credit_and_check_adjacent_edge(
    vault: &Vault,
    anchor: Anchor,
    with_ancestor_passed: bool,
    without_ancestor_passed: bool,
    now: u64,
) -> Result<String> {
    let pattern = EntityId::now();
    let output = EntityId::now();
    let input = EntityId::now();
    let attempt_receipt = format!("attempt:{}", EntityId::now().to_hex());
    let outcome_receipt = format!("outcome:{}", EntityId::now().to_hex());
    let fields = PackAttributionFields {
        type_ref: root_type(vault)?,
        executor: "executor@1".to_owned(),
        agent_definition: None,
        judge: Some("judge@1".to_owned()),
        pattern,
        team_shape: vec!["solo".to_owned()],
        decider: EntityId::now(),
        project: None,
        output: Some(output),
        contributions: Vec::new(),
        used_edges: vec![UsedProvenanceEdge {
            derived: output,
            source: input,
            check: None,
        }],
        credit: CreditOptions {
            enabled: true,
            depth_cap: None,
            check_every_hop: false,
        },
    };
    let credit = LateCreditReceipt {
        receipt_id: String::new(),
        attempt_receipt: attempt_receipt.clone(),
        outcome_receipt: outcome_receipt.clone(),
        anchor,
        succeeded: true,
        axis: AXIS.to_owned(),
        at: now,
        goal_revision: None,
        attribution: Some(fields),
        direct_subjects: Vec::new(),
        shares: Vec::new(),
    };
    let receipt = format!("contribution:{}", EntityId::now().to_hex());
    let record = ContributionCheckRecord {
        check: ContributionCheck {
            receipt: receipt.clone(),
            contributed: contributed(with_ancestor_passed, without_ancestor_passed),
        },
        pair: ContributionPair {
            attempt_receipt,
            outcome_receipt,
            skill: Some(pattern),
            edge: Some(CheckedEdge {
                derived: Some(output),
                source: Some(input),
            }),
            axis: AXIS.to_owned(),
            goal_revision: None,
            anchor,
            with_skill: ContributionFork {
                receipt: format!("fork:{}", EntityId::now().to_hex()),
                passed: with_ancestor_passed,
            },
            without_skill: ContributionFork {
                receipt: format!("fork:{}", EntityId::now().to_hex()),
                passed: without_ancestor_passed,
            },
            at: now,
        },
    };
    crate::skill_attribution::decay_fit_door::credit_and_record_ancestor_check(
        vault, &credit, &record, now,
    )?;
    Ok(receipt)
}

/// The vault-wide `credit_decay` fit's own effective runs, at the root of
/// the vault's type tree; `None` while no check fits it.
///
/// # Errors
///
/// The vault's.
pub fn credit_decay_fit_runs(vault: &Vault) -> Result<Option<f64>> {
    let cell = LearningCell::new(
        LearningPredicate::Setting,
        global_setting_subject(CREDIT_DECAY.key)?,
    )
    .setting_key(CREDIT_DECAY.key)
    .type_ref(root_type(vault)?)
    .project(None);
    Ok(crate::learning::learning_estimate(vault, &cell)?.map(|estimate| estimate.runs))
}
