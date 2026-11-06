//! Pre-score basis and scoring inputs from the original write snapshot.

use super::sources::observe_sources;
use super::*;

/// The scoring inputs beside the native rows this subphase reads. The supplied
/// staged/current records and earlier owner/judge checks are not certified here.
#[expect(
    clippy::too_many_arguments,
    reason = "the subphase keeps the original gate inputs explicit"
)]
pub(super) fn score_inputs_sourced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &EntityId,
    staged: SkillRecord,
    current: Option<SkillRecord>,
    target: EntityId,
    cycle: &SkillEditCycle,
    judge_revision: &str,
) -> Result<(Prepared, Option<Vec<EntityId>>)> {
    let mut sources = Some(Vec::new());
    let current = current.ok_or(Error::InvariantViolation(
        "a non-terminal pre-score snapshot has a readable target",
    ))?;
    let held_out = observe_sources(
        &mut sources,
        super::super::basis::held_out_evidence_sourced_in_txn(vault, txn, &target)?,
    );
    // An empty reserve is not an answer ABOUT the proposal, so it
    // does not close one. The gate scores against reserved
    // evidence; a skill whose split has reserved none yet cannot be
    // scored at all, and the drafting door already refuses to spend
    // an author on one ([`crate::skill_optimize::optimize_candidates`]).
    // What is left here is the race and the direct call, and for
    // both the honest outcome is the retryable abort: nothing is
    // scored, nothing is written, and the question stays open for
    // the wake that finds a reserve.
    if held_out.is_empty() {
        return Err(retry(
            "no evidence is reserved for this skill, so there is nothing to score",
        ));
    }
    let outcomes = observe_sources(
        &mut sources,
        super::super::basis::held_out_outcome_results_sourced_in_txn(vault, txn, &target)?,
    );
    let basis = ScoredBasis::of(
        &staged,
        &current,
        &held_out,
        &outcomes,
        observe_sources(
            &mut sources,
            crate::skill_optimize::tier::tier_verdict_sourced_in_txn(vault, txn, proposal, &staged)
                .map(|(tier, rows)| (tier, Some(rows)))?,
        )
        .tier(),
        observe_sources(
            &mut sources,
            super::super::goal_axis::goal_definition_sourced_in_txn(vault, txn, &target)?,
        )
        .revision,
        observe_sources(
            &mut sources,
            super::super::goal_axis::goal_definition_sourced_in_txn(vault, txn, &target)?,
        )
        .goal_id,
    )?;
    // Idempotence, before the LLM tier rather than after it. A gate
    // call is a DELIVERY, and deliveries are retried; asking the
    // judge the same question twice would not only pay twice, it
    // would answer differently, because the first ruling has by
    // then moved the cap the second call is measured against.
    let standing = observe_sources(
        &mut sources,
        super::sources::standing_ruling_sourced_in_txn(
            vault,
            txn,
            proposal,
            &basis,
            cycle,
            judge_revision,
        )?,
    );
    if let Some(standing) = standing {
        return Ok((Prepared::Ruled(Box::new(standing)), sources));
    }
    Ok((
        Prepared::Score(Box::new(ScoreInputs {
            judge_rubric_digest: observe_sources(
                &mut sources,
                super::super::judge_binding::judge_rubric_digest_sourced_in_txn(vault, txn)?,
            ),
            outcomes,
            proposal_instructions: observe_sources(
                &mut sources,
                super::super::rule_policy::gate_instructions_sourced_in_txn(
                    vault, txn, proposal, &staged,
                ),
            ),
            target_instructions: observe_sources(
                &mut sources,
                super::super::rule_policy::gate_instructions_sourced_in_txn(
                    vault, txn, &target, &current,
                ),
            ),
            proposal: staged,
            target,
            target_record: current,
            held_out,
            basis,
            goal_definition: observe_sources(
                &mut sources,
                super::super::goal_axis::goal_definition_sourced_in_txn(vault, txn, &target)?,
            ),
        })),
        sources,
    ))
}
