use super::*;
use crate::error::Result;
use crate::skill_attribution::AttributionVerdict;

/// Rewrites one pack receipt as a run that closed with no executor stamp: the
/// stored shape of an attempt that never named its model
/// (`receipt/field_set.rs` writes `model` only when the attempt holds one).
fn strip_executor_stamp(vault: &Vault, receipt_id: &str) -> Result<()> {
    let mut receipt =
        crate::receipt::attempt_pack_receipt(vault, receipt_id)?.expect("stamped pack receipt");
    assert!(receipt.fields.remove("model").is_some());
    crate::receipt::overwrite_attempt_pack_receipt_for_test(vault, &receipt)
}

/// [JUDGE-SUPERSESSION-UNSTAMPED-EXECUTOR-REPROJECT-ERRS]: an unstamped
/// receipt trains no executor cell, so displacing its judge re-projects
/// nothing for it. The displacement it committed reports Ok, and the stamped
/// verdict judged after it still leaves its executor cell.
#[test]
fn displacing_a_judge_over_an_unstamped_receipt_reprojects_the_stamped_pair() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = EntityId::now();
    put_actor(&vault, &actor);
    let unstamped_skill = EntityId::now();
    put_active_import(&vault, &unstamped_skill, "sk05.unstamped");
    let stamped_skill = EntityId::now();
    put_active_import(&vault, &stamped_skill, "sk05.stamped");

    let unstamped = stamped_receipt_for_as_model(
        &vault,
        "sk05.unstamped",
        "1.0.0",
        Some(actor),
        Some("executor@1"),
    );
    strip_executor_stamp(&vault, &unstamped)?;
    let stamped = stamped_receipt_for_as_model(
        &vault,
        "sk05.stamped",
        "1.0.0",
        Some(actor),
        Some("executor@1"),
    );
    // The unstamped verdict is routed first, so its pair comes first in the
    // displacement's re-projection order.
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&unstamped, actor, AttemptOutcome::Failed, 30)
            .with_skill(unstamped_skill)
            .with_routing_facts(true, true),
    )?;
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&stamped, actor, AttemptOutcome::Failed, 31)
            .with_skill(stamped_skill)
            .with_routing_facts(true, true),
    )?;
    let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
    assert_eq!(judgments.len(), 2);
    assert!(
        judgments
            .iter()
            .all(|judgment| judgment.verdict == AttributionVerdict::SkillDefect)
    );
    assert_eq!(judgments[0].subject, Some(unstamped_skill));
    assert_eq!(judgments[1].subject, Some(stamped_skill));

    // Only the stamped verdict has an executor cell to train.
    project_skill_reliability(&vault, &judgments[1..])?;
    let query = reliability_query_for_receipt(&vault, &stamped);
    assert_eq!(
        skill_executor_reliability(&vault, &stamped_skill, "executor@1", &query)?.runs,
        1.0
    );

    let marked = crate::skill_attribution::supersede_displaced_judge_receipts(
        &vault,
        "rule-attribution@1",
        "replacement@2",
        32,
    )
    .expect("a committed displacement over an unstamped receipt reports Ok");
    let mut receipts: Vec<_> = marked.iter().map(|row| row.receipt_ref.as_str()).collect();
    receipts.sort_unstable();
    let mut expected = vec![unstamped.as_str(), stamped.as_str()];
    expected.sort_unstable();
    assert_eq!(receipts, expected);
    assert_eq!(
        skill_executor_reliability(&vault, &stamped_skill, "executor@1", &query)?.runs,
        0.0
    );
    Ok(())
}
