use super::*;
use crate::dreamer_runner::{
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt, EnqueueDreamerSkillOptimizeAttempt,
};
use crate::test_util::{embedding_test_config, open_test_vault_with};
#[test]
fn micro_meso_and_skill_optimization_share_actor_and_receipt_ledger() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let runner = DreamerRunnerStore::new(&vault);
    let mut attempts = Vec::new();
    for scope in [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Meso,
    ] {
        attempts.push(
            runner.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
                scope,
                input: rmpv::Value::Nil,
                parent_attempt: None,
                dedupe_key: None,
                run_id: None,
                now: 10,
            })?,
        );
    }
    attempts.push(
        runner.enqueue_skill_optimize(EnqueueDreamerSkillOptimizeAttempt {
            input: rmpv::Value::Nil,
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })?,
    );
    let authority = vault.dreamer_authority()?;
    for outcome in attempts {
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        let stamp = vault.dreamer_attempt_authority(status.attempt.id)?.unwrap();
        assert_eq!(stamp.actor, authority.entity_ref());
        let envelope = vault.dreamer_proposal_envelope(&stamp.facet, status.attempt.id)?;
        assert_eq!(envelope.actor(), authority);
        assert_eq!(envelope.approval(), ClaimApprovalStatus::Proposed);
    }
    let records = vault.store.gate_decisions(100)?;
    let authority_records: Vec<_> = records
        .iter()
        .filter(|r| r.content_kind == "dreamer_authority")
        .collect();
    assert_eq!(authority_records.len(), 3);
    assert!(
        authority_records
            .iter()
            .all(|r| r.actor_ref.as_deref() == Some(&authority.entity_ref().to_hex()))
    );
    assert_eq!(vault.dreamer_authority()?, authority);
    let (_other_dir, other_node) = open_test_vault_with(embedding_test_config());
    assert_eq!(other_node.dreamer_authority()?, authority);
    Ok(())
}
