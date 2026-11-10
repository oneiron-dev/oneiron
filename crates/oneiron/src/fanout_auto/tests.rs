//! ONE-1720 (ES-07) unit tests: the closed verdict vocabulary, the fixed
//! evaluation order (blank-context floor, ED's typed standing read, the budget
//! ceiling, then the classifier), the adapter that has no kill arm, and the
//! human-ruling round trip through ED-06's own receipt and proposal machinery.
//!
//! Everything a classifier does here is in-process: a recording fixture with a
//! pinned answer and an invocation counter. No model, no network, no
//! credentials. Every storage write goes through ONE-1762's public API,
//! because ONE-1720 owns no storage.
//!
//! Three of these tests are RE-HOMED from `tests/it/effect_spine_oracle.rs`
//! under their original names. `outbound_chokepoint` is `pub(crate)`, so
//! ONE-1719's plan, estimate, and decider are neither nameable nor
//! constructible from an integration-test crate and those arms could only ever
//! live in-crate. Their doc comments carry the old-assert to new-assert map.

use super::*;

use crate::edit_distance::escalation::is_escalation_receipt;
use crate::receipt::{ReceiptKind, ReceiptQuery};

const SCOPE: &str = "fan_out/consult";
const QUESTION: &str = "may this fan-out of 240 consults start?";
const RATIONALE: &str = "the peer list is the one we agreed";

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config())
}

// ---------------------------------------------------------------------------
// Plan / estimate fixtures
// ---------------------------------------------------------------------------

fn context(scope: &str, trigger: FanoutAskTrigger) -> FanoutAskContext {
    FanoutAskContext {
        task_ref: crate::test_util::entity(0x72),
        scope: scope.to_owned(),
        trigger,
        question: QUESTION.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Recording a human ruling
// ---------------------------------------------------------------------------

#[test]
fn projector_failure_keeps_receipt_resolvable_without_committing_policy() -> Result<()> {
    let (_dir, vault) = open_vault();
    let ask = context(SCOPE, FanoutAskTrigger::Unsure);
    for _ in 0..2 {
        let applied = apply_escalation_ruling(
            &vault,
            &ask,
            FanoutEscalationRuling::Approve,
            RATIONALE.to_owned(),
        )?;
        assert_eq!(applied.proposal, FanoutProposalOutcome::NotProposed);
    }
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(
            txn,
            crate::side_table::EDIT_DISTANCE_ESCALATION_STANDING_N.prefix,
            &[3],
        )?;
        Ok(())
    })?;
    let applied = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )?;
    assert!(matches!(applied.proposal, FanoutProposalOutcome::Failed(_)));
    let receipt_id = format!("escalation:{}", applied.receipt_ref.to_hex());
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    let receipt = receipts
        .iter()
        .find(|r| r.receipt_id == receipt_id)
        .expect("the successful ruling survives projector failure");
    assert_eq!(receipt.outcome, "approve");
    assert_eq!(
        receipts.iter().filter(|r| is_escalation_receipt(r)).count(),
        3
    );
    assert!(standing_policy_for(&vault, SCOPE, EscalationTrigger::Unsure)?.is_none());
    crate::edit_distance::escalation::set_escalation_standing_n(&vault, 3)?;
    assert!(standing_policy_for(&vault, SCOPE, EscalationTrigger::Unsure)?.is_none());
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    assert!(receipts.iter().any(|r| r.receipt_id == receipt_id));
    Ok(())
}
