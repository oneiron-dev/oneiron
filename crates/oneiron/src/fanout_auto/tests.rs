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

use crate::edit_distance::escalation::{is_escalation_receipt, record_escalation_at};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};

const SCOPE: &str = "fan_out/consult";
const QUESTION: &str = "may this fan-out of 240 consults start?";
const RATIONALE: &str = "the peer list is the one we agreed";

/// One byte past ED's scope bound, so its typed standing read fails the way an
/// unreadable row does: with `Err`, not `Ok(None)`.
const OVERLONG_SCOPE_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN + 1;

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
// Storage fixtures — every write goes through ONE-1762's public API
// ---------------------------------------------------------------------------

fn record(
    vault: &Vault,
    scope: &str,
    trigger: EscalationTrigger,
    ruling: &EscalationRuling,
    band: Option<u64>,
    at: u64,
) -> EntityId {
    record_escalation_at(
        vault,
        EscalationReceipt {
            task_ref: crate::test_util::entity(0x71),
            scope: scope.to_owned(),
            trigger,
            question: QUESTION.to_owned(),
            ruling: ruling.clone(),
            rationale: RATIONALE.to_owned(),
            budget_band: band,
        },
        at,
    )
    .expect("ED records the ruling")
}

fn standing_row(vault: &Vault, scope: &str, trigger: EscalationTrigger) -> Option<StandingPolicy> {
    standing_policy_for(vault, scope, trigger).expect("ED's typed standing read")
}

/// Overwrites every stored row whose bytes carry `marker`, so ED's typed read
/// of that range fails. The rows are found by the content ONE-1762 wrote, not
/// by a key prefix duplicated out of ED's private keyspace.
fn corrupt_rows_carrying(vault: &Vault, marker: &str) {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        for entry in vault.store.vault_meta.iter(&rtxn).expect("scan vault meta") {
            let (key, raw) = entry.expect("vault meta row");
            if raw
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
            {
                keys.push(key.to_vec());
            }
        }
    }
    assert!(!keys.is_empty(), "the fixture wrote a row to corrupt");
    vault
        .with_write_txn(|wtxn| {
            for key in &keys {
                vault
                    .store
                    .vault_meta
                    .put(wtxn, key, b"not a stored escalation row")?;
            }
            Ok(())
        })
        .expect("corrupt the stored rows");
}

fn gate_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(1_000).with_kind(ReceiptKind::Gate))
        .expect("gate receipts")
}

fn escalation_receipt_count(vault: &Vault) -> usize {
    gate_receipts(vault)
        .into_iter()
        .filter(is_escalation_receipt)
        .count()
}

// ---------------------------------------------------------------------------
// Recording a human ruling
// ---------------------------------------------------------------------------

#[test]
fn proposal_outcome_preserves_partial_success() {
    let (_dir, vault) = open_vault();
    let ask = context(SCOPE, FanoutAskTrigger::Unsure);

    // `Ok(None)` -> NotProposed.
    let first = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    assert_eq!(first.proposal, FanoutProposalOutcome::NotProposed);

    // `Ok(Some(id))` -> Proposed(id).
    apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    let third = apply_escalation_ruling(
        &vault,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the ruling records");
    let row_ref = match &third.proposal {
        FanoutProposalOutcome::Proposed(row_ref) => *row_ref,
        other => panic!("the third agreeing ruling proposes a row, not {other:?}"),
    };
    assert_eq!(
        standing_row(&vault, SCOPE, EscalationTrigger::Unsure)
            .expect("the proposed row")
            .row_ref,
        row_ref
    );

    // Only a failure BEFORE the receipt commits is `Err`, and it persists
    // nothing.
    let receipts_before = escalation_receipt_count(&vault);
    let mut blank = context(SCOPE, FanoutAskTrigger::Unsure);
    blank.scope = "  ".to_owned();
    assert!(
        apply_escalation_ruling(
            &vault,
            &blank,
            FanoutEscalationRuling::Approve,
            RATIONALE.to_owned(),
        )
        .is_err()
    );
    assert!(
        apply_escalation_ruling(
            &vault,
            &ask,
            FanoutEscalationRuling::Approve,
            "   ".to_owned(),
        )
        .is_err()
    );
    let unwritable = context(&"x".repeat(OVERLONG_SCOPE_LEN), FanoutAskTrigger::Unsure);
    assert!(
        apply_escalation_ruling(
            &vault,
            &unwritable,
            FanoutEscalationRuling::Approve,
            RATIONALE.to_owned(),
        )
        .is_err(),
        "a scope ED's ledger refuses returns Err with nothing persisted"
    );
    assert_eq!(escalation_receipt_count(&vault), receipts_before);

    // `Err` from the projector AFTER the receipt commits -> Failed(rendered),
    // and the caller still holds the committed receipt.
    let (_broken_dir, broken) = open_vault();
    record(
        &broken,
        SCOPE,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        None,
        1_000,
    );
    corrupt_rows_carrying(&broken, QUESTION);
    let partial = apply_escalation_ruling(
        &broken,
        &ask,
        FanoutEscalationRuling::Approve,
        RATIONALE.to_owned(),
    )
    .expect("the receipt still commits");
    match &partial.proposal {
        FanoutProposalOutcome::Failed(rendered) => assert!(
            !rendered.is_empty(),
            "the projector failure is rendered, not swallowed"
        ),
        other => panic!("an unreadable ledger fails the projector, not {other:?}"),
    }
}
