//! ONE-1762 (ED-06) unit tests: the ledger's round trip through the receipt
//! projection, aggregation per `(scope, trigger)` and its rebuild-from-receipts
//! identity, the stable-pattern proposal and the band ceiling that guards it,
//! and the one acceptance door.

use super::*;

use crate::error::GateError;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config())
}

const SCOPE: &str = "fan_out/consult";
const OTHER_SCOPE: &str = "send_email/client_followup";

fn ask(trigger: EscalationTrigger, ruling: EscalationRuling) -> EscalationReceipt {
    EscalationReceipt {
        task_ref: crate::test_util::entity(0x31),
        scope: SCOPE.to_owned(),
        trigger,
        question: "run this fan-out of nine consults?".to_owned(),
        ruling,
        rationale: "the peer list is the one we agreed".to_owned(),
        budget_band: None,
    }
}

/// Records `count` identical rulings on `(SCOPE, trigger)`, one per second so
/// receipt order is stable, returning their row handles in write order.
fn record_run(
    vault: &Vault,
    trigger: EscalationTrigger,
    ruling: &EscalationRuling,
    count: usize,
    first_at: u64,
) -> Vec<EntityId> {
    (0..count)
        .map(|index| {
            record_escalation_at(vault, ask(trigger, ruling.clone()), first_at + index as u64)
                .expect("record escalation")
        })
        .collect()
}

fn gate_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(1_000).with_kind(ReceiptKind::Gate))
        .expect("gate receipts")
}

fn policy_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    gate_receipts(vault)
        .into_iter()
        .filter(is_standing_policy_receipt)
        .collect()
}

fn field<'a>(record: &'a ReceiptRecord, key: &str) -> Option<&'a str> {
    record.fields.get(key).map(String::as_str)
}

// ---------------------------------------------------------------------------
// The acceptance door
// ---------------------------------------------------------------------------

#[test]
fn acceptance_is_the_only_door_and_it_is_receipted() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        3,
        1_000,
    );
    let row_ref = maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("stable pattern");

    // Proposed is not in force: the offer suppresses nothing.
    let proposed = standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy)
        .expect("read")
        .expect("row");
    assert_eq!(proposed.status, StandingPolicyStatus::Proposed);
    assert!(!proposed.covers_ask(None));
    let receipts = policy_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "proposed");
    assert_eq!(receipts[0].occurred_at, 5_000);
    assert_eq!(
        field(&receipts[0], FIELD_ESCALATION_CITED_RECEIPTS)
            .map(|joined| joined.split(CITED_RECEIPTS_SEPARATOR).count()),
        Some(3)
    );

    accept_standing_policy_at(&vault, &row_ref, 6_000).expect("accept");
    let accepted = standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy)
        .expect("read")
        .expect("row");
    assert_eq!(accepted.status, StandingPolicyStatus::Accepted);
    assert!(accepted.covers_ask(None));

    // The proposal receipt survives the acceptance: two acts, two records.
    let receipts = policy_receipts(&vault);
    assert_eq!(receipts.len(), 2);
    let outcomes: Vec<&str> = receipts
        .iter()
        .map(|record| record.outcome.as_str())
        .collect();
    assert!(outcomes.contains(&"proposed") && outcomes.contains(&"accepted"));

    // Re-accepting keeps the time the act happened.
    accept_standing_policy_at(&vault, &row_ref, 9_999).expect("idempotent accept");
    let accepted_receipt = policy_receipts(&vault)
        .into_iter()
        .find(|record| record.outcome == "accepted")
        .expect("acceptance receipt");
    assert_eq!(accepted_receipt.occurred_at, 6_000);
}

#[test]
fn accepting_an_unknown_row_ref_is_a_typed_refusal() {
    let (_dir, vault) = open_vault();
    let error = accept_standing_policy_at(&vault, &crate::test_util::entity(0x32), 6_000)
        .expect_err("no such row");
    assert!(matches!(
        error,
        Error::Gate(GateError::InvalidConsentBound(_))
    ));
}

// ---------------------------------------------------------------------------
// The ES-07 suppression read
// ---------------------------------------------------------------------------

#[test]
fn the_suppression_read_is_scope_and_trigger_exact() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        3,
        1_000,
    );
    let row_ref = maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("stable pattern");
    accept_standing_policy_at(&vault, &row_ref, 6_000).expect("accept");

    assert!(
        standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy)
            .expect("read")
            .is_some()
    );
    // A row for one trigger answers for that trigger and no other, and a row
    // for one scope answers for that scope and no other.
    assert!(
        standing_policy_for(&vault, SCOPE, EscalationTrigger::Unsure)
            .expect("read")
            .is_none()
    );
    assert!(
        standing_policy_for(&vault, OTHER_SCOPE, EscalationTrigger::Policy)
            .expect("read")
            .is_none()
    );
    // A scope the engine would refuse to record is refused on the read too,
    // rather than answering "no policy" for a question it cannot key.
    assert!(matches!(
        standing_policy_for(&vault, "  ", EscalationTrigger::Policy).expect_err("unusable scope"),
        Error::Gate(GateError::InvalidConsentBound(_))
    ));
}

#[test]
fn an_undecodable_policy_row_is_uncertainty_not_absence() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        3,
        1_000,
    );
    maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("stable pattern");

    // Corrupt the row in place. ES-07 maps the Err arm to "escalate", so the
    // distinction from `Ok(None)` — which means "ask, there is no policy" — is
    // load-bearing rather than cosmetic.
    vault
        .with_write_txn(|wtxn| {
            let key = ScopeTriggerKey {
                scope_digest: scope_key(SCOPE),
                trigger: EscalationTrigger::Policy,
            };
            vault.store.vault_meta.put(
                wtxn,
                &STANDING_POLICY.key_bytes(&key),
                b"not a policy row",
            )?;
            Ok(())
        })
        .expect("corrupt the row");

    assert!(matches!(
        standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy).expect_err("undecodable"),
        Error::CorruptedIndex(_)
    ));
}

// ---------------------------------------------------------------------------
// The family walk
// ---------------------------------------------------------------------------

/// Two fixture scopes in KEY order — the axis the projector walk runs along.
/// Which literal sorts first is a blake3 digest's business, so the fixture asks
/// instead of asserting.
fn scopes_in_key_order() -> (&'static str, &'static str) {
    const ONE: &str = "escalation/walk_a";
    const TWO: &str = "escalation/walk_b";
    if scope_key(ONE) < scope_key(TWO) {
        (ONE, TWO)
    } else {
        (TWO, ONE)
    }
}

#[test]
fn a_cap_sized_scope_cannot_hide_a_newer_ruling_under_a_lower_one() {
    // Ledger keys are scope-major, so a bounded prefix of KEY order is not a
    // bounded suffix of TIME order: one scope holding a scan cap's worth of
    // ancient rows used to spend the whole budget, and every ruling under a
    // lower-sorting scope became unprojectable — while `escalation_stats`,
    // which walks one scope's range uncapped, went on counting it. That gap is
    // the rebuild-from-receipts identity (CID-7) coming apart.
    let mut config = crate::test_util::embedding_test_config();
    // A cap-sized ledger outgrows the default test map.
    config.map_size = 512 * 1024 * 1024;
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let (low_scope, high_scope) = scopes_in_key_order();

    let filler = StoredEscalation {
        v: ROW_VERSION,
        task_ref: crate::test_util::entity(0x31).to_hex(),
        scope: high_scope.to_owned(),
        trigger: EscalationTrigger::Unsure.as_str().to_owned(),
        question: "q".to_owned(),
        ruling: EscalationRuling::Approve.as_str().to_owned(),
        delta: None,
        rationale: "r".to_owned(),
        budget_band: None,
        at: 1,
    };
    let data = encode_row(&filler, ESCALATION_ROW_LABEL).expect("encode");
    let filler_id = |index: u32| {
        let mut bytes = [0_u8; ENTITY_ID_LEN];
        // The index leads the id, so key order inside the scope is write order.
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        bytes[4] = 1;
        EntityId::from_bytes(bytes).expect("16 bytes is a well-formed entity id")
    };
    let cap = u32::try_from(crate::receipt::MAX_RECEIPT_QUERY_SCAN).expect("the cap fits in u32");
    vault
        .with_write_txn(|wtxn| {
            for index in 0..cap {
                vault.store.vault_meta.put(
                    wtxn,
                    &ESCALATION.key_bytes(&(scope_key(high_scope), filler_id(index))),
                    &data,
                )?;
            }
            Ok(())
        })
        .expect("plant a cap-sized scope");

    // The newest ruling in the vault, under the scope the digest put first.
    let recent = record_escalation_at(
        &vault,
        EscalationReceipt {
            scope: low_scope.to_owned(),
            ..ask(EscalationTrigger::Unsure, EscalationRuling::Deny)
        },
        9_000,
    )
    .expect("record escalation");

    assert_eq!(
        escalation_stats(&vault, low_scope, EscalationTrigger::Unsure)
            .expect("stats")
            .deny,
        1,
        "the fold counts the recent ruling"
    );
    // A tight result bound on purpose: what is under test is that the WALK is
    // exhaustive, not that the buffer is roomy.
    let projected = escalation_receipts(&vault, &ReceiptQuery::new(2)).expect("receipts");
    assert!(
        projected
            .iter()
            .any(|record| record.receipt_id == escalation_receipt_id(&recent)),
        "a cap-sized scope must not make a newer ruling under another scope unprojectable"
    );
    assert_eq!(projected.len(), 2, "the result is bounded by the query");
}
