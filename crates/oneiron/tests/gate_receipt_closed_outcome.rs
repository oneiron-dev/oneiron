//! UC-03 PR 1f-1: five families move their words (fable/21 DESIGN §2.3; RULING
//! UC-03-D1-RECEIPT-WORDS = A). A Gate row's outcome is one of the 12 closed words, and the
//! word its family wrote before stays on the row as a reason code:
//!
//! - an owner-plane block by the owner's own `decide` pattern reads `deny`, with the reasons
//!   `gate.policy_model.block` and `gate.policy_model.plane.owner_policy` (before:
//!   `owner_plane_block`);
//! - a run desktop's returned takeover reads `noted`, with the reasons
//!   `gate.sandbox.desktop_takeover` and `gate.sandbox.desktop_takeover.returned` (before:
//!   `returned`).
//!
//! Red on the base: the rows read `owner_plane_block` and `returned`.
//!
//! UC-03 PR 1f-2: the scattered arms move their words the same way:
//!
//! - an owner's consent denial reads `rejected`, with the reason `gate.consent.denied`
//!   (before: `denied`);
//! - the consent-denied detector still files that denial as a refusal fact (green on the base
//!   too: there it reads the row's old word, here its new one);
//! - a secret use its custody binding refuses reads `deny`, with the reason `gate.secret.use`
//!   (before: `denied`).
//!
//! Red on 1f-2's base: the two rows read `denied`.
//!
//! UC-03 PR 2-1a: readers read the outcome through one accessor,
//! `GateDecisionRecord::gate_outcome` and `ReceiptRecord::gate_outcome`. A row written
//! before stage 1f keeps its family's word; the accessor reads it as its writer's closed
//! word now (DESIGN section 2.3), so a reader gives the held row the answer it gave before:
//!
//! - a held `owner_plane_block` reads `deny`, on the row and on its receipt;
//! - `denied` reads `deny` on a secret use and `rejected` on a consent row, a bare `block`
//!   reads `rejected` on a policy hold and `deny` on another kind, a closed word reads as
//!   itself, and a word in neither table reads as none.
//!
//! Red on 2-1a's base by construction: it has no accessor and no held-row door.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test gate_receipt_closed_outcome`.

#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::{AuthenticatedOwner, CONSENT_REASON_DENIED, EffectDigest};
use oneiron::policy_model::{PolicyClassifyDecision, PolicyClassifyRequest};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::self_heal::DiagnosticObservation;
use oneiron::store::{GateDecisionId, GateDecisionRecord};
use oneiron::test_doors::gate_receipt_rows::{GUARD_KIND, append_held_word_row, gate_row};
use oneiron::test_doors::payment_credential::register_bound_secret;
use oneiron::verbs::{SecretUseRequest, use_secret_as_caller};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::gate_reason::GateReceiptOutcome;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    (dir, vault)
}

/// An owner plane switched on with one row, `owner:spoilers`, whose action is `block`, and one
/// `decide` pattern on it: the plane concludes without a model.
fn spoiler_block_manifest() -> Vec<u8> {
    let manifest = serde_json::json!({
        "schema_version": "1.2",
        "pack_id": "policy-model-test",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class": "human", "ceiling": "auto"}],
        "owner_policy_enabled": true,
        "owner_policy_rows": [{
            "row_ref": "owner:spoilers",
            "text": "Avoid spoilers in outbound content.",
            "action": "block",
            "active": true,
        }],
        "owner_policy_patterns": [{
            "id": "owner.spoilers",
            "pattern": "(?i)spoiler",
            "category": "owner:spoilers",
            "role": "decide",
        }],
    });
    rmp_serde::to_vec_named(&manifest).expect("a manifest body")
}

fn gate_rows(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))
        .expect("gate receipts")
}

fn has_reason(row: &ReceiptRecord, reason: &str) -> bool {
    row.policy_trace.iter().any(|trace| trace == reason)
}

#[test]
fn an_owner_plane_block_reads_deny_and_keeps_its_word_as_reasons() -> TestResult {
    let (_dir, vault) = vault();
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        EntityId::from_bytes([0x94; 16]).expect("a fixture id"),
        &spoiler_block_manifest(),
    )?;

    let verdict = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);

    let rows = gate_rows(&vault);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.outcome, "deny", "a closed word, not owner_plane_block");
    assert!(has_reason(row, "gate.policy_model.block"), "{row:?}");
    assert!(
        has_reason(row, "gate.policy_model.plane.owner_policy"),
        "{row:?}"
    );
    Ok(())
}

#[test]
fn a_returned_desktop_takeover_reads_noted_and_keeps_its_word_as_a_reason() -> TestResult {
    let (_dir, vault) = vault();
    let run = EntityId::from_bytes([0x51; 16]).expect("a fixture id");

    let receipt_ref =
        vault.append_desktop_takeover_receipt(run, &serde_json::json!({"held_by": "owner"}))?;

    let rows = gate_rows(&vault);
    let row = rows
        .iter()
        .find(|row| row.receipt_id == receipt_ref)
        .expect("the takeover's row");
    assert_eq!(row.outcome, "noted", "a closed word, not returned");
    assert!(has_reason(row, "gate.sandbox.desktop_takeover"), "{row:?}");
    assert!(
        has_reason(row, "gate.sandbox.desktop_takeover.returned"),
        "{row:?}"
    );
    Ok(())
}

/// An owned vault with its embedded owner and a device keystore.
fn owned_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    (dir, vault, owner)
}

fn owner_proof(vault: &Vault, owner: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// The owner's denial of one effect, and the Gate row it wrote.
fn owner_denial(
    vault: &Vault,
    owner: EntityId,
) -> Result<ReceiptRecord, Box<dyn std::error::Error>> {
    let denied = vault.deny_consent(
        &owner_proof(vault, owner),
        EffectDigest::from_bytes([0x1f; 32]),
    )?;
    let receipt_id = format!("gate:{}", denied.decision_id().to_hex());
    Ok(vault
        .receipts(ReceiptQuery::new(50).with_kind(ReceiptKind::Gate))?
        .into_iter()
        .find(|row| row.receipt_id == receipt_id)
        .expect("the denial's row"))
}

#[test]
fn an_owner_consent_denial_reads_rejected_and_keeps_its_word_as_a_reason() -> TestResult {
    let (_dir, vault, owner) = owned_vault();

    let row = owner_denial(&vault, owner)?;

    assert_eq!(row.outcome, "rejected", "a closed word, not denied");
    assert!(has_reason(&row, CONSENT_REASON_DENIED), "{row:?}");
    Ok(())
}

#[test]
fn the_consent_denied_detector_still_files_an_owner_denial() -> TestResult {
    let (_dir, vault, owner) = owned_vault();
    let row = owner_denial(&vault, owner)?;

    let observation = DiagnosticObservation::from_consent_receipt(&row)?
        .expect("an owner's denial is a refusal fact");

    assert_eq!(observation.kind, CONSENT_REASON_DENIED);
    assert_eq!(
        format!("gate:{}", observation.source_ref.to_hex()),
        row.receipt_id
    );
    Ok(())
}

#[test]
fn a_secret_use_its_binding_refuses_reads_deny() -> TestResult {
    let (_dir, vault, owner) = owned_vault();
    // Bound to one connector; the use names another connector's check.
    let secret = register_bound_secret(&vault, "shop", b"uc03-1f-2-value", "connector:shop")?;
    let handle = oneiron::retrieval_depth::short_ref_or_hex(&vault, &secret)?;

    let refused = use_secret_as_caller(
        &vault.memory(owner, EdgeActorClass::Human),
        SecretUseRequest {
            handle,
            operation: "slack.auth_test".to_owned(),
            arguments: serde_json::json!({}),
        },
    );
    assert!(
        refused.is_err(),
        "an effector the record does not bind is refused"
    );

    let rows: Vec<ReceiptRecord> = gate_rows(&vault)
        .into_iter()
        .filter(|row| row.fields.get("content_kind").map(String::as_str) == Some("secret_use"))
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].outcome, "deny", "a closed word, not denied");
    assert!(has_reason(&rows[0], "gate.secret.use"), "{rows:?}");
    Ok(())
}

/// The held row's own row and its receipt, each read through its accessor.
fn held_outcomes(
    vault: &Vault,
    held: &GateDecisionRecord,
) -> Result<(Option<GateReceiptOutcome>, Option<GateReceiptOutcome>), Box<dyn std::error::Error>> {
    let row = gate_row(vault, held.decision_id)?.ok_or("the held row")?;
    let receipt_id = format!("gate:{}", held.decision_id.to_hex());
    let receipt = vault
        .receipts(ReceiptQuery::new(50).with_kind(ReceiptKind::Gate))?
        .into_iter()
        .find(|receipt| receipt.receipt_id == receipt_id)
        .ok_or("the held row's receipt")?;
    Ok((row.gate_outcome(), receipt.gate_outcome()))
}

#[test]
fn a_held_owner_plane_block_reads_deny_through_the_accessor() -> TestResult {
    let (_dir, vault) = vault();
    let held = append_held_word_row(&vault, "owner_plane_block", GUARD_KIND)?;
    assert_eq!(held.outcome, "owner_plane_block", "the stored word stays");

    let (row, receipt) = held_outcomes(&vault, &held)?;
    assert_eq!(row, Some(GateReceiptOutcome::Deny), "the row");
    assert_eq!(receipt, Some(GateReceiptOutcome::Deny), "its receipt");
    Ok(())
}

#[test]
fn a_held_word_with_two_meanings_reads_by_its_kind() -> TestResult {
    let (_dir, vault) = vault();
    for (word, kind, outcome) in [
        ("denied", "secret_use", Some(GateReceiptOutcome::Deny)),
        (
            "denied",
            "consent_grant",
            Some(GateReceiptOutcome::Rejected),
        ),
        ("block", "policy_hold", Some(GateReceiptOutcome::Rejected)),
        ("block", GUARD_KIND, Some(GateReceiptOutcome::Deny)),
        ("approved", GUARD_KIND, Some(GateReceiptOutcome::Approved)),
        ("no_such_word", GUARD_KIND, None),
    ] {
        let held = append_held_word_row(&vault, word, kind)?;
        let (row, receipt) = held_outcomes(&vault, &held)?;
        assert_eq!(row, outcome, "the row: {word} on {kind}");
        assert_eq!(receipt, outcome, "its receipt: {word} on {kind}");
    }
    Ok(())
}
