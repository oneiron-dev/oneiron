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
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test gate_receipt_closed_outcome`.

#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::policy_model::{PolicyClassifyDecision, PolicyClassifyRequest};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::{EntityId, Vault, VaultConfig};

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
