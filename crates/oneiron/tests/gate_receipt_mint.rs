//! UC-03 PR 0: the one Gate receipt writer (fable/21 DESIGN §1). A caller's draft says the
//! outcome, kind, reasons, actor, handle and policy basis; the mint fills the id, the time, the
//! ledger version, the actor's class and ref, the policy version and the frontier.
//!
//! - every field a full draft names lands on the row the ledger holds, details first on the
//!   kind's channel;
//! - each actor form writes its class and ref, and each basis form its frontier and version
//!   (no policy read is 32 zero bytes);
//! - a fresh id comes from the store clock and rises; `created_at` is whole seconds on the
//!   recording clock; a bound id and a backdated decision are kept, and a bound id that is
//!   taken is refused.
//!
//! Red on main: main has no draft or mint, so the doors this file calls do not exist.

#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::store::{GateDecisionContext, GateDecisionId, GateSystemNoticeRecord};
use oneiron::test_doors::gate_receipt_rows as door;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A vault with install signing and its embedded owner.
fn vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    (dir, vault, owner)
}

#[test]
fn a_full_draft_lands_every_field_it_names() -> TestResult {
    let (_dir, vault, owner) = vault();
    let claim = EntityId::now();
    let before = vault.now_recorded_at();

    let row = door::record_full_receipt(&vault, owner, claim)?;

    let after = vault.now_recorded_at();
    assert_eq!(
        door::gate_row(&vault, row.decision_id)?.as_ref(),
        Some(&row),
        "the ledger holds the row the mint returned"
    );
    assert_eq!(row.version, 0);
    assert_eq!(row.outcome, "approved_amended");
    assert_eq!(row.reason_codes, [door::GUARD_REASON]);
    assert_eq!(row.receipt_reasons, [door::GUARD_RECEIPT_REASON]);
    let mut notices = GateSystemNoticeRecord::receipt_details(
        door::GUARD_KIND,
        vec!["first:1".to_owned(), "second:2".to_owned()],
    );
    notices.extend(GateSystemNoticeRecord::receipt_details(
        "uc03_other",
        vec!["third:3".to_owned()],
    ));
    assert_eq!(
        row.system_notices, notices,
        "the details on the kind's channel, then the notices"
    );
    assert_eq!(row.actor_class, "human");
    assert_eq!(row.actor_ref, Some(owner.to_hex()));
    assert_eq!(row.content_kind, door::GUARD_KIND);
    assert_eq!(row.policy_manifest_version, door::GUARD_POLICY_VERSION);
    assert_eq!(row.claim_id, Some(*claim.as_bytes()));
    assert_eq!(row.grant_ref.as_deref(), Some("uc03:guard"));
    assert_eq!(row.diff_handle, b"guard-handle");
    assert_eq!(row.read_frontier_hash, door::GUARD_FRONTIER);
    assert_eq!(row.context, GateDecisionContext::default());
    assert_eq!(row.redacted_at, None);
    assert!(
        (before..=after).contains(&row.created_at),
        "created_at {} is the recording clock in whole seconds, in [{before}, {after}]",
        row.created_at
    );
    Ok(())
}

#[test]
fn each_actor_form_writes_its_class_and_ref() -> TestResult {
    let (_dir, vault, owner) = vault();
    let agent = EntityId::now();

    let fields = door::minted_actor_fields(&vault, owner, agent)?;

    let expected: Vec<(String, Option<String>)> = vec![
        ("human".to_owned(), Some(owner.to_hex())),
        ("agent".to_owned(), Some(agent.to_hex())),
        ("system".to_owned(), None),
        ("policy_model".to_owned(), Some("plane:owner".to_owned())),
        ("booking.http_guard".to_owned(), None),
        (
            "pack-connection".to_owned(),
            Some("connection:1".to_owned()),
        ),
    ];
    assert_eq!(fields, expected);
    Ok(())
}

#[test]
fn each_basis_form_writes_its_frontier_and_version() -> TestResult {
    let (_dir, vault, _owner) = vault();

    let fields = door::minted_basis_fields(&vault)?;

    let expected: Vec<([u8; 32], String)> = vec![
        ([0; 32], "1.2".to_owned()),
        ([3; 32], "1.2".to_owned()),
        (door::GUARD_FRONTIER, door::GUARD_POLICY_VERSION.to_owned()),
        (door::GUARD_FRONTIER, door::GUARD_POLICY_VERSION.to_owned()),
    ];
    assert_eq!(
        fields, expected,
        "not read, a frontier, a versioned frontier, and the basis of that row"
    );
    Ok(())
}

#[test]
fn fresh_ids_rise_and_are_each_appended_once() -> TestResult {
    let (_dir, vault, _owner) = vault();

    let [first, second] = door::record_two_fresh_receipts(&vault)?;

    assert!(
        first.decision_id.as_bytes() < second.decision_id.as_bytes(),
        "the second id is past the first"
    );
    for row in [&first, &second] {
        assert_eq!(row.outcome, "noted");
        assert_eq!(door::gate_row(&vault, row.decision_id)?.as_ref(), Some(row));
    }
    Ok(())
}

#[test]
fn a_bound_id_and_an_earlier_decision_are_kept_and_a_taken_id_is_refused() -> TestResult {
    const DECIDED_AT: u64 = 1_600_000_000;
    let (_dir, vault, _owner) = vault();
    let bound = GateDecisionId::now();

    let row = door::record_bound_receipt(&vault, bound, DECIDED_AT)?;

    assert_eq!(row.decision_id, bound);
    assert_eq!(row.created_at, DECIDED_AT);
    assert_eq!(
        door::gate_row(&vault, bound)?.map(|held| held.created_at),
        Some(DECIDED_AT)
    );
    assert!(
        door::record_bound_receipt(&vault, bound, DECIDED_AT).is_err(),
        "a bound id another row holds is refused, not moved"
    );
    Ok(())
}
