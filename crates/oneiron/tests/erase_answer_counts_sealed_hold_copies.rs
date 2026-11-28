//! The erase answer counts only sealed hold copies (H5R1 T10): a host order
//! with no sealed capture counts no kept copy; a customer hold on the same
//! record counts one. Entry asserts compare code AND full text against the
//! ruled literals. Fixtures copy H5's `hold_fixture`/`hold_named_row`/
//! `preview_and_erase` and `company_hold_inquiry_copy.rs` host-order placement.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test erase_answer_counts_sealed_hold_copies`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::HostingPrivacyPosture;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::HostOrderHold;
use oneiron::deletion::LegalHoldKind;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    OwnerConfirmPreviewRequest, RecordEraseConfirmRequest, RecordEraseOutcome,
    confirm_record_erase, preview_owner_confirm,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const ERASE: &str = "vault.records.erase_confirm";

/// A device keystore with install signing on `vault`, and its embedded
/// owner's proof.
fn hold_owner_on(vault: &Vault) -> (EntityId, AuthenticatedOwner) {
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (actor, owner)
}

/// An owned vault whose hold store lies outside its directory, with the
/// embedded owner's proof. Hosted, so it takes a host order as well as a
/// customer hold.
struct HoldFixture {
    _vault_dir: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn hold_fixture() -> HoldFixture {
    let vault_dir = tempfile::tempdir().expect("vault dir");
    let store_dir = tempfile::tempdir().expect("hold store dir");
    let mut config = VaultConfig::device().with_legal_hold_store(store_dir.path().to_path_buf());
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open_owned(vault_dir.path(), config).expect("open owned");
    let (actor, owner) = hold_owner_on(&vault);
    HoldFixture {
        _vault_dir: vault_dir,
        _store_dir: store_dir,
        vault,
        actor,
        owner,
    }
}

/// A PERSON row named `name` at a fresh id.
fn hold_named_row(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name })).expect("encode row");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .expect("put a fixture row");
    id
}

/// The owner previews the erase of `record` through the shared preview,
/// then confirms it: the preview's shown JSON (P) and the confirm's answer
/// (R).
fn preview_and_erase(
    memory: &Memory<'_>,
    owner_proof: &AuthenticatedOwner,
    record: EntityId,
) -> (Value, RecordEraseOutcome) {
    let input = RecordEraseConfirmRequest {
        record,
        confirm: None,
        also_same_bytes: false,
        check_in_ref: None,
    };
    let preview = preview_owner_confirm(
        memory,
        owner_proof,
        OwnerConfirmPreviewRequest {
            verb: ERASE.to_owned(),
            input: serde_json::to_value(&input).expect("the erase input encodes"),
        },
    )
    .expect("the owner previews the erase");
    let takes = preview
        .takes
        .expect("a record erase preview shows what the erase takes");
    let outcome = confirm_record_erase(
        memory,
        owner_proof,
        RecordEraseConfirmRequest {
            confirm: Some(preview.confirm),
            ..input
        },
    )
    .expect("the owner confirms the erase");
    assert_eq!(
        outcome.first.state,
        oneiron::memory::DeleteRequestState::Applied,
        "the erase applies: {outcome:?}"
    );
    (takes, outcome)
}

/// The `remaining` array of a shown JSON as (code, text) pairs, in order.
fn remaining_of(shown: &Value) -> Vec<(String, String)> {
    shown
        .get("remaining")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            (
                entry
                    .get("code")
                    .and_then(|code| code.as_str())
                    .expect("a remaining entry's code")
                    .to_owned(),
                entry
                    .get("text")
                    .and_then(|text| text.as_str())
                    .expect("a remaining entry's text")
                    .to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_host_order_with_no_sealed_capture_counts_no_kept_copy() {
    // One hosted vault, one host order naming two live records. An applied
    // receipt consumes its record, so the host-only record is erased first
    // (case 1) and the customer hold joins the second record afterwards
    // (case 2), already targeted by the same host order.
    let fixture = hold_fixture();
    let host_only = hold_named_row(&fixture.vault, "host-only record");
    let held = hold_named_row(&fixture.vault, "held record");
    let order = HostOrderHold {
        targets: vec![
            LegalHoldTarget::Record(host_only),
            LegalHoldTarget::Record(held),
        ],
        order_ref: "order-1".to_owned(),
        ends_at: fixture.vault.now_recorded_at() + 3_600,
        secret_until: None,
        placed_by: "host-operator".to_owned(),
        legal_basis_ref: None,
        jurisdiction: None,
        issuing_authority_ref: None,
        requires_non_use: false,
    };
    let host_hold = fixture
        .vault
        .place_host_order_hold(order)
        .expect("the host order");
    assert_eq!(
        host_hold.kind,
        LegalHoldKind::HostOrder,
        "the host order is a host order: {host_hold:?}"
    );
    assert!(
        host_hold.clone_captures.is_empty(),
        "a host order keeps no sealed capture: {host_hold:?}"
    );
    let memory = fixture.vault.memory(fixture.actor, EdgeActorClass::Human);
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, host_only);
    assert!(
        !remaining_of(&takes)
            .iter()
            .any(|(code, _)| code == "legal_hold_copy"),
        "a host order alone lists no hold copy in P: {takes}"
    );
    assert!(
        takes.get("legal_copies_kept").is_none(),
        "a host order alone counts nothing in P: {takes}"
    );
    assert!(
        !outcome
            .remaining
            .iter()
            .any(|notice| notice.code == "legal_hold_copy"),
        "a host order alone lists no hold copy in R: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).expect("the outcome encodes");
    assert!(
        receipt.get("legal_copies_kept").is_none(),
        "a host order alone counts nothing in R: {receipt}"
    );

    let customer_hold = fixture
        .vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            None,
        )
        .expect("the customer hold");
    assert_eq!(
        customer_hold.kind,
        LegalHoldKind::Customer,
        "the customer hold is a customer hold: {customer_hold:?}"
    );
    assert!(
        !customer_hold.clone_captures.is_empty(),
        "a customer hold seals its record: {customer_hold:?}"
    );
    let (takes, outcome) = preview_and_erase(&memory, &fixture.owner, held);
    let preview = remaining_of(&takes);
    let entries: Vec<_> = preview
        .iter()
        .filter(|(code, _)| code == "legal_hold_copy")
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "P lists the one sealed copy once: {takes}"
    );
    assert_eq!(
        entries[0].1,
        "A legal hold keeps a sealed copy of this record outside your vault until the hold is lifted. This erase does not remove that copy.",
        "{takes}"
    );
    assert_eq!(
        takes.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "P counts the one sealed copy, not the host order: {takes}"
    );
    let entries: Vec<_> = outcome
        .remaining
        .iter()
        .filter(|notice| notice.code == "legal_hold_copy")
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "R lists the one sealed copy once: {outcome:?}"
    );
    assert_eq!(
        entries[0].text,
        "A legal hold keeps a sealed copy of this record outside your vault until the hold is lifted. This erase does not remove that copy.",
        "{outcome:?}"
    );
    assert!(
        !outcome
            .first
            .remaining
            .iter()
            .any(|notice| notice.code == "legal_hold_copy"),
        "the hold copy is erase-level, not the receipt's: {outcome:?}"
    );
    let receipt = serde_json::to_value(&outcome).expect("the outcome encodes");
    assert_eq!(
        receipt.get("legal_copies_kept"),
        Some(&Value::from(1)),
        "R counts the one sealed copy, not the host order: {receipt}"
    );
}
