//! PLAN-UC-04 2.4a: `ReceiptRef`, the one text form `{kind}:{lowercase hex}` of a receipt
//! reference. Its text must equal what each mint site writes today, so no stored row or
//! wire value changes; its parser takes only a known reference kind and lowercase hex of
//! that kind's width.
//!
//! PLAN-UC-04 2.5: the mint sites of `served_form`, `reference_refusal`, `task_lifecycle` and
//! `hook` now make their text through `ReceiptRef`. Each oracle below is that site's body on
//! main before 2.5 (ed80b5d804a), so this test is their K-proof: the text keeps its bytes.
//!
//! Run: `cargo test --locked -p oneiron-store --all-features --test receipt_ref`.

use oneiron_contracts::entity_id::{EntityId, bytes_to_hex_lower};
use oneiron_store::gate_decision::types::GateDecisionId;
use oneiron_store::receipt_ref::{ReceiptRef, ReceiptRefError};
use oneiron_store::receipt_row::{ReceiptKind, hex_lower};

/// Bytes that differ at every position, so a swapped or reversed id shows.
fn counting<const N: usize>(step: u8) -> [u8; N] {
    std::array::from_fn(|at| (at as u8).wrapping_mul(step).wrapping_add(1))
}

fn entity() -> EntityId {
    EntityId::from_bytes(counting::<16>(17)).expect("an unreserved id")
}

/// Every reference kind, with the text its mint site wrote on main before 2.5 (ed80b5d804a).
fn references() -> Vec<(ReceiptRef, String)> {
    let gate = GateDecisionId::from_bytes(counting::<16>(29));
    let id = entity();
    let run_key: [u8; 32] = counting::<32>(13);
    vec![
        // crates/oneiron-server/src/api/owner_routes/diary_routes.rs:217 and 91 more.
        (ReceiptRef::gate(gate), format!("gate:{}", gate.to_hex())),
        // crates/oneiron/src/receipt/served_form.rs:228 and its inline copy at
        // crates/oneiron/src/claim/scoped_read/served_forms.rs:46.
        (
            ReceiptRef::served_form(id),
            format!("served_form:{}", id.to_hex()),
        ),
        // crates/oneiron-store/src/reference_refusal.rs:116.
        (
            ReceiptRef::reference_refusal(id),
            format!("reference_refusal:{}", id.to_hex()),
        ),
        // crates/oneiron/src/task_verb/lifecycle_receipt.rs:77 (`RECEIPT_ID_PREFIX`, line 49).
        (
            ReceiptRef::task_lifecycle(id),
            format!("task_lifecycle:{}", id.to_hex()),
        ),
        // crates/oneiron/src/runtime_hooks/store.rs:500 (`crate::receipt::hex_lower`, which is
        // `oneiron_store::receipt_row::hex_lower`).
        (
            ReceiptRef::hook(run_key),
            format!("hook:{}", hex_lower(&run_key)),
        ),
    ]
}

#[test]
fn the_text_is_what_each_mint_site_writes() {
    for (reference, text) in references() {
        assert_eq!(reference.to_string(), text);
    }
}

/// The store's own mint fn, which 2.5 points at `ReceiptRef`, still writes its base text, for
/// the zero id, the all-`ff` id and two ids whose bytes differ at every position.
#[test]
fn the_store_mint_writes_its_base_text() {
    let ids = [
        [0x00; 16],
        [0xff; 16],
        counting::<16>(17),
        counting::<16>(251),
    ]
    .map(EntityId::from_bytes_unchecked);
    for id in ids {
        assert_eq!(
            oneiron_store::reference_refusal::receipt_id(&id),
            format!("reference_refusal:{}", id.to_hex()),
        );
    }
    // The hook text's hex is the store's `hex_lower`, the same digits as the contracts' encoder.
    let run_key: [u8; 32] = counting::<32>(13);
    assert_eq!(hex_lower(&run_key), bytes_to_hex_lower(&run_key));
}

#[test]
fn the_text_parses_back_to_the_same_reference() {
    let kinds = [
        ReceiptKind::Gate,
        ReceiptKind::ServedForm,
        ReceiptKind::ReferenceRefusal,
        ReceiptKind::TaskLifecycle,
        ReceiptKind::Hook,
    ];
    for ((reference, text), kind) in references().into_iter().zip(kinds) {
        let parsed: ReceiptRef = text.parse().expect("a reference");
        assert_eq!(parsed, reference);
        assert_eq!(parsed.kind(), kind);
        assert_eq!(parsed.to_string(), text);
        let width = if kind == ReceiptKind::Hook { 32 } else { 16 };
        assert_eq!(parsed.id_bytes().len(), width);
    }
}

#[test]
fn only_a_gate_reference_names_a_gate_decision() {
    let gate = GateDecisionId::from_bytes(counting::<16>(29));
    assert_eq!(ReceiptRef::gate(gate).gate_id(), Some(gate));
    let served = ReceiptRef::served_form(entity());
    assert_eq!(served.gate_id(), None);
    // The same 16 bytes under another kind are another reference.
    assert_ne!(
        ReceiptRef::gate(GateDecisionId::from_bytes(*entity().as_bytes())),
        served
    );
}

#[test]
fn anything_else_is_refused() {
    let hex16 = "0123456789abcdef0123456789abcdef";
    let hex32 = format!("{hex16}{hex16}");
    let cases: Vec<(String, ReceiptRefError)> = vec![
        ("gate".to_owned(), ReceiptRefError::NoKind),
        (String::new(), ReceiptRefError::NoKind),
        (format!("nope:{hex16}"), ReceiptRefError::UnknownKind),
        (format!("Gate:{hex16}"), ReceiptRefError::UnknownKind),
        (format!(":{hex16}"), ReceiptRefError::UnknownKind),
        (
            format!("outbound:{hex16}"),
            ReceiptRefError::NotAReferenceKind,
        ),
        (
            format!("inquiry:{hex32}"),
            ReceiptRefError::NotAReferenceKind,
        ),
        (format!("gate:{hex32}"), ReceiptRefError::BadId),
        (format!("hook:{hex16}"), ReceiptRefError::BadId),
        ("gate:".to_owned(), ReceiptRefError::BadId),
        (
            format!("gate:{}", hex16.to_uppercase()),
            ReceiptRefError::BadId,
        ),
        (format!("gate:{}g", &hex16[..31]), ReceiptRefError::BadId),
        (format!("gate:+{}", &hex16[..31]), ReceiptRefError::BadId),
        (format!("gate::{hex16}"), ReceiptRefError::BadId),
        (format!("gate:{hex16} "), ReceiptRefError::BadId),
    ];
    for (text, error) in cases {
        assert_eq!(text.parse::<ReceiptRef>(), Err(error), "text {text:?}");
    }
}
