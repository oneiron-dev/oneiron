//! PLAN-UC-04 2.4a: `ReceiptRef`, the one text form `{kind}:{lowercase hex}` of a receipt
//! reference. Its text must equal what each mint site writes today, so no stored row or
//! wire value changes; its parser takes only a known reference kind and lowercase hex of
//! that kind's width.
//!
//! Run: `cargo test --locked -p oneiron-store --all-features --test receipt_ref`.

use oneiron_contracts::entity_id::{EntityId, bytes_to_hex_lower};
use oneiron_store::gate_decision::types::GateDecisionId;
use oneiron_store::receipt_ref::{ReceiptRef, ReceiptRefError};
use oneiron_store::receipt_row::ReceiptKind;

/// Bytes that differ at every position, so a swapped or reversed id shows.
fn counting<const N: usize>(step: u8) -> [u8; N] {
    std::array::from_fn(|at| (at as u8).wrapping_mul(step).wrapping_add(1))
}

fn entity() -> EntityId {
    EntityId::from_bytes(counting::<16>(17)).expect("an unreserved id")
}

/// Every reference kind, with the text its mint site writes on main.
fn references() -> Vec<(ReceiptRef, String)> {
    let gate = GateDecisionId::from_bytes(counting::<16>(29));
    let id = entity();
    let run_key: [u8; 32] = counting::<32>(13);
    vec![
        // crates/oneiron-server/src/api/owner_routes/diary_routes.rs:217 and 91 more.
        (ReceiptRef::gate(gate), format!("gate:{}", gate.to_hex())),
        // crates/oneiron/src/receipt/served_form.rs:228.
        (
            ReceiptRef::served_form(id),
            format!("served_form:{}", id.to_hex()),
        ),
        // crates/oneiron-store/src/reference_refusal.rs:116, called itself.
        (
            ReceiptRef::reference_refusal(id),
            oneiron_store::reference_refusal::receipt_id(&id),
        ),
        // crates/oneiron/src/task_verb/lifecycle_receipt.rs:77.
        (
            ReceiptRef::task_lifecycle(id),
            format!("task_lifecycle:{}", id.to_hex()),
        ),
        // crates/oneiron/src/runtime_hooks/store.rs:534 (`hex_lower`, lowercase).
        (
            ReceiptRef::hook(run_key),
            format!("hook:{}", bytes_to_hex_lower(&run_key)),
        ),
    ]
}

#[test]
fn the_text_is_what_each_mint_site_writes() {
    for (reference, text) in references() {
        assert_eq!(reference.to_string(), text);
    }
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
