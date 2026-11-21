//! UC-09 PR A (FIX ATTEMPT-RECEIPT-PARSER-FOUR-COPIES): the attempt a
//! terminal PACK RECEIPT id names is read back by one fn,
//! `oneiron::receipt::parse_attempt_pack_receipt_id`, the inverse of
//! `attempt_pack_receipt_id`. Before it, five modules each held a copy
//! (skill attribution's credit join and trace, the frozen-call erase, the
//! code-run contribution and the self-heal audit contract), and the archive
//! read checked the same rule inline.
//!
//! Vaults hold these ids (attribution evidence cites them), so the one fn must
//! accept exactly the set the copies accepted. This file is a pin, not a
//! failing-first test: it passes at the commit before the move (through a
//! scratch shim that runs every old copy and asserts they agree) and at its
//! head. Run:
//! `cargo test --locked -p oneiron --all-features --test attempt_receipt_parse`.

use oneiron::attempt_queue::AttemptId;
use oneiron::receipt::{attempt_pack_receipt_id, parse_attempt_pack_receipt_id};

fn attempt(bytes: [u8; 16]) -> AttemptId {
    AttemptId::from_bytes(&bytes).expect("16 bytes")
}

/// The 32 hex digits of `id`, as the receipt id spells them.
fn hex_of(id: &AttemptId) -> String {
    let receipt = attempt_pack_receipt_id(id);
    receipt
        .strip_prefix("attempt:")
        .expect("the attempt: prefix")
        .to_owned()
}

#[test]
fn a_receipt_id_names_its_attempt() {
    let mut ids = vec![AttemptId::now(), AttemptId::now(), AttemptId::now()];
    ids.push(attempt([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ]));
    ids.push(attempt([0x7f; 16]));
    for id in ids {
        let receipt = attempt_pack_receipt_id(&id);
        assert_eq!(
            parse_attempt_pack_receipt_id(&receipt),
            Some(id),
            "{receipt} names its attempt"
        );
    }
}

#[test]
fn the_receipt_id_spelling_is_the_attempt_prefix_and_lowercase_hex() {
    let id = attempt([
        0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc,
    ]);
    assert_eq!(
        attempt_pack_receipt_id(&id),
        "attempt:abcdef00112233445566778899aabbcc"
    );
}

#[test]
fn another_spelling_of_the_same_attempt_names_none() {
    let id = AttemptId::now();
    let hex = hex_of(&id);
    let upper = hex.to_uppercase();
    let mut mixed = hex.clone();
    mixed.replace_range(0..1, &hex[0..1].to_uppercase());
    // `mixed` differs from `hex` only when the first digit is a letter.
    let mixed = if mixed == hex {
        format!("A{}", &hex[1..])
    } else {
        mixed
    };
    let refused = [
        format!("attempt:{upper}"),
        format!("attempt:{mixed}"),
        format!("Attempt:{hex}"),
        format!("ATTEMPT:{hex}"),
        format!("attempts:{hex}"),
        format!("pack:{hex}"),
        format!(":{hex}"),
        hex.clone(),
        format!("attempt::{hex}"),
        format!("attempt:x:{hex}"),
        format!("x:attempt:{hex}"),
        format!(" attempt:{hex}"),
        format!("attempt:{hex} "),
        format!("attempt:+{}", &hex[1..]),
        format!("attempt:{}", &hex[1..]),
        format!("attempt:{hex}0"),
        format!("attempt:{hex}:"),
        "attempt:".to_owned(),
        String::new(),
    ];
    for receipt in refused {
        assert_eq!(
            parse_attempt_pack_receipt_id(&receipt),
            None,
            "{receipt:?} names no attempt"
        );
    }
}

#[test]
fn a_reserved_entity_id_names_no_attempt() {
    let mut legacy_counter = [0xff_u8; 16];
    legacy_counter[0] = 0x01;
    for bytes in [[0x00_u8; 16], [0xff_u8; 16], legacy_counter] {
        let receipt = attempt_pack_receipt_id(&attempt(bytes));
        assert_eq!(
            parse_attempt_pack_receipt_id(&receipt),
            None,
            "{receipt} is a reserved id"
        );
    }
}
