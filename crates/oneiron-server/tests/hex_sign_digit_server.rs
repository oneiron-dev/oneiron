#![cfg(oneiron_test_support)]
//! UC-07 PR 7, HEX-PR6-SIGN-SITES = B: a `+` hex digit is refused at the 3 server decoders,
//! reached through `oneiron_server::test_doors::hex_sign_digit`. Each test
//! asserts the NEW behaviour: valid lowercase still decodes to the same bytes
//! (control), `+a` for the first pair is refused, and either-case sites still
//! decode uppercase (stored/wire sites refuse it). Every test fails today
//! (red) and passes after the bodies move onto `oneiron-hex`. The doors are
//! pure and need no crate features, so this target takes no `[[test]]`
//! stanza.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test hex_sign_digit_server`.

use oneiron_server::test_doors::hex_sign_digit as doors;

/// `chars` lowercase hex digits of neutral values (`chars` is a multiple of 16).
fn hex_pattern(chars: usize) -> String {
    "0123456789abcdef".repeat(chars / 16)
}

/// `valid` with `+a` in place of its first digit pair.
fn with_sign(valid: &str) -> String {
    format!("+a{}", &valid[2..])
}

#[test]
fn managed_owner_id_refuses_a_sign_but_keeps_uppercase() {
    let valid = hex_pattern(64);
    let expected = oneiron_hex::decode_any_case::<32>(&valid).unwrap();
    assert_eq!(doors::managed_owner_id_from_hex(&valid), Some(expected));
    assert_eq!(doors::managed_owner_id_from_hex(&with_sign(&valid)), None);
    assert_eq!(
        doors::managed_owner_id_from_hex(&valid.to_uppercase()),
        Some(expected)
    );
}

#[test]
fn webhook_signature_refuses_a_sign_but_keeps_uppercase() {
    let valid = hex_pattern(16);
    let expected = oneiron_hex::decode_vec_any_case(&valid).unwrap();
    assert_eq!(
        doors::webhook_signature_from_hex(&valid),
        Some(expected.clone())
    );
    assert_eq!(doors::webhook_signature_from_hex(&with_sign(&valid)), None);
    assert_eq!(
        doors::webhook_signature_from_hex(&valid.to_uppercase()),
        Some(expected)
    );
}

#[test]
fn custody_anchor_record_refuses_a_sign_and_uppercase() {
    let valid = hex_pattern(16);
    let expected = oneiron_hex::decode_vec(&valid).unwrap();
    assert_eq!(
        doors::custody_anchor_record_from_hex(&valid).unwrap(),
        expected
    );
    assert!(doors::custody_anchor_record_from_hex(&with_sign(&valid)).is_err());
    assert!(doors::custody_anchor_record_from_hex(&valid.to_uppercase()).is_err());
}
