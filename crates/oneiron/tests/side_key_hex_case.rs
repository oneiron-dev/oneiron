//! UC-06 PR 0a (HEX-CASE-POLICY = A, Engine RULING 14:31 Sun 15 Nov: "Stored and wire forms
//! stay lowercase-only"): each `oneiron` side-table key that spells a hex part decodes only
//! the lowercase digits its encoder writes, at the width it writes them. A side-table key is
//! a stored form.
//!
//! On main these decoders read their hex parts with `from_str_radix` or
//! `EntityId::from_hex`, which take upper case, and `from_str_radix` also takes a `+` digit,
//! so the `*_refuses_*` tests fail there. Two more: `LeaseKey` splits at the first `:`, so a
//! 33-byte key split elsewhere decodes, and `CheckoutId` slices its text at byte offsets, so
//! a key holding a multi-byte character panics instead of being refused. The lowercase
//! spelling each encoder writes decodes on main and on the PR.
//!
//! `CheckoutId` is public; the other four keys are crate-private and are reached through
//! `test_doors::side_key_hex_case`. Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test side_key_hex_case`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::store::checkout_lease::CheckoutId;
use oneiron::test_doors::side_key_hex_case::{
    ingest_check_key, lease_key, nonce_key, pending_tombstone_key,
};
use oneiron_store::side_table::key::SideKey;

const ID_LOWER: &str = "0123456789abcdef0123456789abcdef";
const ID_UPPER: &str = "0123456789ABCDEF0123456789ABCDEF";
const PEER: &str = "peerpeerpeerpeerpeerpeerpeerpeerpeerpeerpeerpeerpeerpeerpeerpeer";
const DIGEST: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn id() -> EntityId {
    EntityId::from_hex(ID_LOWER).expect("fixture id is not a sentinel")
}

fn id_bytes() -> [u8; 16] {
    *id().as_bytes()
}

#[test]
fn checkout_id_decodes_the_lowercase_it_writes() {
    let checkout = CheckoutId::from_bytes(id_bytes()).expect("nonzero checkout id");
    let mut spelled = Vec::new();
    checkout.encode_into(&mut spelled);
    assert_eq!(spelled, ID_LOWER.as_bytes());
    assert_eq!(CheckoutId::decode_key(ID_LOWER.as_bytes()), Some(checkout));
    assert_eq!(
        CheckoutId::decode_key(b"00000000000000000000000000000000"),
        None,
        "the zero checkout id stays refused"
    );
}

#[test]
fn checkout_id_refuses_upper_case_hex() {
    assert_eq!(CheckoutId::decode_key(ID_UPPER.as_bytes()), None);
}

#[test]
fn checkout_id_refuses_a_signed_digit() {
    assert_eq!(
        CheckoutId::decode_key(b"+123456789abcdef0123456789abcdef"),
        None
    );
}

#[test]
fn checkout_id_refuses_a_key_that_is_not_ascii() {
    // 32 bytes: one `0`, the two-byte `é`, then 29 digits; the second pair is not a char
    // boundary.
    let key = "0é01234567890123456789abcdefabc";
    assert_eq!(key.len(), 32);
    assert_eq!(CheckoutId::decode_key(key.as_bytes()), None);
}

#[test]
fn lease_key_decodes_the_lowercase_it_writes() {
    assert_eq!(
        lease_key(b"00000000000000ab:ffffffffffffffff"),
        Some((0xab, u64::MAX))
    );
}

#[test]
fn lease_key_refuses_upper_case_hex() {
    assert_eq!(lease_key(b"00000000000000AB:0000000000000001"), None);
    assert_eq!(lease_key(b"00000000000000ab:FFFFFFFFFFFFFFFF"), None);
}

#[test]
fn lease_key_refuses_a_signed_digit() {
    assert_eq!(lease_key(b"+0000000000000ab:0000000000000001"), None);
    assert_eq!(lease_key(b"00000000000000ab:+000000000000001"), None);
}

#[test]
fn lease_key_refuses_a_separator_away_from_its_place() {
    // 33 bytes, `:` after the first digit: main reads vault 1 and client 1.
    assert_eq!(lease_key(b"1:0000000000000000000000000000001"), None);
}

#[test]
fn ingest_check_key_decodes_the_lowercase_it_writes() {
    let spelled = format!("{PEER}:00000000000000ab");
    assert_eq!(
        ingest_check_key(spelled.as_bytes()),
        Some((PEER.to_owned(), 0xab))
    );
}

#[test]
fn ingest_check_key_refuses_upper_case_hex() {
    let spelled = format!("{PEER}:00000000000000AB");
    assert_eq!(ingest_check_key(spelled.as_bytes()), None);
}

#[test]
fn ingest_check_key_refuses_a_signed_digit() {
    let spelled = format!("{PEER}:+0000000000000ab");
    assert_eq!(ingest_check_key(spelled.as_bytes()), None);
}

#[test]
fn nonce_key_decodes_the_lowercase_it_writes() {
    let spelled = format!("00000000000000ab:{DIGEST}");
    assert_eq!(
        nonce_key(spelled.as_bytes()),
        Some((0xab, DIGEST.to_owned()))
    );
}

#[test]
fn nonce_key_refuses_upper_case_hex() {
    let spelled = format!("00000000000000AB:{DIGEST}");
    assert_eq!(nonce_key(spelled.as_bytes()), None);
}

#[test]
fn nonce_key_refuses_a_signed_digit() {
    let spelled = format!("+0000000000000ab:{DIGEST}");
    assert_eq!(nonce_key(spelled.as_bytes()), None);
}

#[test]
fn pending_tombstone_key_decodes_the_lowercase_it_writes() {
    let spelled = format!("2026-11:{ID_LOWER}");
    assert_eq!(
        pending_tombstone_key(spelled.as_bytes()),
        Some(("2026-11".to_owned(), id()))
    );
}

#[test]
fn pending_tombstone_key_refuses_upper_case_hex() {
    let spelled = format!("2026-11:{ID_UPPER}");
    assert_eq!(pending_tombstone_key(spelled.as_bytes()), None);
}
