//! The identity ask key's hex form (UC-07 PR 8; FIX [IDENTITY-ASK-KEY-ACCEPTS-SIGN]).
//!
//! An ask key is 64 hex digits. `parse_key` reads the key an owner or an
//! agent names in an answer, and the key of a stored applied row. Either
//! case is a key; a sign digit (`+`) is not.

use oneiron_records::dreamer_runner::maintenance::identity::{key_hex, parse_key};

fn sample_key() -> [u8; 32] {
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::try_from(index * 37 % 256).unwrap() ^ 0xa5;
    }
    key
}

#[test]
fn a_sign_digit_is_refused_in_any_pair() {
    for at in [0, 2, 62] {
        let mut text = "0".repeat(64);
        text.replace_range(at..at + 2, "+a");
        assert_eq!(text.len(), 64);
        assert_eq!(parse_key(&text), None, "{text}");
    }
}

#[test]
fn key_hex_round_trips() {
    let key = sample_key();
    let text = key_hex(&key);
    assert_eq!(text.len(), 64);
    assert_eq!(parse_key(&text), Some(key));
}

#[test]
fn uppercase_and_mixed_case_name_the_same_key() {
    let key = sample_key();
    let lower = key_hex(&key);
    let upper = lower.to_uppercase();
    assert_ne!(lower, upper);
    assert_eq!(parse_key(&upper), Some(key));
    let mixed: String = lower
        .chars()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == 0 {
                digit.to_ascii_uppercase()
            } else {
                digit
            }
        })
        .collect();
    assert_eq!(parse_key(&mixed), Some(key));
}

#[test]
fn a_wrong_length_or_a_non_hex_digit_is_refused() {
    let text = key_hex(&sample_key());
    assert_eq!(parse_key(&text[..62]), None);
    assert_eq!(parse_key(&format!("{text}00")), None);
    assert_eq!(parse_key(""), None);
    assert_eq!(parse_key(&format!("g{}", &text[1..])), None);
    assert_eq!(parse_key(&format!("-a{}", &text[2..])), None);
    assert_eq!(parse_key(&format!("\u{e9}{}", &text[2..])), None);
}
