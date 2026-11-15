//! The hex cursor reader (UC-13 PR 2, HEX-CASE-POLICY = A): hex digits of
//! either case, nothing else.

use oneiron_contracts::cursor_text::{parse_hex_cursor, parse_hex_cursor_vec};

#[test]
fn a_fixed_cursor_reads_in_either_case() {
    for text in ["0af9", "0AF9", "0aF9", "0Af9"] {
        assert_eq!(parse_hex_cursor::<2>(text), Some([0x0a, 0xf9]), "{text}");
    }
    assert_eq!(parse_hex_cursor::<1>("00"), Some([0]));
    assert_eq!(parse_hex_cursor::<1>("ff"), Some([0xff]));
}

#[test]
fn a_fixed_cursor_is_hex_digits_only() {
    for text in [
        "", "0af", "0af9a", "0af90a", "+af9", "+a", "-af9", " 0af9", "0af9 ", "0x0a", "0ag9",
        "0aé", "0a:9",
    ] {
        assert_eq!(parse_hex_cursor::<2>(text), None, "{text:?}");
    }
    assert_eq!(parse_hex_cursor::<1>("+f"), None);
}

#[test]
fn a_variable_cursor_reads_in_either_case() {
    assert_eq!(parse_hex_cursor_vec(""), Some(Vec::new()));
    for text in ["0af9", "0AF9", "0aF9"] {
        assert_eq!(parse_hex_cursor_vec(text), Some(vec![0x0a, 0xf9]), "{text}");
    }
    for text in ["0af", "+f", "+af9", " 0af9", "0ag9", "0aé"] {
        assert_eq!(parse_hex_cursor_vec(text), None, "{text:?}");
    }
}
