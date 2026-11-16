//! Hex text for bytes: encode, decode and check in one place.
//!
//! One policy: lowercase is the canonical form. Every encoder writes
//! lowercase, and the plain decoders and checks accept only lowercase.
//! Accepting `A-F` is a named, explicit choice: the `*_any_case` functions
//! are for text that an outside format lets be either case (MIME, CSS
//! colours, typed CLI input, a foreign webhook).
//!
//! No function trims, strips a `0x` prefix or caps a length; a caller that
//! needs one keeps it at its own door.

const LOWER_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of `bytes`: two digits per byte.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    encode_into(bytes, &mut out);
    out
}

/// Appends the lowercase hex of `bytes` to `out`.
pub fn encode_into(bytes: &[u8], out: &mut String) {
    out.reserve(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(LOWER_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(LOWER_DIGITS[usize::from(byte & 0x0f)]));
    }
}

/// `N` bytes from exactly `2 * N` lowercase hex digits; anything else is `None`.
pub fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode_array_with(text, nibble)
}

/// Bytes from an even count of lowercase hex digits (`""` gives an empty Vec);
/// anything else is `None`.
pub fn decode_vec(text: &str) -> Option<Vec<u8>> {
    decode_vec_with(text, nibble)
}

/// [`decode`] that also accepts `A-F`, for text an outside format lets be
/// either case.
pub fn decode_any_case<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode_array_with(text, nibble_any_case)
}

/// [`decode_vec`] that also accepts `A-F`, for text an outside format lets be
/// either case.
pub fn decode_vec_any_case(text: &str) -> Option<Vec<u8>> {
    decode_vec_with(text, nibble_any_case)
}

/// Whether `text` is lowercase hex: exactly `len` digits when `Some(len)`,
/// else one or more digits of any count (an abbreviated git id may be odd).
/// `""` passes only as `Some(0)`.
pub fn is_lower_hex(text: &str, len: Option<usize>) -> bool {
    is_hex_with(text, len, nibble)
}

/// [`is_lower_hex`] that also accepts `A-F`.
pub fn is_hex_any_case(text: &str, len: Option<usize>) -> bool {
    is_hex_with(text, len, nibble_any_case)
}

/// The value of one lowercase hex digit (`0-9`, `a-f`); anything else is `None`.
pub fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The value of one hex digit of either case (`0-9`, `a-f`, `A-F`); anything
/// else is `None`.
pub fn nibble_any_case(digit: u8) -> Option<u8> {
    match digit {
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => nibble(digit),
    }
}

fn decode_array_with<const N: usize>(
    text: &str,
    digit_value: fn(u8) -> Option<u8>,
) -> Option<[u8; N]> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if pairs.len() != N || !rest.is_empty() {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, &[high, low]) in out.iter_mut().zip(pairs) {
        *slot = (digit_value(high)? << 4) | digit_value(low)?;
    }
    Some(out)
}

fn decode_vec_with(text: &str, digit_value: fn(u8) -> Option<u8>) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[high, low]| Some((digit_value(high)? << 4) | digit_value(low)?))
        .collect()
}

fn is_hex_with(text: &str, len: Option<usize>, digit_value: fn(u8) -> Option<u8>) -> bool {
    let length_matches = match len {
        Some(len) => text.len() == len,
        None => !text.is_empty(),
    };
    length_matches && text.bytes().all(|digit| digit_value(digit).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bytes(count: usize) -> Vec<u8> {
        (0..count)
            .map(|index| u8::try_from(index * 37 % 256).unwrap())
            .collect()
    }

    #[test]
    fn encode_matches_the_two_digit_lowercase_format_for_every_byte() {
        for byte in 0..=u8::MAX {
            assert_eq!(encode(&[byte]), format!("{byte:02x}"));
        }
    }

    #[test]
    fn round_trips_for_0_1_16_and_32_bytes() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode::<0>(""), Some([]));
        assert_eq!(decode_vec(""), Some(Vec::new()));

        let one = [0xa5u8];
        assert_eq!(encode(&one), "a5");
        assert_eq!(decode::<1>("a5"), Some(one));

        let sixteen: [u8; 16] = sample_bytes(16).try_into().unwrap();
        let text = encode(&sixteen);
        assert_eq!(text.len(), 32);
        assert_eq!(decode::<16>(&text), Some(sixteen));
        assert_eq!(decode_vec(&text), Some(sixteen.to_vec()));

        let thirty_two: [u8; 32] = sample_bytes(32).try_into().unwrap();
        let text = encode(&thirty_two);
        assert_eq!(text.len(), 64);
        assert_eq!(decode::<32>(&text), Some(thirty_two));
        assert_eq!(
            decode_any_case::<32>(&text.to_uppercase()),
            Some(thirty_two)
        );
        assert_eq!(decode_vec_any_case(&text), Some(thirty_two.to_vec()));
    }

    #[test]
    fn encode_into_appends_after_existing_text() {
        let mut out = String::from("sha256:");
        encode_into(&[0x00, 0xff, 0x10], &mut out);
        assert_eq!(out, "sha256:00ff10");
    }

    #[test]
    fn decode_refuses_odd_and_wrong_lengths() {
        assert_eq!(decode::<1>("a"), None);
        assert_eq!(decode::<1>("abc"), None);
        assert_eq!(decode::<2>("ab"), None);
        assert_eq!(decode::<1>("abcd"), None);
        assert_eq!(decode::<1>(""), None);
        assert_eq!(decode_vec("abc"), None);
        assert_eq!(decode_vec_any_case("A"), None);
    }

    #[test]
    fn decode_refuses_uppercase_and_non_hex_bytes() {
        assert_eq!(decode::<2>("AbC0"), None);
        assert_eq!(decode::<1>("aF"), None);
        assert_eq!(decode_vec("ABCD"), None);
        assert_eq!(decode::<1>("g0"), None);
        assert_eq!(decode::<1>("0x"), None);
        assert_eq!(decode::<1>(" a"), None);
        assert_eq!(decode::<1>("+a"), None);
        assert_eq!(decode_vec("00zz"), None);
        assert_eq!(decode_any_case::<1>("G0"), None);
    }

    #[test]
    fn decode_refuses_a_multibyte_utf8_char() {
        // "é" is two bytes (0xC3 0xA9), so it has the length of one hex pair.
        assert_eq!("é".len(), 2);
        assert_eq!(decode::<1>("é"), None);
        assert_eq!(decode_any_case::<1>("é"), None);
        assert_eq!(decode_vec("00é"), None);
        assert!(!is_lower_hex("é", Some(2)));
        assert!(!is_hex_any_case("é", None));
    }

    #[test]
    fn decode_any_case_accepts_mixed_case() {
        assert_eq!(decode_any_case::<2>("AbC0"), Some([0xab, 0xc0]));
        assert_eq!(decode_vec_any_case("AbC0"), Some(vec![0xab, 0xc0]));
        assert_eq!(decode_any_case::<2>("abc0"), Some([0xab, 0xc0]));
    }

    #[test]
    fn is_lower_hex_with_an_exact_length() {
        assert!(is_lower_hex("00ff", Some(4)));
        assert!(!is_lower_hex("00ff", Some(3)));
        assert!(!is_lower_hex("00ff", Some(5)));
        assert!(!is_lower_hex("00FF", Some(4)));
        assert!(!is_lower_hex("00fg", Some(4)));
        assert!(is_hex_any_case("00FF", Some(4)));
        assert!(!is_hex_any_case("00FF", Some(2)));
    }

    #[test]
    fn is_lower_hex_with_no_length_takes_any_nonempty_count() {
        assert!(is_lower_hex("a", None));
        assert!(is_lower_hex("abc", None));
        assert!(is_lower_hex("0123456789abcdef", None));
        assert!(!is_lower_hex("abC", None));
        assert!(!is_lower_hex("ab ", None));
        assert!(is_hex_any_case("abC", None));
    }

    #[test]
    fn is_lower_hex_on_the_empty_string() {
        assert!(!is_lower_hex("", None));
        assert!(is_lower_hex("", Some(0)));
        assert!(!is_lower_hex("", Some(2)));
        assert!(!is_hex_any_case("", None));
        assert!(is_hex_any_case("", Some(0)));
    }

    #[test]
    fn nibble_values_and_case_policy() {
        for (digit, value) in b"0123456789abcdef".iter().zip(0u8..) {
            assert_eq!(nibble(*digit), Some(value));
            assert_eq!(nibble_any_case(*digit), Some(value));
        }
        for (digit, value) in b"ABCDEF".iter().zip(10u8..) {
            assert_eq!(nibble(*digit), None);
            assert_eq!(nibble_any_case(*digit), Some(value));
        }
        for digit in [b'g', b'G', b'x', b' ', b'/', b':', b'@', b'`', 0x00, 0xff] {
            assert_eq!(nibble(digit), None);
            assert_eq!(nibble_any_case(digit), None);
        }
    }
}
