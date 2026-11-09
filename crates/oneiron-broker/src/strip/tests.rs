//! The strip forms of ARCH-0069 `#model-adapter-strip-forms`, each written
//! the way a provider could echo it, built here independently of the rule.

use base64::Engine as _;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};

use super::{MARKER, strip};

/// A synthetic key whose JSON, percent and URL-safe base64 forms all differ
/// from its raw and standard ones.
const KEY: &str = "sk-test/sentinel+\"0000~?>";

fn echoes(key: &str) -> Vec<Vec<u8>> {
    let json = serde_json::to_string(key).expect("json");
    let mut percent = String::new();
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            percent.push(char::from(byte));
        } else {
            percent.push_str(&format!("%{byte:02X}"));
        }
    }
    // Percent-encoding may spell any byte `%XX`, unreserved ones too.
    let every_byte: String = key.bytes().map(|byte| format!("%{byte:02x}")).collect();
    let mut echoes = vec![
        key.as_bytes().to_vec(),
        json.as_bytes()[1..json.len() - 1].to_vec(),
        format!("Bearer {key}").into_bytes(),
        percent.clone().into_bytes(),
        percent.to_ascii_lowercase().into_bytes(),
        every_byte.into_bytes(),
        format!("https://h.example/cb?token={percent}&x=1").into_bytes(),
    ];
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        echoes.push(engine.encode(key).into_bytes());
        // The key inside a longer encoded text, at each byte offset.
        echoes.push(engine.encode(format!("Bearer {key}")).into_bytes());
        echoes.push(engine.encode(format!("u:{key}")).into_bytes());
        echoes.push(engine.encode(format!("{key}!")).into_bytes());
    }
    echoes
}

/// How many decodings the oracle reads through: past the rule's own limit,
/// so it sees what the rule leaves unread.
const ORACLE_DEPTH: usize = 8;
const _: () = assert!(ORACLE_DEPTH > super::DEPTH);

/// Whether `text` still gives the key away, read as a client could read it:
/// through any chain of up to [`ORACLE_DEPTH`] decodings (JSON escapes,
/// percent-encoding, in any order), then as is or decoded from any base64 run
/// in that reading, at any offset.
fn leaks(text: &[u8], key: &str) -> bool {
    let contains = |haystack: &[u8]| {
        haystack
            .windows(key.len())
            .any(|window| window == key.as_bytes())
    };
    readings(text).iter().any(|reading| {
        contains(reading) || base64_readings(reading, key.len()).any(|decoded| contains(&decoded))
    })
}

/// `text` and each reading of it through up to [`ORACLE_DEPTH`] decodings.
fn readings(text: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![text.to_vec()];
    let mut level = all.clone();
    for _ in 0..ORACLE_DEPTH {
        level = level
            .iter()
            .flat_map(|reading| [json_unescaped(reading), percent_decoded(reading)])
            .filter(|reading| !all.contains(reading))
            .collect();
        all.extend(level.iter().cloned());
    }
    all
}

/// Every base64 run of `text` at least `shortest` long, read at each start
/// offset and each end, in both alphabets, leniently: a key inside a longer
/// encoded text shows up in one of those readings. A run shorter than the key
/// cannot encode it.
fn base64_readings(text: &[u8], shortest: usize) -> impl Iterator<Item = Vec<u8>> + '_ {
    let lenient = |alphabet: &base64::alphabet::Alphabet| {
        GeneralPurpose::new(
            alphabet,
            GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(DecodePaddingMode::Indifferent),
        )
    };
    let engines = [
        lenient(&base64::alphabet::STANDARD),
        lenient(&base64::alphabet::URL_SAFE),
    ];
    text.split(|byte| !(byte.is_ascii_alphanumeric() || b"+/-_".contains(byte)))
        .filter(move |run| run.len() >= shortest)
        .flat_map(|run| (0..4).flat_map(move |skip| (0..4).map(move |cut| (run, skip, cut))))
        .filter_map(|(run, skip, cut)| run.get(skip..run.len().checked_sub(cut)?))
        .flat_map(move |window| {
            engines
                .clone()
                .into_iter()
                .map(move |engine| engine.decode(window).unwrap_or_default())
        })
}

/// `text` with JSON's escapes read back: `\uXXXX`, a surrogate pair as one
/// character, and the two-character ones.
fn json_unescaped(text: &[u8]) -> Vec<u8> {
    let unit = |at: usize| {
        text.get(at..at + 4)
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
    };
    let mut out = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let decoded = match (text[at], text.get(at + 1)) {
            (b'\\', Some(b'u')) => match unit(at + 2) {
                Some(high @ 0xD800..=0xDBFF) => unit(at + 8)
                    .filter(|low| (0xDC00..=0xDFFF).contains(low))
                    .filter(|_| text.get(at + 6..at + 8) == Some(b"\\u".as_slice()))
                    .and_then(|low| {
                        char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
                    })
                    .map(|character| (character, 12)),
                Some(code) => char::from_u32(code).map(|character| (character, 6)),
                None => None,
            },
            (b'\\', Some(&escaped)) if escaped.is_ascii() => {
                let byte = match escaped {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    b'b' => 8,
                    b'f' => 12,
                    other => other,
                };
                Some((char::from(byte), 2))
            }
            _ => None,
        };
        match decoded {
            Some((character, width)) => {
                let mut utf8 = [0; 4];
                out.extend_from_slice(character.encode_utf8(&mut utf8).as_bytes());
                at += width;
            }
            None => {
                out.push(text[at]);
                at += 1;
            }
        }
    }
    out
}

fn percent_decoded(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let hex = text
            .get(at + 1..at + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (text[at], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                at += 3;
            }
            (byte, _) => {
                out.push(byte);
                at += 1;
            }
        }
    }
    out
}

#[test]
fn only_the_key_goes_from_a_url_run_that_percent_decodes_to_it() {
    // Words joined to a part-encoded key in one URL-like run stay.
    let key = "sk-test-sentinel-0000";
    let body = format!(
        "{{\"content\":\"prefix-%{:02X}{}-suffix\"}}",
        key.as_bytes()[0],
        &key[1..]
    );
    assert!(leaks(body.as_bytes(), key));
    let stripped = strip(key.as_bytes(), body.as_bytes());
    assert!(!leaks(&stripped, key));
    let parsed: serde_json::Value = serde_json::from_slice(&stripped).expect("still json");
    assert_eq!(parsed["content"], "prefix-[redacted]-suffix");
}

#[test]
fn only_the_key_goes_from_an_escaped_run_that_percent_decodes_to_it() {
    // Escaped spaces join the words around a percent-spelled key into one
    // run; the words stay, and only the key's own bytes are redacted.
    let every_byte: String = KEY.bytes().map(|byte| format!("%{byte:02x}")).collect();
    let body = format!("{{\"error\":\"prefix\\u0020{every_byte}\\u0020suffix\"}}");
    assert!(leaks(body.as_bytes(), KEY));
    let stripped = strip(KEY.as_bytes(), body.as_bytes());
    assert!(
        !leaks(&stripped, KEY),
        "{}",
        String::from_utf8_lossy(&stripped)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&stripped).expect("still json");
    assert_eq!(parsed["error"], "prefix [redacted] suffix");
    // The key's own quote joins the string's quotes to the run; they stay.
    let body = format!("{{\"content\":\"\\u0025{}\"}}", &every_byte[1..]);
    assert!(leaks(body.as_bytes(), KEY));
    let stripped = strip(KEY.as_bytes(), body.as_bytes());
    let parsed: serde_json::Value = serde_json::from_slice(&stripped).expect("still json");
    assert_eq!(parsed["content"], "[redacted]");
}

/// A synthetic key from the broker's alphabet whose standard base64 holds
/// `+`, `/` and padding: `~` and `?` as the third byte of a group spell them.
const URL_KEY: &str = "sk~te?sentinel00";

/// Each byte as `%XX`, in lowercase hex.
fn percent_every_byte(text: &str) -> String {
    text.bytes().map(|byte| format!("%{byte:02x}")).collect()
}

/// URL-component encoding: each byte outside the unreserved set as `%XX`.
fn percent_component(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Each character as JSON's `\uXXXX`, or only every other one, with each
/// backslash and quote left between escaped as JSON must.
fn json_spelled(text: &str, every: usize) -> String {
    text.chars()
        .enumerate()
        .map(|(index, c)| match c {
            c if index % every == 0 => format!("\\u{:04x}", u32::from(c)),
            '\\' => "\\\\".to_owned(),
            '"' => "\\\"".to_owned(),
            c => c.to_string(),
        })
        .collect()
}

/// The reply read back as a client would: JSON escapes, then percent-decoding,
/// then base64.
fn client_reads(text: &[u8]) -> Vec<u8> {
    let decoded = percent_decoded(&json_unescaped(text));
    let engine = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    engine.decode(decoded).unwrap_or_default()
}

/// A number below `below`, drawn from `state` with a fixed-seed generator.
fn draw(state: &mut u64, below: usize) -> usize {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    usize::try_from(*state >> 33).unwrap_or_default() % below
}

/// Keys from the broker's alphabet: fixed ones, then a spread drawn from it
/// with a fixed seed.
fn alphabet_keys() -> Vec<String> {
    const ALPHABET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@/?#";
    let mut keys = vec![
        URL_KEY.to_owned(),
        "sk-test/sentinel?~0000".to_owned(),
        "sk-ant-api03-~?~?-sentinel".to_owned(),
    ];
    let mut state: u64 = 0x1407_5eed;
    for len in [8, 9, 10, 13, 16, 21, 32, 47] {
        let key: String = (0..len)
            .map(|_| char::from(ALPHABET[draw(&mut state, ALPHABET.len())]))
            .collect();
        keys.push(key);
    }
    keys
}

/// An outer spelling of an echo.
type Spelling = fn(&str) -> String;

