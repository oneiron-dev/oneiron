//! The strip forms of ARCH-0069 `#model-adapter-strip-forms`, each written
//! the way a provider could echo it, built here independently of the rule.

use base64::Engine as _;
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};
use base64::engine::DecodePaddingMode;

use super::{MARKER, strip, strip_body};

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

/// Whether `text` still gives the key away: in any echoed form, or decodable
/// from any base64 run in it at any offset.
fn leaks(text: &[u8], key: &str) -> bool {
    let contains = |haystack: &[u8]| {
        haystack
            .windows(key.len())
            .any(|window| window == key.as_bytes())
    };
    if contains(text) || contains(&percent_decoded(text)) || contains(&json_unescaped(text)) {
        return true;
    }
    // Every base64 run, read at each start offset and each end, in both
    // alphabets, leniently: a key inside a longer encoded text shows up in
    // one of those readings.
    let lenient = |alphabet: &base64::alphabet::Alphabet| {
        GeneralPurpose::new(
            alphabet,
            GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(DecodePaddingMode::Indifferent),
        )
    };
    let engines = [lenient(&base64::alphabet::STANDARD), lenient(&base64::alphabet::URL_SAFE)];
    text.split(|byte| !(byte.is_ascii_alphanumeric() || b"+/-_".contains(byte)))
        .flat_map(|run| (0..4).flat_map(move |skip| (0..4).map(move |cut| (run, skip, cut))))
        .filter_map(|(run, skip, cut)| run.get(skip..run.len().checked_sub(cut)?))
        .flat_map(|window| engines.iter().map(move |engine| engine.decode(window).unwrap_or_default()))
        .any(|decoded| contains(&decoded))
}

/// `text` with JSON's two-character escapes read back.
fn json_unescaped(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bytes = text.iter();
    while let Some(&byte) = bytes.next() {
        if byte == b'\\' {
            out.push(*bytes.next().unwrap_or(&byte));
        } else {
            out.push(byte);
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
fn every_echoed_form_of_the_key_is_redacted() {
    for echo in echoes(KEY) {
        let mut body = b"{\"error\":\"bad key: ".to_vec();
        body.extend_from_slice(&echo);
        body.extend_from_slice(b"\"}");
        assert!(
            leaks(&body, KEY),
            "the oracle must see {}",
            String::from_utf8_lossy(&echo)
        );
        let stripped = strip(KEY.as_bytes(), &body);
        assert!(
            !leaks(&stripped, KEY),
            "{} survived as {}",
            String::from_utf8_lossy(&echo),
            String::from_utf8_lossy(&stripped)
        );
        assert!(
            stripped
                .windows(MARKER.len())
                .any(|window| window == MARKER),
            "{}",
            String::from_utf8_lossy(&echo)
        );
    }
}

#[test]
fn text_without_the_key_passes_unchanged() {
    let body = br#"{"choices":[{"message":{"content":"sk-test/sentinel is a prefix only"}}]}"#;
    assert_eq!(strip(KEY.as_bytes(), body).as_slice(), body.as_slice());
}

#[test]
fn a_json_body_is_checked_in_its_decoded_strings() {
    // JSON may spell any character `\uXXXX`; the runner's parser reads the key.
    let spelled: String = KEY
        .chars()
        .map(|c| format!("\\u{:04x}", u32::from(c)))
        .collect();
    let body = format!(
        "{{\"error\":\"bad key {spelled}\",\"{spelled}\":1,\"usage\":{{\"input_tokens\":3}}}}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        parsed["error"].as_str(),
        Some(format!("bad key {KEY}").as_str())
    );
    let stripped = strip_body(KEY.as_bytes(), body.as_bytes());
    let parsed: serde_json::Value = serde_json::from_slice(&stripped).expect("still json");
    assert_eq!(parsed["error"], "bad key [redacted]");
    assert_eq!(parsed["[redacted]"], 1, "{parsed}");
    assert_eq!(parsed["usage"]["input_tokens"], 3);
    assert!(!leaks(&stripped, KEY));
}
