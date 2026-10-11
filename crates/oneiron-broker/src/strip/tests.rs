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

/// Whether `text` still gives the key away: in any echoed form, read through
/// JSON escapes then percent-decoding, or decodable from any base64 run in it
/// at any offset.
fn leaks(text: &[u8], key: &str) -> bool {
    let contains = |haystack: &[u8]| {
        haystack
            .windows(key.len())
            .any(|window| window == key.as_bytes())
    };
    let unescaped = json_unescaped(text);
    if contains(text)
        || contains(&percent_decoded(text))
        || contains(&unescaped)
        || contains(&percent_decoded(&unescaped))
    {
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
    let engines = [
        lenient(&base64::alphabet::STANDARD),
        lenient(&base64::alphabet::URL_SAFE),
    ];
    text.split(|byte| !(byte.is_ascii_alphanumeric() || b"+/-_".contains(byte)))
        .flat_map(|run| (0..4).flat_map(move |skip| (0..4).map(move |cut| (run, skip, cut))))
        .filter_map(|(run, skip, cut)| run.get(skip..run.len().checked_sub(cut)?))
        .flat_map(|window| {
            engines
                .iter()
                .map(move |engine| engine.decode(window).unwrap_or_default())
        })
        .any(|decoded| contains(&decoded))
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
    let stripped = strip(KEY.as_bytes(), body.as_bytes());
    let parsed: serde_json::Value = serde_json::from_slice(&stripped).expect("still json");
    assert_eq!(parsed["error"], "bad key [redacted]");
    assert_eq!(parsed["[redacted]"], 1, "{parsed}");
    assert_eq!(parsed["usage"]["input_tokens"], 3);
    assert!(!leaks(&stripped, KEY));
}

#[test]
fn a_key_partly_spelled_in_escapes_is_redacted_outside_json_too() {
    // Some characters escaped and some not, as a provider's own serializer
    // may write them, in a header value and in a plain-text body.
    let partial: String = KEY
        .chars()
        .enumerate()
        .map(|(index, c)| match c {
            '"' => "\\\"".to_owned(),
            '/' => "\\/".to_owned(),
            c if index % 3 == 0 => format!("\\u{:04X}", u32::from(c)),
            c => c.to_string(),
        })
        .collect();
    for text in [
        format!("invalid api key: {partial}"),
        format!("Bearer realm=\"api\", error_description=\"{partial}\""),
    ] {
        assert!(leaks(text.as_bytes(), KEY), "the oracle must see {text}");
        let stripped = strip(KEY.as_bytes(), text.as_bytes());
        assert!(
            !leaks(&stripped, KEY),
            "{text} survived as {}",
            String::from_utf8_lossy(&stripped)
        );
    }
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
