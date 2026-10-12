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

#[test]
fn a_base64_echo_spelled_in_percent_bytes_is_redacted() {
    // Astra on #1407: the key's base64 with each byte percent-spelled, the
    // same with each `%` written `\u0025`, and the URL-component encoding of
    // a base64 holding `+`, `/` and `=`. A client that percent-decodes, then
    // base64-decodes, reads the key from each.
    let base64 = STANDARD.encode(URL_KEY);
    assert!(base64.contains('+') && base64.contains('/') && base64.ends_with('='));
    let spelled = percent_every_byte(&base64);
    let echoes = [
        spelled.clone(),
        spelled.replace('%', "\\u0025"),
        percent_component(&base64),
    ];
    for echo in echoes {
        assert_eq!(client_reads(echo.as_bytes()), URL_KEY.as_bytes(), "{echo}");
        let body =
            format!("{{\"error\":{{\"message\":\"{echo}\"}},\"usage\":{{\"input_tokens\":3}}}}");
        let header = format!("Bearer error=\"invalid_token\", error_description=\"{echo}\"");
        for text in [body.as_str(), header.as_str()] {
            let stripped = strip(URL_KEY.as_bytes(), text.as_bytes());
            assert!(
                !leaks(&stripped, URL_KEY),
                "{text} survived as {}",
                String::from_utf8_lossy(&stripped)
            );
        }
        let stripped = strip(URL_KEY.as_bytes(), body.as_bytes());
        let parsed: serde_json::Value = serde_json::from_slice(&stripped).expect("still json");
        assert_eq!(parsed["error"]["message"], "[redacted]", "{echo}");
        assert_eq!(parsed["usage"]["input_tokens"], 3);
        let message = parsed["error"]["message"].as_str().unwrap_or_default();
        assert_ne!(client_reads(message.as_bytes()), URL_KEY.as_bytes());
    }
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

#[test]
fn every_inner_form_in_every_outer_spelling_is_redacted() {
    let outer: [(&str, Spelling); 8] = [
        ("as is", str::to_owned),
        ("json every char", |text| json_spelled(text, 1)),
        ("json every other char", |text| json_spelled(text, 2)),
        ("percent every byte", percent_every_byte),
        ("percent component", percent_component),
        ("percent, then json", |text| {
            percent_every_byte(text).replace('%', "\\u0025")
        }),
        ("percent twice", |text| {
            percent_component(&percent_component(text))
        }),
        ("json, then percent", |text| {
            percent_component(&json_spelled(text, 1))
        }),
    ];
    for key in alphabet_keys() {
        assert!(super::admits(key.as_bytes()), "{key}");
        let mut inner = vec![key.clone(), format!("Bearer {key}")];
        for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            inner.push(engine.encode(&key));
        }
        // The key inside a longer encoded text, at each byte offset.
        for engine in [&STANDARD, &URL_SAFE_NO_PAD] {
            inner.push(engine.encode(format!("u:{key}")));
            inner.push(engine.encode(format!("Bearer {key}")));
            inner.push(engine.encode(format!("{key}!")));
        }
        for form in &inner {
            for (name, spell) in &outer {
                let echo = spell(form);
                let body = format!("{{\"note\":\"w0rds~{echo}~m0re\",\"n\":1}}");
                let header = format!("error_description=\"w0rds~{echo}~m0re\"");
                for text in [body.as_str(), header.as_str()] {
                    assert!(
                        leaks(text.as_bytes(), &key),
                        "the oracle must see {name}: {text}"
                    );
                    let stripped = strip(key.as_bytes(), text.as_bytes());
                    let stripped = String::from_utf8_lossy(&stripped);
                    assert!(
                        !leaks(stripped.as_bytes(), &key),
                        "{key} / {name}: {text} survived as {stripped}"
                    );
                    // The words beside the echo stay.
                    let (head, tail) = text.split_once(&echo).unwrap_or_default();
                    assert!(
                        stripped.starts_with(head) && stripped.ends_with(tail),
                        "{key} / {name}: {stripped}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_key_nested_past_the_reading_depth_goes_with_its_run() {
    // Astra's re-check on #1407: the key's base64 in a URL query, that URL in
    // three nested `next` parameters, each value URL-component encoded once:
    // four percent layers on the token. A client reads each `next` once, then
    // the token, then its base64.
    let mut url = format!(
        "https://provider.example/echo?token={}",
        percent_component(&STANDARD.encode(URL_KEY))
    );
    for host in ["relay1.example", "relay2.example", "relay3.example"] {
        url = format!("https://{host}/go?next={}", percent_component(&url));
    }
    let client_reads = |url: &str| -> Option<Vec<u8>> {
        let param = |url: &reqwest::Url, name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };
        let mut current = reqwest::Url::parse(url).ok()?;
        for _ in 0..3 {
            current = reqwest::Url::parse(&param(&current, "next")?).ok()?;
        }
        STANDARD.decode(param(&current, "token")?).ok()
    };
    assert_eq!(client_reads(&url).as_deref(), Some(URL_KEY.as_bytes()));
    let body = format!(
        "{{\"choices\":[{{\"message\":{{\"content\":\"{url}\"}}}}],\"usage\":{{\"input_tokens\":3}}}}"
    );
    assert_eq!(body.len(), 324, "Astra's body: {body}");
    assert!(leaks(body.as_bytes(), URL_KEY));
    let stripped = strip(URL_KEY.as_bytes(), body.as_bytes());
    assert!(
        !leaks(&stripped, URL_KEY),
        "{}",
        String::from_utf8_lossy(&stripped)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&stripped).expect("still json");
    let content = parsed["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(content, "[redacted]");
    assert_eq!(client_reads(content), None);
    assert_eq!(parsed["usage"]["input_tokens"], 3);
    // The same URL as a header value, say `Location`.
    let stripped = strip(URL_KEY.as_bytes(), url.as_bytes());
    assert_eq!(stripped.as_slice(), MARKER);
}

#[test]
fn a_key_split_across_two_chains_of_decodings_goes_with_its_run() {
    // Astra's re-check on #1407: one part of the key read back through JSON,
    // percent, JSON, the other through percent, JSON, percent. Each part is
    // three decodings deep; the whole key only shows in a four-step reading.
    let key = "sk-test-sentinel-0000";
    let (head, tail) = key.split_at(8);
    let json = |text: &str| json_spelled(text, 1);
    let echo = format!(
        "{}{}",
        json(&percent_every_byte(&json(head))),
        percent_every_byte(&json(&percent_every_byte(tail)))
    );
    let four_steps = percent_decoded(&json_unescaped(&percent_decoded(&json_unescaped(
        echo.as_bytes(),
    ))));
    assert_eq!(four_steps, key.as_bytes());
    let body = format!("{{\"error\":{{\"message\":\"bad key: {echo}\"}},\"n\":1}}");
    let header = format!("Bearer error=\"invalid_token\", error_description=\"{echo}\"");
    for text in [body.as_str(), header.as_str()] {
        assert!(leaks(text.as_bytes(), key), "the oracle must see {text}");
        let stripped = strip(key.as_bytes(), text.as_bytes());
        assert!(
            !leaks(&stripped, key),
            "{text} survived as {}",
            String::from_utf8_lossy(&stripped)
        );
        // The run goes whole; the text around it stays.
        let (before, after) = text.split_once(&echo).unwrap_or_default();
        assert_eq!(
            String::from_utf8_lossy(&stripped),
            format!("{before}[redacted]{after}")
        );
    }
}

#[test]
fn a_key_in_any_chain_of_encodings_is_redacted_or_goes_with_its_run() {
    // Random alphabet keys, each form in a random chain of one to six layers.
    // A key no deeper than the rule reads is redacted at its own bytes, and
    // the words beside it in its run stay; a deeper one takes its run along.
    // The text outside the run always stays.
    //
    // Each layer comes off with one of the rule's two decodings and spells
    // every escape of the layer below it, so a reading takes the layers off
    // in one order only.
    let layers: [(&str, Spelling); 4] = [
        ("percent component", percent_component),
        ("json every other char", |text| json_spelled(text, 2)),
        ("percent every byte", percent_every_byte),
        ("json every char", |text| json_spelled(text, 1)),
    ];
    let mut state: u64 = 0x1407_dee9;
    let mut seen = [0_usize; 2];
    for key in alphabet_keys() {
        let mut inner = vec![key.clone()];
        for engine in [&STANDARD, &URL_SAFE_NO_PAD] {
            inner.push(engine.encode(&key));
            inner.push(engine.encode(format!("u:{key}")));
        }
        for _ in 0..16 {
            let mut echo = inner[draw(&mut state, inner.len())].clone();
            let mut chain = Vec::new();
            for _ in 0..=draw(&mut state, 6) {
                // A long echo takes only the first, lighter layer, so the
                // oracle stays quick.
                let choices = if echo.len() > 200 { 1 } else { layers.len() };
                let (name, layer) = layers[draw(&mut state, choices)];
                let next = layer(&echo);
                if next != echo {
                    chain.push(name);
                    echo = next;
                }
            }
            let run = format!("w0rds~{echo}~m0re");
            let body = format!("{{\"note\":\"outside {run} outside\",\"n\":1}}");
            let header = format!("error_description=\"outside {run} outside\"");
            for text in [body.as_str(), header.as_str()] {
                assert!(
                    leaks(text.as_bytes(), &key),
                    "the oracle must see {chain:?}: {text}"
                );
                let stripped = strip(key.as_bytes(), text.as_bytes());
                let stripped = String::from_utf8_lossy(&stripped);
                assert!(
                    !leaks(stripped.as_bytes(), &key),
                    "{key} / {chain:?}: {text} survived as {stripped}"
                );
                let (before, after) = text.split_once(&run).unwrap_or_default();
                let left = stripped
                    .strip_prefix(before)
                    .and_then(|rest| rest.strip_suffix(after));
                let Some(left) = left else {
                    panic!("{key} / {chain:?}: the text outside the run went: {stripped}");
                };
                if chain.len() > super::DEPTH {
                    assert_eq!(left, "[redacted]", "{key} / {chain:?}");
                } else {
                    assert!(
                        left.starts_with("w0rds~")
                            && left.ends_with("~m0re")
                            && left.contains("[redacted]"),
                        "{key} / {chain:?}: {left}"
                    );
                }
                seen[usize::from(chain.len() > super::DEPTH)] += 1;
            }
        }
    }
    assert!(seen.iter().all(|&count| count > 20), "{seen:?}");
}
