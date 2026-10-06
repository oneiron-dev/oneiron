//! Credential-shape detection shared by write, serve, and export.

use sha2::{Digest, Sha256};

use super::wordlist::WORDS;
const BLOCKLIST: &str = include_str!("blocklist.txt");

/// Which door asks. A hit at the write door refuses the whole write, so an
/// assignment there must carry a value that looks like real secret material,
/// and a private key must be a whole block. The release doors (serve, export,
/// snapshot custody, pre-receive, pack screening) redact or quarantine one
/// item instead, and keep the wide rules: any non-placeholder value under a
/// credential name, and any private-key header line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Door {
    Write,
    Release,
}

pub(super) fn blocklisted(text: &str) -> bool {
    BLOCKLIST
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|entry| text.contains(entry))
}

/// BIP39 phrase lengths: 128 to 256 bits of entropy in 32-bit steps.
const PHRASE_WORDS: [usize; 5] = [12, 15, 18, 21, 24];
/// The longest word on the BIP39 English list.
const MAX_LIST_WORD_LEN: usize = 8;

/// A recovery phrase: an exact count of list words whose last word carries a
/// valid BIP39 checksum, standing as its own segment. Text splits into
/// segments at line breaks, clause and sentence stops, commas, quotes,
/// brackets and `=`. A phrase is one segment of only list words (`words: a b
/// c …`, a quoted value), or a run of one-word segments (`1. a\n2. b …`,
/// `a, b, c, …`, a JSON array), allowing one list word on either edge of the
/// run as a label. A run of list words inside a sentence is prose, a markdown
/// list of short phrases is prose, and a run with a wrong checksum is no
/// wallet. Seed-labelled fields are separately refused even when incomplete or
/// misspelled.
pub(super) fn mnemonic(text: &str) -> bool {
    let mut group = PureSegments::default();
    let mut segment: Vec<u16> = Vec::new();
    let mut pure = true;
    let mut chars = text.char_indices().peekable();
    while let Some((start, ch)) = chars.next() {
        if !ch.is_ascii_alphabetic() {
            if segment_break(ch) {
                if group.close(std::mem::take(&mut segment), pure) {
                    return true;
                }
                pure = true;
            }
            continue;
        }
        let mut end = start + 1;
        while let Some(&(at, next)) = chars.peek() {
            if !next.is_ascii_alphabetic() {
                break;
            }
            end = at + 1;
            chars.next();
        }
        match list_word_index(&text[start..end]) {
            Some(index) => segment.push(index),
            None => pure = false,
        }
    }
    group.close(segment, pure) || group.finish()
}

/// Consecutive segments made only of list words, between impure segments.
#[derive(Default)]
struct PureSegments {
    segments: Vec<Vec<u16>>,
    /// A segment of several words joined the run: the run is prose-shaped
    /// (`**a b c** (d, e)`), so only single segments count inside it.
    multi_word: bool,
}

impl PureSegments {
    /// Takes one finished segment; `true` once a phrase is found. A segment
    /// holding any other word ends the group; a segment with no words joins
    /// nothing and breaks nothing (list numbering, blank lines).
    fn close(&mut self, words: Vec<u16>, pure: bool) -> bool {
        if !pure {
            return self.finish();
        }
        if words.is_empty() {
            return false;
        }
        if phrase(&words) {
            return true;
        }
        self.multi_word |= words.len() > 1;
        self.segments.push(words);
        false
    }

    /// A run of one-word segments: the whole run, or the run less one word at
    /// either edge (a list word used as a label). Never an arbitrary window: a
    /// long list of common words must not offer a checksum many chances.
    fn finish(&mut self) -> bool {
        let segments = std::mem::take(&mut self.segments);
        if std::mem::take(&mut self.multi_word) {
            return false;
        }
        let count = segments.len();
        [
            (0, count),
            (1, count),
            (0, count.saturating_sub(1)),
            (1, count.saturating_sub(1)),
        ]
        .into_iter()
        .filter(|(first, last)| first < last)
        .any(|(first, last)| {
            let words = &segments[first..last];
            PHRASE_WORDS.contains(&words.iter().map(Vec::len).sum::<usize>())
                && phrase(&words.concat())
        })
    }
}

/// Text that ends a segment: a line break, a sentence or clause stop, a comma,
/// a quote, a bracket, or an assignment. Spaces, hyphens and digits join the
/// words of one segment.
fn segment_break(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\r'
            | ':'
            | ';'
            | ','
            | '.'
            | '!'
            | '?'
            | '"'
            | '\''
            | '`'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '<'
            | '>'
            | '='
            | '|'
    )
}

fn list_word_index(word: &str) -> Option<u16> {
    if word.len() > MAX_LIST_WORD_LEN {
        return None;
    }
    let lower = word.to_ascii_lowercase();
    WORDS
        .binary_search(&lower.as_str())
        .ok()
        .and_then(|index| u16::try_from(index).ok())
}

/// The list is the BIP39 English list in its canonical (sorted) order, so a
/// word's position is its 11-bit index. The phrase packs ENT entropy bits and
/// ENT/32 checksum bits; the checksum is the head of SHA-256(entropy).
fn phrase(indices: &[u16]) -> bool {
    if !PHRASE_WORDS.contains(&indices.len()) {
        return false;
    }
    let total_bits = indices.len() * 11;
    let checksum_bits = total_bits / 33;
    let entropy_bytes = (total_bits - checksum_bits) / 8;
    let mut packed = vec![0_u8; total_bits.div_ceil(8)];
    for (position, &index) in indices.iter().enumerate() {
        for bit in 0..11 {
            if (index >> (10 - bit)) & 1 == 1 {
                let at = position * 11 + bit;
                packed[at / 8] |= 0x80 >> (at % 8);
            }
        }
    }
    let digest = Sha256::digest(&packed[..entropy_bytes]);
    let shift = 8 - checksum_bits;
    packed[entropy_bytes] >> shift == digest[0] >> shift
}

/// The release doors' private-key rule, unchanged: any `-----BEGIN …PRIVATE
/// KEY…-----` header line. Line-at-a-time scanners (the pre-receive credential
/// door) see the header without its body, so release keeps the header alone.
pub(super) fn private_key_header(text: &str) -> bool {
    text.lines().any(|line| {
        let Some(start) = line.find("-----BEGIN ") else {
            return false;
        };
        let marker = &line[start + "-----BEGIN ".len()..];
        let Some(end) = marker.find("-----") else {
            return false;
        };
        marker[..end].contains("PRIVATE KEY")
    })
}

/// The base64 a real key body carries at the least (an Ed25519 PKCS#8 key is 64).
const MIN_KEY_BODY_BASE64: usize = 40;

/// The write door's private-key rule: a PEM or PGP block, i.e. a `-----BEGIN
/// …PRIVATE KEY…-----` line, a base64 body, and the matching END line. The
/// header alone, or a block whose body is not base64, is text about keys.
pub(super) fn private_key_block(text: &str) -> bool {
    const BEGIN: &str = "-----BEGIN ";
    const DASHES: &str = "-----";
    let mut rest = text;
    while let Some(at) = rest.find(BEGIN) {
        rest = &rest[at + BEGIN.len()..];
        let Some(label_len) = rest.find(DASHES) else {
            return false;
        };
        let label = &rest[..label_len];
        if label.contains(['\n', '\r']) || !label.contains("PRIVATE KEY") {
            continue;
        }
        let body_and_tail = &rest[label_len + DASHES.len()..];
        let end = format!("-----END {label}-----");
        if let Some(body_len) = body_and_tail.find(&end)
            && armored_body(&body_and_tail[..body_len])
        {
            return true;
        }
    }
    false
}

fn armored_body(body: &str) -> bool {
    let mut base64 = 0_usize;
    // A key quoted in source code keeps its line breaks as `\n` escapes.
    let lines = body
        .split(['\n', '\r'])
        .flat_map(|line| line.split("\\n"))
        .flat_map(|line| line.split("\\r"));
    for line in lines {
        // Source code may quote and concatenate the lines: `"MIIE…" +`.
        let line = line
            .trim()
            .trim_end_matches('+')
            .trim_end()
            .trim_matches(['"', '\'', '`', ',', ';', '\\']);
        if line.is_empty() || armor_header(line) {
            continue;
        }
        if !line
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return false;
        }
        base64 += line.len();
    }
    base64 >= MIN_KEY_BODY_BASE64
}

/// RFC 1421 and RFC 4880 armor headers (`Proc-Type: 4,ENCRYPTED`, `Version: …`).
fn armor_header(line: &str) -> bool {
    line.split_once(": ").is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

pub(super) fn sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '.'], "_");
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "token"
            | "api_key"
            | "apikey"
            | "private_key"
            | "client_secret"
            | "access_token"
            | "refresh_token"
            | "authorization"
            | "mnemonic"
            | "seed_phrase"
    ) || [
        "_password",
        "_passwd",
        "_secret",
        "_token",
        "_api_key",
        "_private_key",
        "_access_key",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix))
}

/// Values serve and export have always treated as no secret at all.
fn placeholder(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "[redacted]" | "[secret redacted]" | "<redacted>" | "null"
    )
}

/// Placeholder words a person writes in place of a secret.
const PLACEHOLDER_WORDS: [&str; 22] = [
    "password",
    "passwd",
    "secret",
    "token",
    "changeme",
    "example",
    "dummy",
    "test",
    "testing",
    "sample",
    "placeholder",
    "string",
    "str",
    "none",
    "nil",
    "undefined",
    "todo",
    "tbd",
    "foo",
    "bar",
    "baz",
    "redacted",
];
/// Fragments that mark a value as a stand-in wherever they appear.
const PLACEHOLDER_MARKS: [&str; 10] = [
    "example",
    "changeme",
    "change_me",
    "change-me",
    "placeholder",
    "dummy",
    "redacted",
    "replace_me",
    "xxxx",
    "****",
];
/// Openings of a template, a variable or a stand-in rather than a value.
const PLACEHOLDER_OPENINGS: [&str; 7] = ["your", "<", "$", "{{", "%", "...", "…"];

/// The write door's wider placeholder list: `password=password`, `$TOKEN`,
/// `<your-key>`, `xxxx`, `changeme`, `example`, `dummy`, `test`, and the like.
fn write_placeholder(value: &str) -> bool {
    let value = trim_value(value);
    let lower = value.to_ascii_lowercase();
    placeholder(value)
        || PLACEHOLDER_WORDS.contains(&lower.as_str())
        || PLACEHOLDER_MARKS.iter().any(|mark| lower.contains(mark))
        || PLACEHOLDER_OPENINGS
            .iter()
            .any(|opening| lower.starts_with(opening))
        || masked(value)
}

/// One character repeated as a mask: `xxxxxxxx`, `********`, `00000000`.
fn masked(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| {
        matches!(first, 'x' | 'X' | '*' | '.' | '#' | '0' | '-' | '_')
            && chars.all(|ch| ch == first)
    })
}

fn trim_value(value: &str) -> &str {
    value
        .trim()
        .trim_matches(['"', '\'', '`'])
        .trim_end_matches([',', ';'])
}

/// The shortest value the write door counts as secret material.
const MIN_SECRET_LEN: usize = 8;
/// HTTP authorization schemes that precede the credential itself.
const AUTH_SCHEMES: [&str; 4] = ["bearer", "basic", "token", "digest"];

/// Whether an assigned value is plausibly a real secret rather than an
/// example, a placeholder, or a reference in code. The value's first word is
/// the candidate (after an HTTP auth scheme); it must hold letters and digits,
/// be at least eight characters, and not read as a call, an index, a template,
/// a variable, a path, or a dotted name.
fn secret_material(value: &str) -> bool {
    let mut words = value.split_whitespace().map(trim_value);
    let Some(mut candidate) = words.next() else {
        return false;
    };
    if AUTH_SCHEMES.contains(&candidate.to_ascii_lowercase().as_str()) {
        let Some(credential) = words.next() else {
            return false;
        };
        candidate = credential;
    }
    if candidate.len() < MIN_SECRET_LEN
        || write_placeholder(candidate)
        || candidate.contains(['(', ')', '[', ']', '{', '}', '<', '>'])
        || candidate.starts_with(['$', '%', '@', '&', '*', '#', '/', '~'])
        || candidate.starts_with("./")
        || candidate.starts_with("../")
        || dotted_name(candidate)
    {
        return false;
    }
    candidate.bytes().any(|byte| byte.is_ascii_alphabetic())
        && candidate.bytes().any(|byte| byte.is_ascii_digit())
}

/// `this.apiKey`, `process.env.API_KEY`, `config.v2.token`: names joined by
/// dots. A JWT's parts are long and carry digits, so it is not one.
fn dotted_name(value: &str) -> bool {
    value.contains('.')
        && value.split('.').all(|part| {
            part.as_bytes()
                .first()
                .is_some_and(|first| first.is_ascii_alphabetic() || matches!(first, b'_' | b'$'))
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
                && (part.len() <= 3 || !part.bytes().any(|byte| byte.is_ascii_digit()))
        })
}

pub(super) fn sensitive_assignment(text: &str, door: Door) -> bool {
    // Assignment syntax covers dotenv, shell, JSON and YAML. Structural
    // MessagePack fields are checked separately at the payload door.
    text.split(['\n', '\r', ',', ';', '{', '}']).any(|line| {
        let Some((key, value)) = line.split_once(['=', ':']) else {
            return false;
        };
        let key = key
            .trim()
            .trim_start_matches("export ")
            .trim()
            .trim_matches(['\"', '\'']);
        let value = value.trim().trim_matches(['\"', '\'']);
        sensitive_key(key)
            && match door {
                Door::Write => secret_material(value),
                Door::Release => !placeholder(value),
            }
    })
}

/// A string value under a credential field name that the door still treats as
/// no secret.
pub(super) fn field_placeholder(value: &str, door: Door) -> bool {
    match door {
        Door::Write => write_placeholder(value),
        Door::Release => placeholder(value),
    }
}
