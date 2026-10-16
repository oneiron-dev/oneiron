//! Credential-shape detection shared by write, serve, and export.

use std::ops::Range;

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
    blocklist().any(|entry| text.contains(entry))
}

/// Where [`blocklisted`] finds each entry in `text`.
pub(super) fn blocklist_spans(text: &str) -> Vec<Range<usize>> {
    blocklist()
        .flat_map(|entry| {
            text.match_indices(entry)
                .map(move |(at, _)| at..at + entry.len())
        })
        .collect()
}

/// The byte range `part`, a slice of `text`, takes in it.
pub(super) fn span_of(text: &str, part: &str) -> Range<usize> {
    let start = part.as_ptr() as usize - text.as_ptr() as usize;
    start..start + part.len()
}

/// The longest blocklist entry, in bytes.
pub(super) fn blocklist_longest() -> usize {
    blocklist().map(str::len).max().unwrap_or(0)
}

fn blocklist() -> impl Iterator<Item = &'static str> {
    BLOCKLIST
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// BIP39 phrase lengths: 128 to 256 bits of entropy in 32-bit steps.
const PHRASE_WORDS: [usize; 5] = [12, 15, 18, 21, 24];
/// The longest word on the BIP39 English list.
const MAX_LIST_WORD_LEN: usize = 8;

/// A recovery phrase: an exact count of list words whose last word carries a
/// valid BIP39 checksum, standing as its own segment. Text splits into
/// segments at line breaks, clause and sentence stops, commas, quotes,
/// brackets and `=`. A phrase is one segment of only list words (`words: a b
/// c …`, a quoted value), a run of one-word segments (`1. a\n2. b …`, `a, b,
/// c, …`, a JSON array), allowing one list word on either edge of the run as a
/// label, or one segment wrapped over lines of only list words and blanks. A
/// run of list words inside a sentence is prose, a markdown list of short
/// phrases is prose, and a run with a wrong checksum is no wallet.
/// Seed-labelled fields are separately refused even when incomplete or
/// misspelled.
pub(super) fn mnemonic(text: &str) -> bool {
    let mut stream = MnemonicStream::default();
    stream.feed(text) || stream.finish()
}

/// [`mnemonic`] over text read in parts, in order: it finds what one read of
/// the whole finds, a word or a run cut by an edge included. What it keeps is
/// bounded, since past [`MAX_RUN`] words no run can hold a phrase.
#[derive(Default)]
pub(super) struct MnemonicStream {
    group: PureSegments,
    wrapped: WrappedLines,
    segment: Vec<u16>,
    /// The segment holds a word off the list.
    impure: bool,
    /// The segment holds something other than words and blanks.
    filled: bool,
    /// The word the text so far ends in, kept to one letter past the longest
    /// list word.
    word: String,
}

/// The most words any run of a phrase can span: the longest phrase, and a
/// label on either edge.
const MAX_RUN: usize = 26;

impl MnemonicStream {
    /// Reads `text` on; `true` once a phrase is found.
    pub(super) fn feed(&mut self, text: &str) -> bool {
        for ch in text.chars() {
            if ch.is_ascii_alphabetic() {
                if self.word.len() <= MAX_LIST_WORD_LEN {
                    self.word.push(ch);
                }
                continue;
            }
            self.end_word();
            if segment_break(ch) {
                let line_break = matches!(ch, '\n' | '\r');
                let segment = std::mem::take(&mut self.segment);
                if self
                    .wrapped
                    .close(&segment, !self.impure && !self.filled, line_break)
                    || self.group.close(segment, !self.impure)
                {
                    return true;
                }
                self.impure = false;
                self.filled = false;
            } else if !matches!(ch, ' ' | '\t') {
                self.filled = true;
            }
        }
        false
    }

    /// Reads the end of the text; `true` when a phrase ends it.
    pub(super) fn finish(&mut self) -> bool {
        self.end_word();
        let segment = std::mem::take(&mut self.segment);
        let found = self
            .wrapped
            .close(&segment, !self.impure && !self.filled, false)
            || self.group.close(segment, !self.impure)
            || self.group.finish();
        *self = Self::default();
        found
    }

    fn end_word(&mut self) {
        if self.word.is_empty() {
            return;
        }
        match list_word_index(&self.word) {
            // A segment past the longest run reads as any longer one does.
            Some(index) if self.segment.len() < MAX_RUN => self.segment.push(index),
            Some(_) => {}
            None => self.impure = true,
        }
        self.word.clear();
    }
}

/// One phrase wrapped over lines that hold only list words and blanks (`a b c
/// d e f\ng h i j k l`, a narrow window's line breaks): the whole run of such
/// lines, never a window of it. Bullets, numbers and punctuation keep a line
/// out of the run, so a markdown list of short phrases stays prose.
#[derive(Default)]
struct WrappedLines {
    words: Vec<u16>,
    lines: usize,
}

impl WrappedLines {
    /// Takes one finished segment; `true` once a wrapped phrase is found.
    /// `wraps`: the segment holds only list words and blanks. `line_break`:
    /// a line break ended it, so the next line may carry the run on. A blank
    /// line between two lines neither joins nor breaks the run.
    fn close(&mut self, words: &[u16], wraps: bool, line_break: bool) -> bool {
        if words.is_empty() && wraps && line_break {
            return false;
        }
        if !wraps || words.is_empty() {
            return self.finish();
        }
        let room = (MAX_RUN + 1).saturating_sub(self.words.len());
        self.words.extend(words.iter().take(room));
        self.lines += 1;
        !line_break && self.finish()
    }

    fn finish(&mut self) -> bool {
        let words = std::mem::take(&mut self.words);
        std::mem::take(&mut self.lines) > 1 && phrase(&words)
    }
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
        // A run past the longest one a phrase spans reads as any longer one.
        if self.segments.len() <= MAX_RUN {
            self.segments.push(words);
        }
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

/// Where [`private_key_block`] finds each block in `text`: from its BEGIN line
/// through its END line.
pub(super) fn private_key_block_spans(text: &str) -> Vec<Range<usize>> {
    const BEGIN: &str = "-----BEGIN ";
    const DASHES: &str = "-----";
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find(BEGIN) {
        let start = from + at;
        let label_at = start + BEGIN.len();
        from = label_at;
        let Some(label_len) = text[label_at..].find(DASHES) else {
            break;
        };
        let label = &text[label_at..label_at + label_len];
        if label.contains(['\n', '\r']) || !label.contains("PRIVATE KEY") {
            continue;
        }
        let body_at = label_at + label_len + DASHES.len();
        let end = format!("-----END {label}-----");
        if let Some(body_len) = text[body_at..].find(&end)
            && armored_body(&text[body_at..body_at + body_len])
        {
            from = body_at + body_len + end.len();
            spans.push(start..from);
        }
    }
    spans
}

fn armored_body(body: &str) -> bool {
    let body = join_quoted_literals(body);
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

/// Source code may quote the lines of a key and join the literals, on one
/// line or across several: `"…\\n" + "MIIE…\\n" + "…"`. Each join (a closing
/// quote, `+`, an opening quote) is dropped, so the literals' text runs on as
/// the key's lines. A `+` inside the base64 has no quote beside it and stays.
fn join_quoted_literals(body: &str) -> String {
    const QUOTES: [char; 3] = ['"', '\'', '`'];
    let mut joined = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(at) = rest.find('+') {
        let before = rest[..at].trim_end();
        let after = rest[at + 1..].trim_start();
        if let (Some(before), Some(after)) =
            (before.strip_suffix(QUOTES), after.strip_prefix(QUOTES))
        {
            joined.push_str(before);
            rest = after;
        } else {
            joined.push_str(&rest[..=at]);
            rest = &rest[at + 1..];
        }
    }
    joined.push_str(rest);
    joined
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

/// Values serve and export have always treated as no secret at all, and the
/// handle a mask on write leaves.
fn placeholder(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "[redacted]" | "[secret redacted]" | "<redacted>" | "null"
    ) || custody_handle(value)
}

/// How a masked span opens: `[secret sc12]` stands where the secret was.
pub(super) const HANDLE_OPEN: &str = "[secret ";

/// The handle a mask on write leaves where it lifted a secret into custody
/// (ARCH-0069 #handles-in-fields): `sc12` as a whole value, or a value that
/// starts with `[secret sc12]`. It names a custody record and holds no value.
fn custody_handle(value: &str) -> bool {
    let bare = |text: &str| {
        text.strip_prefix("sc").is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    };
    let value = trim_value(value);
    bare(value)
        || value
            .strip_prefix(HANDLE_OPEN)
            .and_then(|rest| rest.split_once(']'))
            .is_some_and(|(handle, _)| bare(handle))
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
/// Words that mark a whole value as a stand-in when every other word of it is
/// a placeholder word, a filler word or a number: `example-key-0123456789`,
/// `YOUR_SECRET_KEY`, `change_me`. Inside one word they mark nothing, so a real
/// password with `dummy` in its middle is still a password.
const PLACEHOLDER_MARKS: [&str; 8] = [
    "example",
    "changeme",
    "placeholder",
    "dummy",
    "redacted",
    "your",
    "change",
    "replace",
];
/// Words a stand-in joins its marks with (`your-api-key-here`, `replace_me`).
const PLACEHOLDER_FILLER: [&str; 10] = [
    "my", "the", "a", "me", "api", "key", "access", "private", "client", "here",
];

/// The write door's wider placeholder list: `password=password`, `$TOKEN`,
/// `<your-key>`, `xxxx`, `changeme`, `example-key-0123`, `dummy`, `test`, and
/// the like. Only a whole value counts: a stand-in word, a mask, a template,
/// or words that are all stand-in, filler or numbers with a mark among them.
fn write_placeholder(value: &str) -> bool {
    let value = trim_value(value);
    let lower = value.to_ascii_lowercase();
    placeholder(value)
        || PLACEHOLDER_WORDS.contains(&lower.as_str())
        || masked(value)
        || template(value)
        || placeholder_words(&lower)
}

/// A whole-value template, variable or elision: `<your-key>`, `{{token}}`,
/// `${TOKEN}`, `$TOKEN`, `%TOKEN%`, or an elided value (`...`, `…abcd`) that
/// shows at most a four-character tail.
fn template(value: &str) -> bool {
    let name = |text: &str| {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    };
    (value.starts_with('<') && value.ends_with('>'))
        || (value.starts_with("{{") && value.ends_with("}}"))
        || (value.starts_with("${") && value.ends_with('}'))
        || value.strip_prefix('$').is_some_and(name)
        || (value.len() > 2 && value.starts_with('%') && value.ends_with('%'))
        || ["...", "…"].iter().any(|elision| {
            value
                .strip_prefix(elision)
                .is_some_and(|tail| tail.chars().count() <= 4)
        })
}

/// Every word a stand-in (`password`, `token`, `xxxx`), a filler word or a
/// number, and at least one word a mark: `your_api_key_here`,
/// `example-key-0123456789`. A value of one unbroken word is never this.
fn placeholder_words(lower: &str) -> bool {
    let words: Vec<&str> = lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    words.len() > 1
        && words.iter().any(|word| PLACEHOLDER_MARKS.contains(word))
        && words.iter().all(|word| {
            PLACEHOLDER_WORDS.contains(word)
                || PLACEHOLDER_MARKS.contains(word)
                || PLACEHOLDER_FILLER.contains(word)
                || masked(word)
                || word.bytes().all(|byte| byte.is_ascii_digit())
        })
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
    secret_candidate(value).is_some()
}

/// [`secret_material`]'s candidate word, a slice of `value`, when it reads as
/// a real secret.
fn secret_candidate(value: &str) -> Option<&str> {
    let mut words = value.split_whitespace().map(trim_value);
    let mut candidate = words.next()?;
    if AUTH_SCHEMES.contains(&candidate.to_ascii_lowercase().as_str()) {
        candidate = words.next()?;
    }
    if candidate.len() < MIN_SECRET_LEN
        || write_placeholder(candidate)
        || candidate.contains(['(', ')', '[', ']', '{', '}', '<', '>'])
        || candidate.starts_with(['$', '%', '@', '&', '*', '#', '/', '~'])
        || candidate.starts_with("./")
        || candidate.starts_with("../")
        || dotted_name(candidate)
    {
        return None;
    }
    (candidate.bytes().any(|byte| byte.is_ascii_alphabetic())
        && candidate.bytes().any(|byte| byte.is_ascii_digit()))
    .then_some(candidate)
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
        let value = assigned_value(value);
        sensitive_key(assigned_key(key))
            && match door {
                Door::Write => secret_material(value),
                Door::Release => !placeholder(value),
            }
    })
}

/// Where the write door's [`sensitive_assignment`] reads each secret in
/// `text`: the assigned value's candidate word.
pub(super) fn assignment_spans(text: &str) -> Vec<Range<usize>> {
    text.split(['\n', '\r', ',', ';', '{', '}'])
        .filter_map(|line| {
            let (key, value) = line.split_once(['=', ':'])?;
            if !sensitive_key(assigned_key(key)) {
                return None;
            }
            secret_candidate(assigned_value(value)).map(|candidate| span_of(text, candidate))
        })
        .collect()
}

/// The name an assignment's key text reads as.
fn assigned_key(key: &str) -> &str {
    key.trim()
        .trim_start_matches("export ")
        .trim()
        .trim_matches(['"', '\''])
}

/// The value an assignment's value text reads as.
fn assigned_value(value: &str) -> &str {
    value.trim().trim_matches(['"', '\''])
}

/// The longest ending [`sensitive_key`] reads, and some.
const KEY_ENDING: usize = 16;

/// The write door's assignment rule over one line a reader kept in parts,
/// its middle dropped: its key, or its `head` and end when the key's middle
/// was dropped, and its value's start (`value_cut`: more of the value was
/// dropped; else `value` is the whole value). `None` when the parts cannot
/// tell what the whole line reads as: the key's reading trims through a
/// part it was cut at (a run of `export `, quotes or blanks), or the value
/// word a sensitive key's rule reads runs past the cut.
pub(super) fn cut_assignment(
    head: Option<&str>,
    key: &str,
    value: &str,
    value_cut: bool,
) -> Option<bool> {
    let sensitive = match head {
        None => sensitive_key(assigned_key(key)),
        Some(head) => {
            // A key cut in the middle is longer than any name, so only its
            // ending can read as one, once its own ends are trimmed as whole.
            // A head left as the start of another `export ` may strip on past
            // the cut, and so may one whose last character the cut split (read
            // as U+FFFD, it may have been a blank).
            let head = head
                .strip_suffix(char::REPLACEMENT_CHARACTER)
                .unwrap_or(head);
            let exported = head.trim_start().trim_start_matches("export ");
            let start = exported.trim_start().trim_start_matches(['"', '\'']);
            let ending = key.trim_end().trim_end_matches(['"', '\'']);
            if "export ".starts_with(exported) || start.is_empty() || ending.len() < KEY_ENDING {
                return None;
            }
            sensitive_key(ending)
        }
    };
    if !sensitive || !value_cut {
        return Some(sensitive && secret_material(assigned_value(value)));
    }
    // The rule reads the value's first word, and the next after an auth
    // scheme: each must end, at a blank, before the cut.
    let read = value.trim_start().trim_start_matches(['"', '\'']);
    let words: Vec<&str> = read.split_whitespace().take(3).collect();
    let complete = if words.len() == 3 || read.ends_with(char::is_whitespace) {
        words.len()
    } else {
        words.len().saturating_sub(1)
    };
    let scheme = words
        .first()
        .is_some_and(|word| AUTH_SCHEMES.contains(&trim_value(word).to_ascii_lowercase().as_str()));
    (complete > usize::from(scheme)).then(|| secret_material(assigned_value(value)))
}

/// A string value under a credential field name that the door still treats as
/// no secret.
pub(super) fn field_placeholder(value: &str, door: Door) -> bool {
    match door {
        Door::Write => write_placeholder(value),
        Door::Release => placeholder(value),
    }
}
