//! The release assignment rule as a body's text streams (FIX 7200, FIX 5392
//! Rule 5). It reads what [`sensitive_assignment`] reads at the release door
//! in one segment, one character at a time. No length bounds a key or a
//! value, so the reader keeps neither. Small states follow each trim of the
//! whole rule, the `export ` run, the credential names and endings, the
//! placeholders and the custody handle. A segment is judged only where it
//! ends, as the whole rule judges it.
//!
//! [`sensitive_assignment`]: super::super::shapes::sensitive_assignment

use super::super::shapes::{
    ASSIGNMENT_QUOTES, ASSIGNMENT_SEPARATORS, CREDENTIAL_NAME_ENDINGS, CREDENTIAL_NAMES,
    EXPORT_PREFIX, HANDLE_OPEN, HANDLE_QUOTES, HANDLE_TAG, RELEASE_PLACEHOLDERS,
    normalized_key_byte,
};
use super::advance;

/// The release assignment rule over one segment as it streams.
#[derive(Default)]
pub(super) struct AssignmentSegment {
    reading: Reading,
}

impl AssignmentSegment {
    /// Reads `ch`, a character of the segment, never a segment edge.
    pub(super) fn feed(&mut self, ch: char) {
        let next = match &mut self.reading {
            Reading::Key(key) => {
                if !ASSIGNMENT_SEPARATORS.contains(&ch) {
                    key.feed(ch);
                    return;
                }
                if key.credential_name() {
                    Reading::Value(ValueReading::default())
                } else {
                    Reading::OtherKey
                }
            }
            Reading::Value(value) => {
                value.feed(ch);
                return;
            }
            Reading::OtherKey => return,
        };
        self.reading = next;
    }

    /// Ends the segment: whether it held a credential assignment. The next
    /// segment is read from its start.
    pub(super) fn finish(&mut self) -> bool {
        let assignment = match &self.reading {
            Reading::Value(value) => value.secret(),
            Reading::Key(_) | Reading::OtherKey => false,
        };
        self.reading = Reading::default();
        assignment
    }
}

/// Where in its segment the rule reads.
enum Reading {
    /// Before the segment's first separator: its key.
    Key(KeyReading),
    /// After it, under a credential name: its value.
    Value(ValueReading),
    /// After it, under any other key: the segment holds no assignment.
    OtherKey,
}

impl Default for Reading {
    fn default() -> Self {
        Self::Key(KeyReading::default())
    }
}

/// A key as it streams: `assigned_key`'s trims (blanks, each leading
/// `export `, blanks, quotes), then `sensitive_key`'s names.
#[derive(Default)]
struct KeyReading {
    lead: KeyLead,
    /// A whole `export ` was read and no non-blank since. If the key ends
    /// so, its first trim takes that last blank, and the key is `export`.
    export_open: bool,
    name: KeyName,
}

/// The trim a key's start is in, in the trims' order.
#[derive(Default, Clone, Copy)]
enum KeyLead {
    /// The blanks the first trim takes.
    #[default]
    Blanks,
    /// The `export ` run: this many bytes of the next `export `.
    Export(usize),
    /// The blanks the second trim takes after the run.
    ExportBlanks,
    /// The quotes the quote trim takes.
    Quotes,
    /// The name itself.
    Name,
}

impl KeyReading {
    fn feed(&mut self, ch: char) {
        match self.lead {
            KeyLead::Blanks => {
                if !ch.is_whitespace() {
                    self.lead = KeyLead::Export(0);
                    self.feed(ch);
                }
            }
            KeyLead::Export(matched) => self.export(matched, ch),
            KeyLead::ExportBlanks => {
                if !ch.is_whitespace() {
                    self.export_open = false;
                    self.lead = KeyLead::Quotes;
                    self.feed(ch);
                }
            }
            KeyLead::Quotes => {
                if !ASSIGNMENT_QUOTES.contains(&ch) {
                    self.lead = KeyLead::Name;
                    self.name.feed(ch);
                }
            }
            KeyLead::Name => self.name.feed(ch),
        }
    }

    /// Reads `ch` after `matched` bytes of an `export `.
    fn export(&mut self, matched: usize, ch: char) {
        if EXPORT_PREFIX[matched..].starts_with(ch) {
            // The prefix's only blank is its last character. Any other
            // character of it closes the `export ` before it. That blank
            // opens this one: the key's first trim takes it back unless a
            // non-blank follows.
            let matched = matched + ch.len_utf8();
            self.export_open = matched == EXPORT_PREFIX.len();
            self.lead = KeyLead::Export(if self.export_open { 0 } else { matched });
            return;
        }
        // No `export ` here: the key's text starts with what was read of one.
        self.lead = KeyLead::ExportBlanks;
        for read in EXPORT_PREFIX[..matched].chars() {
            self.feed(read);
        }
        self.feed(ch);
    }

    /// Whether the key read so far is a credential name, were it to end
    /// here.
    fn credential_name(&self) -> bool {
        let rest = match self.lead {
            // The key's first trim takes the blank of its last `export `, so
            // the prefix trim leaves that `export` as the key.
            _ if self.export_open => EXPORT_PREFIX.trim_end(),
            // The key ends inside what could have been an `export `: what
            // was read of it is the key.
            KeyLead::Export(matched) => &EXPORT_PREFIX[..matched],
            _ => return self.name.credential_name(),
        };
        let mut name = KeyName::default();
        for ch in rest.chars() {
            name.feed(ch);
        }
        name.credential_name()
    }
}

/// A key's name past its leading trims, less the end its trailing trims may
/// still take: blanks, and the quotes before them.
#[derive(Default, Clone, Copy)]
struct KeyName {
    /// The name through its last character no trailing trim takes.
    kept: NameForm,
    /// The name through every character read.
    read: NameForm,
    /// The last character read is a blank.
    blank_end: bool,
}

impl KeyName {
    fn feed(&mut self, ch: char) {
        let quote = ASSIGNMENT_QUOTES.contains(&ch);
        if quote && self.blank_end {
            // Quotes are trimmed after the blanks, so a quote run trimmed
            // from the end stops at a blank: the blanks before this quote
            // stay in the name.
            self.kept = self.read;
        }
        self.read.feed(ch);
        self.blank_end = ch.is_whitespace();
        if !self.blank_end && !quote {
            self.kept = self.read;
        }
    }

    fn credential_name(&self) -> bool {
        self.kept.matched()
    }
}

/// What a key's name reads as so far, over its normalized bytes
/// ([`normalized_key_byte`]): a credential name whole, or a name with a
/// credential ending.
#[derive(Clone, Copy)]
struct NameForm {
    whole: WholeMatch<{ CREDENTIAL_NAMES.len() }>,
    ending: EndingMatch<{ CREDENTIAL_NAME_ENDINGS.len() }>,
}

impl Default for NameForm {
    fn default() -> Self {
        Self {
            whole: WholeMatch::new(&CREDENTIAL_NAMES),
            ending: EndingMatch::new(&CREDENTIAL_NAME_ENDINGS),
        }
    }
}

impl NameForm {
    fn feed(&mut self, ch: char) {
        for &byte in ch.encode_utf8(&mut [0; 4]).as_bytes() {
            let byte = normalized_key_byte(byte);
            self.whole.feed(byte);
            self.ending.feed(byte);
        }
    }

    fn matched(&self) -> bool {
        self.whole.matched() || self.ending.matched()
    }
}

/// A credential name's value as it streams: `assigned_value`'s trims
/// (blanks, quotes), the placeholder rule's own trim (blanks), then the
/// release placeholders.
#[derive(Default)]
struct ValueReading {
    lead: ValueLead,
    text: ValueText,
}

/// The trim a value's start is in, in the trims' order.
#[derive(Default, Clone, Copy)]
enum ValueLead {
    /// The blanks the first trim takes.
    #[default]
    Blanks,
    /// The quotes the quote trim takes.
    Quotes,
    /// The blanks the placeholder rule's trim takes after them.
    QuoteBlanks,
    /// The value's text.
    Text,
}

impl ValueReading {
    fn feed(&mut self, ch: char) {
        let blank = ch.is_whitespace();
        let quote = ASSIGNMENT_QUOTES.contains(&ch);
        self.lead = match self.lead {
            ValueLead::Blanks if blank => ValueLead::Blanks,
            ValueLead::Blanks | ValueLead::Quotes if quote => ValueLead::Quotes,
            ValueLead::Quotes | ValueLead::QuoteBlanks if blank => ValueLead::QuoteBlanks,
            _ => {
                self.text.feed(ch);
                ValueLead::Text
            }
        };
    }

    /// Whether the value read is a secret: no release placeholder.
    fn secret(&self) -> bool {
        !self.text.kept.placeholder()
    }
}

/// A value's text past its leading trims, less the end its trailing trims
/// may still take. Trimmed from the end: blanks, then quotes, then blanks.
#[derive(Default, Clone, Copy)]
struct ValueText {
    /// The text through its last character no trailing trim takes.
    kept: ValueForm,
    /// The text through every character read.
    read: ValueForm,
    /// With `end` at [`ValueEnd::QuoteBlanks`]: the text before its last
    /// blank run.
    before_blanks: ValueForm,
    end: ValueEnd,
}

/// What the text read ends in, past `kept`.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum ValueEnd {
    /// Nothing.
    #[default]
    Kept,
    /// Blanks.
    Blanks,
    /// Quotes, after any blanks.
    Quotes,
    /// Blanks after quotes.
    QuoteBlanks,
}

impl ValueText {
    fn feed(&mut self, ch: char) {
        self.end = if ch.is_whitespace() {
            match self.end {
                ValueEnd::Kept | ValueEnd::Blanks => ValueEnd::Blanks,
                ValueEnd::Quotes => {
                    self.before_blanks = self.read;
                    ValueEnd::QuoteBlanks
                }
                ValueEnd::QuoteBlanks => ValueEnd::QuoteBlanks,
            }
        } else if ASSIGNMENT_QUOTES.contains(&ch) {
            if self.end == ValueEnd::QuoteBlanks {
                // A quote run trimmed from the end stops at a blank: only
                // the blanks before this quote may still go.
                self.kept = self.before_blanks;
            }
            ValueEnd::Quotes
        } else {
            ValueEnd::Kept
        };
        self.read.feed(ch);
        if self.end == ValueEnd::Kept {
            self.kept = self.read;
        }
    }
}

/// What a value's text reads as so far: a release placeholder, read in
/// ASCII lower case, or a custody handle.
#[derive(Clone, Copy)]
struct ValueForm {
    fixed: WholeMatch<{ RELEASE_PLACEHOLDERS.len() }>,
    handle: Handle,
}

impl Default for ValueForm {
    fn default() -> Self {
        Self {
            fixed: WholeMatch::new(&RELEASE_PLACEHOLDERS),
            handle: Handle::default(),
        }
    }
}

impl ValueForm {
    fn feed(&mut self, ch: char) {
        for &byte in ch.encode_utf8(&mut [0; 4]).as_bytes() {
            self.fixed.feed(byte.to_ascii_lowercase());
        }
        self.handle = self.handle.step(ch);
    }

    fn placeholder(&self) -> bool {
        self.fixed.matched() || self.handle.accepts()
    }
}

// The handle's two forms differ at their first character, so its first
// character picks the form.
const _: () = assert!(HANDLE_OPEN.as_bytes()[0] != HANDLE_TAG.as_bytes()[0]);

/// The custody handle as a value streams, read as `custody_handle` reads
/// it: past the handle quotes trimmed from both ends, `sc` and digits
/// whole, or `[secret `, `sc`, digits, `]` and then blanks only. The
/// handle reading's last trim, of `,` and `;`, takes nothing here: no
/// segment holds either.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Handle {
    /// The quotes trimmed from the start.
    #[default]
    Quotes,
    /// This many bytes of [`HANDLE_OPEN`].
    Open(usize),
    /// This many bytes of [`HANDLE_TAG`], inside a bracket or bare.
    Tag { bracketed: bool, matched: usize },
    /// The digits after the tag; `digit`: one was read.
    Digits { bracketed: bool, digit: bool },
    /// After a bracketed handle's `]`: blanks.
    Closed,
    /// The quotes trimmed from the end.
    EndQuotes,
    /// No handle.
    Rejected,
}

impl Handle {
    fn step(self, ch: char) -> Self {
        let quote = HANDLE_QUOTES.contains(&ch);
        match self {
            Self::Quotes if quote => Self::Quotes,
            Self::Quotes if HANDLE_OPEN.starts_with(ch) => Self::Open(0).step(ch),
            Self::Quotes => Self::Tag {
                bracketed: false,
                matched: 0,
            }
            .step(ch),
            Self::Open(matched) if HANDLE_OPEN[matched..].starts_with(ch) => {
                let matched = matched + ch.len_utf8();
                if matched == HANDLE_OPEN.len() {
                    Self::Tag {
                        bracketed: true,
                        matched: 0,
                    }
                } else {
                    Self::Open(matched)
                }
            }
            Self::Tag { bracketed, matched } if HANDLE_TAG[matched..].starts_with(ch) => {
                let matched = matched + ch.len_utf8();
                if matched == HANDLE_TAG.len() {
                    Self::Digits {
                        bracketed,
                        digit: false,
                    }
                } else {
                    Self::Tag { bracketed, matched }
                }
            }
            Self::Digits { bracketed, .. } if ch.is_ascii_digit() => Self::Digits {
                bracketed,
                digit: true,
            },
            Self::Digits {
                bracketed: true,
                digit: true,
            } if ch == ']' => Self::Closed,
            Self::Closed if ch.is_whitespace() => Self::Closed,
            Self::Digits {
                bracketed: false,
                digit: true,
            }
            | Self::Closed
            | Self::EndQuotes
                if quote =>
            {
                Self::EndQuotes
            }
            _ => Self::Rejected,
        }
    }

    /// Whether the value read so far is a handle, were it to end here.
    fn accepts(self) -> bool {
        matches!(
            self,
            Self::Digits {
                bracketed: false,
                digit: true,
            } | Self::Closed
                | Self::EndQuotes
        )
    }
}

/// Which of `entries` the bytes read so far are, whole.
#[derive(Clone, Copy)]
struct WholeMatch<const N: usize> {
    entries: &'static [&'static str; N],
    /// Each entry still begins with the bytes read.
    alive: [bool; N],
    /// The bytes read while an entry was alive: at most one past the
    /// longest entry.
    read: usize,
}

impl<const N: usize> WholeMatch<N> {
    const fn new(entries: &'static [&'static str; N]) -> Self {
        Self {
            entries,
            alive: [true; N],
            read: 0,
        }
    }

    fn feed(&mut self, byte: u8) {
        if !self.alive.contains(&true) {
            return;
        }
        for (alive, entry) in self.alive.iter_mut().zip(self.entries) {
            *alive &= entry.as_bytes().get(self.read) == Some(&byte);
        }
        self.read += 1;
    }

    fn matched(&self) -> bool {
        self.alive
            .iter()
            .zip(self.entries)
            .any(|(&alive, entry)| alive && entry.len() == self.read)
    }
}

/// Which of `entries` the bytes read so far end in.
#[derive(Clone, Copy)]
struct EndingMatch<const N: usize> {
    entries: &'static [&'static str; N],
    /// For each entry, how much of its start the bytes read end in.
    matched: [usize; N],
}

impl<const N: usize> EndingMatch<N> {
    const fn new(entries: &'static [&'static str; N]) -> Self {
        Self {
            entries,
            matched: [0; N],
        }
    }

    fn feed(&mut self, byte: u8) {
        for (matched, entry) in self.matched.iter_mut().zip(self.entries) {
            *matched = advance(entry.as_bytes(), *matched, byte);
        }
    }

    fn matched(&self) -> bool {
        self.matched
            .iter()
            .zip(self.entries)
            .any(|(&matched, entry)| matched == entry.len())
    }
}
