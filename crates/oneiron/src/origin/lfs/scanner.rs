//! Bounded credential scanning across transport and content-defined boundaries.

use crate::error::{Error, GateError, Result};

/// Retains token prefixes and a window of each token, not arbitrarily long
/// binary/text tokens. All standing token detectors decide within
/// [`KEY_MAX`] bytes of where a key starts. PEM armor is a separate
/// streaming automaton because its header can contain arbitrary padding.
///
/// Its constructors keep two contracts apart (OF-067). The token and armor
/// automata are the always-on custody reading an object bound for a repo
/// gets, whatever the owner's switch says, as the pre-receive scan reads a
/// pushed blob ([`Self::custody`]). The seam, the phrase rule and the
/// blocklist are the write door's memory admission, which only the owner's
/// switch turns on ([`Self::with_write_seam`]); a result body's taint reads
/// them always ([`Self::exhaust`]).
#[derive(Default)]
pub(crate) struct CredentialStream {
    token: Vec<u8>,
    /// The open token past its first byte, for a key that starts inside it
    /// (F23): each offset is read once [`KEY_MAX`] bytes follow it, the rest
    /// when the token ends, so this holds at most twice that.
    inner: Vec<u8>,
    begin: usize,
    inside: bool,
    private: usize,
    seen_private: bool,
    dashes: usize,
    seam: Option<Seam>,
    /// The recovery-phrase rule over the whole stream: a phrase's run of
    /// one-word segments crosses the line breaks that end a seam's segment.
    phrases: Option<crate::batch::secret_scan::PhraseStream>,
    /// The blocklist over the whole stream, which matches anywhere in a
    /// segment, the part a long one drops included.
    blocklist: Option<crate::batch::secret_scan::BlocklistStream>,
}

/// How much of one segment a seam reads whole, once its padding is squeezed:
/// as much as an object the upload reads whole, so a segment up to that size
/// is read whole however a peer cuts it.
const SEAM_MAX: usize = super::upload::LFS_WHOLE_SCAN_MAX as usize;

/// The longest key a provider rule reads from where it starts.
const KEY_MAX: usize = 128;

/// How much of a run of one repeated character a seam keeps: as much as the
/// longest token any text rule measures (a stream keeps 128 bytes of one too),
/// so the run reads as it did.
const RUN_KEEP: usize = 128;

/// How much of a run of whitespace a seam keeps: its first two characters,
/// which every text rule reads as it reads the whole run (the assignment
/// rule's `export ` prefix strips only before a run of one space).
const SPACE_KEEP: usize = 2;

/// How much a segment longer than [`SEAM_MAX`] keeps of each of the places
/// the assignment rule reads (see [`Seam::bound`]).
const PART_KEEP: usize = SEAM_MAX / 4;

/// The write door's text rules across feed edges, but for the recovery-phrase
/// rule, which the stream reads whole. A batch scan reads each chunk alone,
/// so a `password=` at one chunk's end and its value at the next one's start
/// meet nowhere else: a segment an edge splits (the text
/// between `\n`, `\r`, `,`, `;`, `{` and `}`, as the assignment rule splits
/// it) is read whole once it ends, in the chunk that ends it or at the end of
/// the stream, so each byte is read once more at most. A peer chooses the
/// edges, and padding must not carry a key away from its value: each run of
/// whitespace reads as its first [`SPACE_KEEP`] characters and each run of
/// one other character as at most [`RUN_KEEP`] of it. A segment still
/// longer than [`SEAM_MAX`] keeps what the assignment rule reads of it, and
/// only that rule reads it ([`Seam::bound`]); the stream reads the rules
/// that match anywhere.
#[derive(Default)]
struct Seam {
    /// A long segment's key's first [`PART_KEEP`], once its middle was
    /// dropped.
    head: Vec<u8>,
    /// A long segment's key (or its end, after `head`), and its first `=` or
    /// `:`.
    key: Vec<u8>,
    /// A long segment's value's first [`PART_KEEP`].
    value: Vec<u8>,
    /// The open segment's text since its start, or since its kept parts.
    tail: Vec<u8>,
    /// Whether the open segment crossed an edge, so that no chunk holds it.
    crossed: bool,
    /// The last character kept or squeezed, and how long its run is.
    run: Option<(char, usize)>,
    /// Where in `tail` the segment's first `=` or `:` stands, until a long
    /// segment's key takes it.
    separator: Option<usize>,
    /// Which part of a segment longer than [`SEAM_MAX`] `tail` holds.
    long: Option<Part>,
}

/// The part of a long segment a seam's tail holds.
#[derive(Clone, Copy)]
enum Part {
    /// The key, past its first [`PART_KEEP`].
    Key,
    /// The value's start, until it holds [`PART_KEEP`].
    Value,
    /// What follows the value's start; `true` once some of it was dropped.
    Rest(bool),
}

impl Seam {
    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        let Some(first) = bytes.iter().position(|byte| segment_break(*byte)) else {
            self.carry(bytes);
            return Ok(());
        };
        self.carry(&bytes[..first]);
        self.finish()?;
        let last = bytes
            .iter()
            .rposition(|byte| segment_break(*byte))
            .unwrap_or(first);
        self.carry(&bytes[last + 1..]);
        Ok(())
    }

    /// Reads the open segment if it crossed an edge, and closes it.
    fn finish(&mut self) -> Result<()> {
        if self.crossed {
            let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
            let value_cut = matches!(self.long, Some(Part::Rest(true)));
            if self.head.is_empty() && !value_cut {
                // Nothing was dropped: the whole segment.
                let whole = [self.key.as_slice(), &self.value, &self.tail].concat();
                crate::batch::secret_scan::scan_write_seam(&text(&whole))?;
            } else if let Some((_, key)) = self.key.split_last() {
                let value = if value_cut {
                    text(&self.value)
                } else {
                    text(&[self.value.as_slice(), &self.tail].concat())
                };
                crate::batch::secret_scan::scan_cut_seam(
                    (!self.head.is_empty()).then(|| text(&self.head)).as_deref(),
                    &text(key),
                    &value,
                    value_cut,
                )?;
            }
        }
        *self = Self::default();
        Ok(())
    }

    fn carry(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.crossed |= !(self.head.is_empty() && self.key.is_empty() && self.tail.is_empty());
        self.squeeze(bytes);
        self.bound();
    }

    /// Bounds a segment longer than [`SEAM_MAX`] to what the assignment rule
    /// reads of it: its first `=` or `:`, never dropped, [`PART_KEEP`] of
    /// each end of its key and of its value's start, and whether more of the
    /// value was dropped. The rest of the value is kept only while nothing of
    /// it is dropped (as [`PART_KEEP`] of its end, for a tail is cut only once
    /// it is twice what it keeps, so each byte moves once at most).
    fn bound(&mut self) {
        loop {
            match self.long {
                None if self.tail.len() <= SEAM_MAX => return,
                None => {
                    let key = self.separator.unwrap_or(self.tail.len());
                    if key > 2 * PART_KEEP {
                        self.keep_key_ends(key);
                    }
                    self.long = Some(Part::Key);
                }
                Some(Part::Key) => {
                    let Some(at) = self.separator.take() else {
                        if self.tail.len() > 2 * PART_KEEP {
                            self.keep_key_ends(self.tail.len());
                        }
                        return;
                    };
                    // A key whose first part is kept keeps its last.
                    let dropped = if self.head.is_empty() {
                        0
                    } else {
                        at.saturating_sub(PART_KEEP)
                    };
                    self.tail.drain(..dropped);
                    self.key.extend(self.tail.drain(..=at - dropped));
                    self.long = Some(Part::Value);
                }
                Some(Part::Value) => {
                    if self.tail.len() < PART_KEEP {
                        return;
                    }
                    self.value.extend(self.tail.drain(..PART_KEEP));
                    self.long = Some(Part::Rest(false));
                }
                Some(Part::Rest(_)) => {
                    if self.tail.len() > 2 * PART_KEEP {
                        self.tail.drain(..self.tail.len() - PART_KEEP);
                        self.long = Some(Part::Rest(true));
                    }
                    return;
                }
            }
        }
    }

    /// Keeps the first [`PART_KEEP`] of a key the tail holds `key` bytes of
    /// as its head, and its last: the middle is dropped.
    fn keep_key_ends(&mut self, key: usize) {
        if self.head.is_empty() {
            self.head.extend_from_slice(&self.tail[..PART_KEEP]);
        }
        self.tail.drain(..key - PART_KEEP);
        if let Some(at) = &mut self.separator {
            *at -= key - PART_KEEP;
        }
    }

    /// Appends `bytes` with their padding squeezed: each run of whitespace
    /// (every character the assignment rule trims) to its first
    /// [`SPACE_KEEP`], and each run of one other character past [`RUN_KEEP`]
    /// to that many. Bytes that are not text (a character an edge cut in
    /// two) stay as they are.
    fn squeeze(&mut self, bytes: &[u8]) {
        for chunk in bytes.utf8_chunks() {
            for ch in chunk.valid().chars() {
                // Whitespace of any kind runs as one.
                let class = if ch.is_whitespace() { ' ' } else { ch };
                let run = match self.run {
                    Some((previous, run)) if previous == class => run + 1,
                    _ => 1,
                };
                self.run = Some((class, run));
                if run <= if class == ' ' { SPACE_KEEP } else { RUN_KEEP } {
                    if matches!(ch, '=' | ':')
                        && self.separator.is_none()
                        && matches!(self.long, None | Some(Part::Key))
                    {
                        self.separator = Some(self.tail.len());
                    }
                    self.tail
                        .extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                }
            }
            if !chunk.invalid().is_empty() {
                self.tail.extend_from_slice(chunk.invalid());
                self.run = None;
            }
        }
    }
}

fn segment_break(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r' | b',' | b';' | b'{' | b'}')
}

impl CredentialStream {
    /// The always-on custody reading alone: provider keys and private-key
    /// armor across each feed edge. A hit refuses an object bound for a repo
    /// with the switch off too, and before any file mark: a key in repo
    /// content is refused, as receive-pack refuses one, not marked.
    pub(super) fn custody() -> Self {
        Self::default()
    }

    /// [`Self::custody`] plus the write door's text rules across each feed
    /// edge ([`Seam`]), the phrase rule and the blocklist: the memory
    /// admission. `on` is the owner's `secrets` switch, which the batch door
    /// that scans each chunk follows too; off, only the custody reading runs.
    pub(super) fn with_write_seam(on: bool) -> Self {
        Self {
            seam: on.then(Seam::default),
            phrases: on.then(Default::default),
            blocklist: on.then(Default::default),
            ..Self::default()
        }
    }

    /// [`Self::custody`] plus the write door's text rules across each feed
    /// edge and the blocklist, always on, for a result body's taint (ARCH-0069
    /// S7): build exhaust is marked whatever the switch says. Its reader reads
    /// the phrase rule over the text in order itself, and each feed's own
    /// text by the door's rules (`scan_write_seam`), as the batch door reads
    /// each chunk an object's seam joins.
    pub(crate) fn exhaust() -> Self {
        Self {
            seam: Some(Seam::default()),
            blocklist: Some(Default::default()),
            ..Self::default()
        }
    }

    /// Reads what the last edge left open: a segment that crossed an edge
    /// and runs to the end of the stream, and the phrase rule's last run.
    pub(crate) fn finish(&mut self) -> Result<()> {
        if let Some(phrases) = &mut self.phrases {
            phrases.finish()?;
        }
        self.seam.as_mut().map_or(Ok(()), Seam::finish)
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(seam) = &mut self.seam {
            seam.feed(bytes)?;
        }
        if let Some(phrases) = &mut self.phrases {
            phrases.feed(&String::from_utf8_lossy(bytes))?;
        }
        if let Some(blocklist) = &mut self.blocklist {
            blocklist.feed(bytes)?;
        }
        for &byte in bytes {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') {
                if !self.token.is_empty() {
                    self.inner.push(byte);
                    if self.inner.len() == 2 * KEY_MAX {
                        self.check_inner(KEY_MAX)?;
                        self.inner.drain(..KEY_MAX);
                    }
                }
                if self.token.len() < 128 {
                    self.token.push(byte);
                }
            } else {
                self.check_token()?;
                self.token.clear();
                self.inner.clear();
            }
            if byte == b'\n' {
                self.begin = 0;
                self.inside = false;
                self.private = 0;
                self.seen_private = false;
                self.dashes = 0;
                continue;
            }
            if !self.inside {
                self.begin = advance(b"-----BEGIN ", self.begin, byte);
                if self.begin == b"-----BEGIN ".len() {
                    self.inside = true;
                    self.begin = 0;
                }
            } else {
                self.private = advance(b"PRIVATE KEY", self.private, byte);
                if self.private == b"PRIVATE KEY".len() {
                    self.seen_private = true;
                    self.private = 0;
                }
                self.dashes = if byte == b'-' { self.dashes + 1 } else { 0 };
                if self.dashes == 5 {
                    if self.seen_private {
                        return Err(denied("gate.secret_scan.private_key"));
                    }
                    self.inside = false;
                    self.private = 0;
                    self.dashes = 0;
                }
            }
        }
        self.check_token()
    }

    fn check_token(&self) -> Result<()> {
        if self.token.len() >= 20
            && matches!(self.token[0], b'A' | b'g' | b's' | b'x' | b'r')
            && let Some(reason) = crate::batch::secret_scan::scan_file_content("", &self.token)
        {
            return Err(denied(reason));
        }
        self.check_inner(self.inner.len())
    }

    /// Reads a key that starts at each of the first `starts` offsets of
    /// [`Self::inner`], as the write door reads one after leading token bytes.
    fn check_inner(&self, starts: usize) -> Result<()> {
        for (start, &byte) in self.inner.iter().enumerate().take(starts) {
            if !matches!(byte, b'A' | b'g' | b's' | b'x' | b'r') {
                continue;
            }
            let candidate = &self.inner[start..self.inner.len().min(start + KEY_MAX)];
            if let Some(reason) = crate::batch::secret_scan::embedded_credential(candidate) {
                return Err(denied(reason));
            }
        }
        Ok(())
    }
}

fn advance(pattern: &[u8], matched: usize, byte: u8) -> usize {
    if matched == 0 {
        return usize::from(byte == pattern[0]);
    }
    if pattern[matched] == byte {
        return matched + 1;
    }
    // Tiny patterns: recomputing the proper prefix is bounded by eleven bytes.
    // This handles six-or-more leading dashes without missing a BEGIN marker.
    let mut candidate = [0u8; 12];
    candidate[..matched].copy_from_slice(&pattern[..matched]);
    candidate[matched] = byte;
    let candidate = &candidate[..matched + 1];
    (1..=pattern.len().min(candidate.len()))
        .rev()
        .find(|&n| candidate.ends_with(&pattern[..n]))
        .unwrap_or(0)
}

fn denied(reason: &'static str) -> Error {
    Error::Gate(GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec!["gate.secret_scan.detected", reason],
    })
}
