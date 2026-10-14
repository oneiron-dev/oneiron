//! Bounded credential scanning across transport and content-defined boundaries.

use crate::error::{Error, GateError, Result};

/// Retains token prefixes, not arbitrarily long binary/text tokens. All standing
/// token detectors decide within the first 128 bytes. PEM armor is a separate
/// streaming automaton because its header can contain arbitrary padding.
#[derive(Default)]
pub(super) struct CredentialStream {
    token: Vec<u8>,
    begin: usize,
    inside: bool,
    private: usize,
    seen_private: bool,
    dashes: usize,
    seam: Option<Seam>,
    /// The recovery-phrase rule over the whole stream: a phrase's run of
    /// one-word segments crosses the line breaks that end a seam's segment.
    phrases: Option<crate::batch::secret_scan::PhraseStream>,
}

/// The most of one segment a seam keeps, once its padding is squeezed: as
/// much as an object the upload reads whole, so a segment up to that size is
/// read whole however a peer cuts it.
const SEAM_MAX: usize = super::upload::LFS_WHOLE_SCAN_MAX as usize;

/// How much of a run of one repeated character a seam keeps: as much as the
/// longest token any text rule measures (a stream keeps 128 bytes of one too),
/// so the run reads as it did.
const RUN_KEEP: usize = 128;

/// The write door's text rules across feed edges, but for the recovery-phrase
/// rule, which the stream reads whole. A batch scan reads each chunk alone,
/// so a `password=` at one chunk's end and its value at the next one's start
/// meet nowhere else: a segment an edge splits (the text
/// between `\n`, `\r`, `,`, `;`, `{` and `}`, as the assignment rule splits
/// it) is read whole once it ends, in the chunk that ends it or at the end of
/// the stream, so each byte is read once more at most. A peer chooses the
/// edges, and padding must not carry a key away from its value: each run of
/// whitespace reads as one space and each run of one other character as at
/// most [`RUN_KEEP`] of it. A segment still longer than [`SEAM_MAX`] keeps
/// its two ends, the key's side and the side that meets the next edge.
#[derive(Default)]
struct Seam {
    /// The start of a segment cut to its two ends.
    front: Vec<u8>,
    /// The open segment's text since its start (or since its front).
    tail: Vec<u8>,
    /// Whether the open segment crossed an edge, so that no chunk holds it.
    crossed: bool,
    /// The last character kept or squeezed, and how long its run is.
    run: Option<(char, usize)>,
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
            let joined = [self.front.as_slice(), &self.tail].concat();
            crate::batch::secret_scan::scan_write_seam(&String::from_utf8_lossy(&joined))?;
        }
        *self = Self::default();
        Ok(())
    }

    fn carry(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.crossed |= !self.tail.is_empty();
        self.squeeze(bytes);
        // Cut only once the tail is twice what it keeps, so each byte moves
        // once at most.
        if self.tail.len() > SEAM_MAX {
            if self.front.is_empty() {
                self.front = self.tail[..SEAM_MAX / 2].to_vec();
            }
            self.tail.drain(..self.tail.len() - SEAM_MAX / 2);
        }
    }

    /// Appends `bytes` with their padding squeezed: each run of whitespace
    /// (every character the assignment rule trims) to one space, and each
    /// run of one other character past [`RUN_KEEP`] to that many. Bytes that
    /// are not text (a character an edge cut in two) stay as they are.
    fn squeeze(&mut self, bytes: &[u8]) {
        for chunk in bytes.utf8_chunks() {
            for ch in chunk.valid().chars() {
                let ch = if ch.is_whitespace() { ' ' } else { ch };
                let run = match self.run {
                    Some((previous, run)) if previous == ch => run + 1,
                    _ => 1,
                };
                self.run = Some((ch, run));
                if run <= if ch == ' ' { 1 } else { RUN_KEEP } {
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
    /// A stream that also reads the write door's text rules across each feed
    /// edge ([`Seam`]). `on` is the owner's `secrets` switch, which the batch
    /// door that scans each chunk follows too.
    pub(super) fn with_write_seam(on: bool) -> Self {
        Self {
            seam: on.then(Seam::default),
            phrases: on.then(Default::default),
            ..Self::default()
        }
    }

    /// Reads what the last edge left open: a segment that crossed an edge
    /// and runs to the end of the stream, and the phrase rule's last run.
    pub(super) fn finish(&mut self) -> Result<()> {
        if let Some(phrases) = &mut self.phrases {
            phrases.finish()?;
        }
        self.seam.as_mut().map_or(Ok(()), Seam::finish)
    }

    pub(super) fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(seam) = &mut self.seam {
            seam.feed(bytes)?;
        }
        if let Some(phrases) = &mut self.phrases {
            phrases.feed(&String::from_utf8_lossy(bytes))?;
        }
        for &byte in bytes {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') {
                if self.token.len() < 128 {
                    self.token.push(byte);
                }
            } else {
                self.check_token()?;
                self.token.clear();
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
        if self.token.len() < 20 || !matches!(self.token[0], b'A' | b'g' | b's' | b'x' | b'r') {
            return Ok(());
        }
        if let Some(reason) = crate::batch::secret_scan::scan_file_content("", &self.token) {
            return Err(denied(reason));
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
