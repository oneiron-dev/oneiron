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
}

/// The most of one segment a seam keeps on either side of an edge, once its
/// padding is squeezed.
const SEAM_MAX: usize = 1024;

/// How much of a run of one repeated character a seam keeps: as much as the
/// longest token any text rule measures (a stream keeps 128 bytes of one too),
/// so the run reads as it did.
const RUN_KEEP: usize = 128;

/// The write door's text rules across a feed edge. A batch scan reads each
/// chunk alone, so a `password=` at one chunk's end and its value at the
/// next one's start meet nowhere else: the segment an edge splits (the text
/// between `\n`, `\r`, `,`, `;`, `{` and `}`, as the assignment rule splits
/// it) is read whole. A peer chooses the edges, and padding must not carry a
/// key away from its value: each run of whitespace reads as one space and
/// each run of one other character as at most [`RUN_KEEP`] of it. A segment
/// still longer than [`SEAM_MAX`] keeps its two ends, the key's side and the
/// side that meets the edge.
#[derive(Default)]
struct Seam {
    /// The start of a segment cut to its two ends.
    front: Vec<u8>,
    /// The segment's text up to the edge (its last part, once cut).
    tail: Vec<u8>,
}

impl Seam {
    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        if !self.tail.is_empty() {
            let head_end = bytes
                .iter()
                .position(|byte| segment_break(*byte))
                .unwrap_or(bytes.len());
            let mut head = squeeze(&bytes[..head_end]);
            if head.len() > SEAM_MAX {
                head.drain(SEAM_MAX / 2..head.len() - SEAM_MAX / 2);
            }
            let joined = [self.front.as_slice(), &self.tail, &head].concat();
            crate::batch::secret_scan::scan_write_seam(&String::from_utf8_lossy(&joined))?;
        }
        match bytes.iter().rposition(|byte| segment_break(*byte)) {
            Some(at) => {
                self.front.clear();
                self.tail.clear();
                self.carry(&bytes[at + 1..]);
            }
            None => self.carry(bytes),
        }
        Ok(())
    }

    fn carry(&mut self, run: &[u8]) {
        self.tail.extend_from_slice(run);
        self.tail = squeeze(&self.tail);
        if self.front.len() + self.tail.len() > SEAM_MAX {
            if self.front.is_empty() {
                self.front = self.tail[..SEAM_MAX / 2].to_vec();
            }
            self.tail.drain(..self.tail.len() - SEAM_MAX / 2);
        }
    }
}

/// `bytes` with their padding squeezed: each run of whitespace (every
/// character the assignment rule trims) to one space, and each run of one
/// other character past [`RUN_KEEP`] to that many. Bytes that are not text
/// (a character an edge cut in two) stay as they are.
fn squeeze(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut previous = None;
    let mut run = 0;
    for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            let ch = if ch.is_whitespace() { ' ' } else { ch };
            run = if previous == Some(ch) { run + 1 } else { 1 };
            previous = Some(ch);
            let keep = if ch == ' ' { 1 } else { RUN_KEEP };
            if run <= keep {
                out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
            }
        }
        if !chunk.invalid().is_empty() {
            out.extend_from_slice(chunk.invalid());
            previous = None;
        }
    }
    out
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
            ..Self::default()
        }
    }

    pub(super) fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(seam) = &mut self.seam {
            seam.feed(bytes)?;
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
