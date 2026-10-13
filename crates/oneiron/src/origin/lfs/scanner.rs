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

/// The longest run of one segment a seam keeps on either side of an edge.
const SEAM_MAX: usize = 1024;

/// The write door's text rules across a feed edge. A batch scan reads each
/// chunk alone, so a `password=` at one chunk's end and its value at the
/// next one's start meet nowhere else: the segment an edge splits (the text
/// between `\n`, `\r`, `,`, `;`, `{` and `}`, as the assignment rule splits
/// it) is read whole. A segment longer than [`SEAM_MAX`] before the edge is
/// not carried: the chunk that holds its start holds its key and value too.
#[derive(Default)]
struct Seam {
    tail: Vec<u8>,
    overlong: bool,
}

impl Seam {
    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        let head_end = bytes.iter().position(|byte| segment_break(*byte));
        if !self.tail.is_empty() && !self.overlong {
            let head = &bytes[..head_end.unwrap_or(bytes.len()).min(SEAM_MAX)];
            let joined = [self.tail.as_slice(), head].concat();
            crate::batch::secret_scan::scan_write_seam(&String::from_utf8_lossy(&joined))?;
        }
        match bytes.iter().rposition(|byte| segment_break(*byte)) {
            Some(at) => {
                self.tail.clear();
                self.overlong = false;
                self.carry(&bytes[at + 1..]);
            }
            None => self.carry(bytes),
        }
        Ok(())
    }

    fn carry(&mut self, run: &[u8]) {
        if self.overlong || self.tail.len() + run.len() > SEAM_MAX {
            self.tail.clear();
            self.overlong = true;
        } else {
            self.tail.extend_from_slice(run);
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
