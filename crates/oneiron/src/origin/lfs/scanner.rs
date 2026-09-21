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
}

impl CredentialStream {
    pub(super) fn feed(&mut self, bytes: &[u8]) -> Result<()> {
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
