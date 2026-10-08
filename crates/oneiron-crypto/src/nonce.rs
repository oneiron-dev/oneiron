//! Duplicate-nonce detection where the caller can see it.
//!
//! The real guarantee is the fresh 32-byte salt per envelope: the payload key is
//! unique per envelope, so a repeated nonce alone does not reuse a key/nonce pair.
//! The ledger is a stricter, optional guard on top: it refuses a second envelope
//! with the same `(key id, nonce)` seen by one ledger. It lives in memory only and
//! promises nothing across processes.

use std::collections::HashSet;

use crate::envelope::Envelope;
use crate::error::{Error, Result};

/// Remembers `(key id, nonce)` pairs. Feed it envelopes this process sealed, or
/// envelopes that already opened; never unauthenticated input.
#[derive(Debug, Default)]
pub struct NonceLedger {
    seen: HashSet<(Vec<u8>, Vec<u8>)>,
}

impl NonceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the envelope's `(key id, nonce)`; refuses a pair seen before.
    pub fn record(&mut self, envelope: &Envelope) -> Result<()> {
        let header = envelope.header();
        if self
            .seen
            .insert((header.key_id.clone(), header.nonce.clone()))
        {
            Ok(())
        } else {
            Err(Error::DuplicateNonce)
        }
    }
}
