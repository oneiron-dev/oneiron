//! Private, synchronous per-vault Unix socket adapter for the real retrieval bridge.
//!
//! The host supplies an active, owner-only runtime directory, an `Arc<Vault>`,
//! and a concrete [`super::PartialEnricher`] for each connection. Binding is NOT
//! model readiness. There is no production enricher, fabricated signature, voice
//! orchestrator, TCP listener, or public HTTP route here. Pipecat retains audio
//! and scheduling ownership. Live TINY, LiveKit, interruption and memory/soak
//! requirements remain unpassed successor gates.
//!
//! One newline-delimited JSON request produces one response. Operations are
//! `open {utterance_id}`, `partial/final {handle, revision, text}`, and
//! `close {handle}`, each with an `op` field. Unknown fields (including provider
//! labels, terms, vectors and cap settings) are rejected. Handles are opaque,
//! connection-local tokens, not caller utterance ids. One utterance is open per
//! connection. Finalization follows the core's consume-on-retrieval-error rule.
//! Responses contain ordered refs only; resolving them still requires ordinary
//! disclosure gates. Error codes never contain parser, provider or vault errors.
//!
//! Each accepted partial and final must call the host enricher. Host errors return
//! `bridge_error` without retrieval and leave the observation retryable. Successful
//! empty enrichment is valid: the core `SpeculativeSession` returns
//! `SkippedEmptySignature` (`skipped_empty_signature` on the wire) for a partial
//! and performs normal final retrieval. This is not an enrichment bypass; the
//! adapter never invents labels, terms or vectors.
//!
//! The host bounds concurrent workers and supplies independent enrichers. No
//! global voice-loop lock is used. Shutdown interrupts socket waits, not a host
//! enricher or synchronous vault call already running; those need host deadlines.
//! A connection has bounded frames, requests, errors, idle time and frame time.
//!
//! Filesystem binding currently uses Linux descriptor-relative paths; other
//! Unix targets fail closed with `Unsupported`. The runtime directory must be
//! host-owned and inaccessible to group/other users. Its owner is trusted not
//! to race filesystem mutations. Ancestors are opened without following links;
//! cleanup uses the pinned directory and checks socket identity before unlink.

mod codec;
mod connection;
mod socket;

pub use connection::{Connection, Shutdown};
pub use socket::SocketGuard;

use crate::speculative::SpeculativeSessionConfig;

/// Hard wire limits, independent of untrusted request fields.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_TEXT_BYTES: usize = 8 * 1024;
pub const MAX_RESULT_REFS: usize = 64;

/// Trusted host policy. No request can override these values.
#[derive(Debug, Clone, Copy)]
pub struct BridgeLimits {
    pub max_fires: u8,
    pub fire_limit: usize,
    pub final_limit: usize,
}

impl Default for BridgeLimits {
    fn default() -> Self {
        Self {
            max_fires: 4,
            fire_limit: 8,
            final_limit: 32,
        }
    }
}

impl BridgeLimits {
    fn validate(self) -> std::io::Result<Self> {
        if self.max_fires > 4
            || !(1..=MAX_RESULT_REFS).contains(&self.fire_limit)
            || !(1..=MAX_RESULT_REFS).contains(&self.final_limit)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid bridge limits",
            ));
        }
        Ok(self)
    }

    fn session_config(self) -> SpeculativeSessionConfig {
        SpeculativeSessionConfig {
            max_fires: self.max_fires,
            fire_limit: self.fire_limit,
            final_limit: self.final_limit,
        }
    }
}

#[cfg(test)]
mod tests;
