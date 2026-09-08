//! Result redaction types, sender trait, and transport hardening policy.

use std::fmt;

use crate::outbound_intent_ledger::{FrozenOutboundCall, OutboundSendOutcome};

/// Raw provider result. Diagnostics redact every provider-controlled field.
pub struct RawOutboundResult {
    body: Option<Vec<u8>>,
    error: Option<String>,
    stderr: Option<Vec<u8>>,
    url: Option<String>,
}

impl RawOutboundResult {
    #[must_use]
    pub fn new(
        body: Option<Vec<u8>>,
        error: Option<String>,
        stderr: Option<Vec<u8>>,
        url: Option<String>,
    ) -> Self {
        Self {
            body,
            error,
            stderr,
            url,
        }
    }

    #[must_use]
    pub fn scrubbable_field_count(&self) -> usize {
        usize::from(self.body.is_some())
            + usize::from(self.error.is_some())
            + usize::from(self.stderr.is_some())
            + usize::from(self.url.is_some())
    }
}

impl fmt::Debug for RawOutboundResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawOutboundResult")
            .field("body", &self.body.as_ref().map(std::vec::Vec::len))
            .field("error", &self.error.as_ref().map(|_| "[redacted]"))
            .field("stderr", &self.stderr.as_ref().map(std::vec::Vec::len))
            .field("url", &self.url.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Provider result after all raw fields have been destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubbedOutboundResult {
    body: bool,
    error: bool,
    stderr: bool,
    url: bool,
}

impl ScrubbedOutboundResult {
    #[must_use]
    pub const fn scrubbed_field_count(self) -> usize {
        self.body as usize + self.error as usize + self.stderr as usize + self.url as usize
    }
}

/// In-memory quarantine carrier. It deliberately implements neither
/// serialization nor accessors for provider-controlled content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantinedOutboundResult {
    scrubbed: ScrubbedOutboundResult,
}

impl QuarantinedOutboundResult {
    #[must_use]
    pub const fn scrubbed_field_count(self) -> usize {
        self.scrubbed.scrubbed_field_count()
    }
}

/// Destructive result-scrub fence at the transport boundary.
#[must_use]
pub fn scrub_outbound_result(raw: RawOutboundResult) -> QuarantinedOutboundResult {
    QuarantinedOutboundResult {
        scrubbed: ScrubbedOutboundResult {
            body: raw.body.is_some(),
            error: raw.error.is_some(),
            stderr: raw.stderr.is_some(),
            url: raw.url.is_some(),
        },
    }
}

/// Result-carrying transport response before adaptation to the intent ledger.
pub struct OutboundTransportResult {
    pub outcome: OutboundSendOutcome,
    pub raw_result: RawOutboundResult,
}

/// Result-carrying transport seam. Implementations receive only the immutable
/// frozen call whose bytes were authorized.
pub trait OutboundResultSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult;
}

/// Stdio child restrictions a real transport must apply before spawn.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StdioSandboxPolicy {
    pub environment_allowlist: Vec<String>,
    pub inherited_fd_allowlist: Vec<u32>,
    pub filesystem_allowlist: Vec<String>,
}

/// Mandatory hardening contract for any real outbound sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTransportPolicy {
    pub stdio_sandbox: StdioSandboxPolicy,
    tls_peer_verification_required: bool,
    resolved_endpoint_disclosure_required: bool,
}

impl OutboundTransportPolicy {
    #[must_use]
    pub const fn new(stdio_sandbox: StdioSandboxPolicy) -> Self {
        Self {
            stdio_sandbox,
            tls_peer_verification_required: true,
            resolved_endpoint_disclosure_required: true,
        }
    }

    #[must_use]
    pub const fn tls_peer_verification_required(&self) -> bool {
        self.tls_peer_verification_required
    }

    #[must_use]
    pub const fn resolved_endpoint_disclosure_required(&self) -> bool {
        self.resolved_endpoint_disclosure_required
    }
}
