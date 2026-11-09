//! Moved from `crates/oneiron/src/dreamer_wake/sieve/audit_windows/finding_identity.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::sieve::SpanKind;
use crate::dreamer_wake::sieve::audit_windows::SieveAuditDiscovery;
use crate::dreamer_wake::sieve::audit_windows::SieveAuditFinding;
use crate::dreamer_wake::sieve::audit_windows::SieveAuditWindow;
use crate::dreamer_wake::sieve::audit_windows::SieveUnlocatedDiscovery;

pub const LOCATED_DOMAIN: &[u8] = b"oneiron:dreamer-sieve:audit-discovery:v1";

pub const UNLOCATED_DOMAIN: &[u8] = b"oneiron:dreamer-sieve:audit-discovery-unlocated:v1";

impl SieveAuditDiscovery {
    /// The discovery's identity, found in `window`: its source, the text
    /// version its offsets index, and those offsets.
    pub fn identity(&self, window: &SieveAuditWindow) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(LOCATED_DOMAIN)
            .update(window.source.as_bytes())
            .update(&window.source_digest)
            .update(&self.start.to_be_bytes())
            .update(&self.end.to_be_bytes())
            .finalize()
            .as_bytes()
    }
}

impl SieveUnlocatedDiscovery {
    /// The discovery's identity, named in `window`: its source, that
    /// source's text version, its kind and the words it quoted.
    pub fn identity(&self, window: &SieveAuditWindow) -> [u8; 32] {
        let kind: &[u8] = match self.kind {
            SpanKind::Date => b"date",
            SpanKind::Name => b"name",
        };
        *blake3::Hasher::new()
            .update(UNLOCATED_DOMAIN)
            .update(window.source.as_bytes())
            .update(&window.source_digest)
            .update(&(kind.len() as u64).to_be_bytes())
            .update(kind)
            .update(&(self.quote.len() as u64).to_be_bytes())
            .update(self.quote.as_bytes())
            .finalize()
            .as_bytes()
    }
}

impl SieveAuditFinding {
    /// The identity of each discovery the finding holds, located ones then
    /// unlocated ones, one per occurrence, in its order.
    pub fn identities(&self) -> Vec<[u8; 32]> {
        self.discovered
            .iter()
            .map(|found| found.identity(&self.window))
            .chain(
                self.unlocated
                    .iter()
                    .map(|found| found.identity(&self.window)),
            )
            .collect()
    }
}
