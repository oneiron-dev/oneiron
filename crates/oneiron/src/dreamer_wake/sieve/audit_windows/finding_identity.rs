//! A window audit's discovery identity (FIX 7903). Windows are drawn again
//! each weave, and a source's pieces move when its flagged spans move, so
//! the same span the rules missed can be found by more than one audit. A
//! located discovery is the same discovery wherever it was found: its
//! source, the text version its offsets index and those offsets, never the
//! window or the draw that found it. An unlocated one (FIX 7901) is its
//! source and text version, its kind and the words it quoted. Every audit
//! keeps its own occurrence, its window and its offsets; the identity only
//! groups them.

use std::collections::BTreeMap;

use super::{SieveAuditDiscovery, SieveAuditFinding, SieveAuditWindow, SieveUnlocatedDiscovery};
use crate::dreamer_wake::sieve::SpanKind;

const LOCATED_DOMAIN: &[u8] = b"oneiron:dreamer-sieve:audit-discovery:v1";
const UNLOCATED_DOMAIN: &[u8] = b"oneiron:dreamer-sieve:audit-discovery-unlocated:v1";

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

/// The distinct discoveries `findings` hold, each with how many times it
/// was found among them: every occurrence counts, none is dropped.
pub(crate) fn distinct_discoveries(findings: &[&SieveAuditFinding]) -> BTreeMap<[u8; 32], u64> {
    let mut found = BTreeMap::new();
    for identity in findings.iter().flat_map(|finding| finding.identities()) {
        *found.entry(identity).or_insert(0) += 1;
    }
    found
}
