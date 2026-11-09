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

use super::SieveAuditFinding;

#[doc(hidden)]

/// The distinct discoveries `findings` hold, each with how many times it
/// was found among them: every occurrence counts, none is dropped.
pub(crate) fn distinct_discoveries(findings: &[&SieveAuditFinding]) -> BTreeMap<[u8; 32], u64> {
    let mut found = BTreeMap::new();
    for identity in findings.iter().flat_map(|finding| finding.identities()) {
        *found.entry(identity).or_insert(0) += 1;
    }
    found
}
