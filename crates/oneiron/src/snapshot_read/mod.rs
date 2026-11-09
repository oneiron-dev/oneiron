//! Primitive A (slice 6.4, SLICE6-MAP row A): reads any agent makes behind
//! its own grant, with the version of every source it read, so a later commit
//! can prove it cites the same words.
//!
//! Nothing here holds a storage snapshot across calls. A version names a row
//! as one scoped read served it (its type, learned time and the
//! domain-separated hash of its logical body; for a TURN also the fingerprint
//! of the MESSAGE rows its text was projected from), and
//! [`SourceVersion::recheck_in_txn`] judges it again in the caller's own
//! transaction under the caller's live read: the row still reads, and it is
//! the same revision. Every read goes through the caller's `ScopedRead`, so
//! authority, privacy, relationship, audience, sensitivity, device and world
//! filters, source finality and deletion apply to each row.

mod evidence_spans;
mod source_version;

pub use evidence_spans::{
    EVIDENCE_SPANS_MAX_RANGES, EvidenceMessageSlice, EvidenceRange, EvidenceSourceStatus,
    EvidenceSpan, EvidenceSpans, EvidenceSpansRequest, evidence_spans, validate_evidence_spans,
};
pub use source_version::{SourceVersion, SourceVersionCheck};
// The integration tests' doors name a cited source's version as a caller's
// read serves it (untangle 6.7a).
#[cfg(oneiron_test_support)]
pub(crate) use source_version::source_version_in_txn;
