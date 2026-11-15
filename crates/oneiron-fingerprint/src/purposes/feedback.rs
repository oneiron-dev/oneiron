//! Purposes of feedback (`crates/oneiron/src/feedback`).

purposes! {}

legacy_purposes! {
    /// A triage part's digest on a long revision's work graph
    /// (`feedback::triage::work::digest`): plain BLAKE3, the tag's bytes and then the part's
    /// text, with no length between them; the graph holds it as lowercase hex, and a part's
    /// answer is checked against it.
    TRIAGE_PART = (Blake3, HashedFirst, "oneiron:feedback-triage:part:v1");

    /// The digest of a triaged item's whole text on its work graph
    /// (`feedback::triage::work::digest`): plain BLAKE3, the tag's bytes and then the text,
    /// with no length between them; held as lowercase hex.
    TRIAGE_ITEM = (Blake3, HashedFirst, "oneiron:feedback-triage:item:v1");
}
