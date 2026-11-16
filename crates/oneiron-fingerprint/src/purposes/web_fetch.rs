//! Purposes of web acquisition (`oneiron-web-fetch`; OF-444).
//!
//! A fetch result's content hash is the identity of its Markdown. Every rung of the
//! renderer ladder writes it into the result; a web import stores it in the source's
//! ASSET row, compares it with that row when the same revision comes again, and derives
//! the import's ids from it; and the result's decode door takes it again over the Markdown
//! beside it and refuses a pair that differs. So it keeps its bytes (K, PLAN-UC-04 6.2).

purposes! {}

legacy_purposes! {
    /// A fetch result's content hash (`web_acquisition::content_hash`,
    /// `FetchResult::content_hash`). BLAKE3: the tag, NUL-terminated and with no length
    /// before it, then the Markdown's bytes; written as 64 lowercase hex digits.
    CONTENT_HASH = (Blake3, HashedFirst, "oneiron.web_fetch.content.v1\0");
}
