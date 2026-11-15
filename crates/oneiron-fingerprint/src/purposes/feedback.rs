//! Purposes of feedback (`crates/oneiron/src/feedback`).

purposes! {}

legacy_purposes! {
    /// A report's exact request (`feedback::report::disclosure`): plain BLAKE3, the tag's
    /// bytes (with its final NUL), then the named MessagePack of the `ReportRequest`,
    /// unframed. An issue's disclosure basis stores its hex, the owner's report views return
    /// it, and a fresh digest equal to the stored one keeps an approval.
    REPORT_REQUEST = (Blake3, HashedFirst, "oneiron.report.request_digest.v1\0");
}
