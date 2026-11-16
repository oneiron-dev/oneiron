//! Purposes of the MCP endpoint (`crates/oneiron-server/src/mcp`).
//!
//! A continuable page binds the call's arguments by their digest: the server keeps the
//! digest with the page, mints the cursor it hands the client over it, and refuses a
//! resumed call whose own arguments give another. A call whose content its host holds
//! outside the payload must give the digest the whole payload would. It keeps its bytes
//! (K, PLAN-UC-04 stage 6.4c).

purposes! {}

legacy_purposes! {
    /// A call's page-argument digest (`mcp::mcp_page_argument_digest`, and its twin for
    /// held content): BLAKE3, the tag's bytes, then the u64 big-endian length of the
    /// arguments' canonical JSON (less their `page` member) and that JSON.
    PAGE_ARGUMENTS = (Blake3, HashedFirst, "oneiron.mcp.page-arguments.v2");
}
