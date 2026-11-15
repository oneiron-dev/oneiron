//! Moved from `crates/oneiron/src/mail_pack/search.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.mail.sources.search`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceSearchRequest {
    /// The mailbox source, 32-hex.
    pub source_ref: String,
    /// The query, in the provider's own search language: Gmail's search
    /// operators for a Google mailbox, Microsoft Graph's `$search` text for
    /// a Microsoft 365 one, `SEARCH` keys (RFC 3501 6.4.4, such as
    /// `FROM "ann" SINCE 1-Jan-2025`) for an IMAP one.
    pub query: String,
    /// The provider's token for the next page of hits, as the last page
    /// returned it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// The hits this page lands: 25 when absent, at most 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// What one search page found and landed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSearchReport {
    /// The mailbox source, 32-hex.
    pub source_ref: String,
    /// The messages the page found.
    pub found: u32,
    /// The messages it landed whole now.
    pub landed: u32,
    /// The messages the vault held already, or forgot.
    pub same: u32,
    /// The messages a gate refused, or the provider no longer had.
    pub skipped: u32,
    /// The provider's token for the next page of hits; absent at the end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page: Option<String>,
}
