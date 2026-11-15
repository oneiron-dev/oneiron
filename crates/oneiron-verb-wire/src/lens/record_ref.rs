//! Moved from `crates/oneiron/src/lens/record_ref.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_base::request_limits::RECORD_REF_MAX_BYTES;
pub use oneiron_store::record_ref::RECORD_REF_LABEL_MAX_CHARS;
use serde::Deserialize;
use serde::Serialize;

/// `vault.refs.resolve`'s one input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveRecordRefRequest {
    /// The ref to resolve: a short id or a 32-hex id, either one optionally
    /// pinned as `<ref>@<revision>`.
    pub reference: String,
    /// The caller's retrieval filter (FIX 3977): a record it excludes
    /// resolves as one the reader may not read.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

/// `vault.refs.links`'s one input: a text to read for links, the texts a
/// read surface returned, or a TURN whose messages this reader may read, a
/// page at a time. Exactly one of `text`, `texts` and `turn_ref` is named;
/// `after` and `limit` page a turn only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordLinksRequest {
    /// Text to read for `oneiron://` Markdown links.
    #[serde(default)]
    pub text: Option<String>,
    /// The plain texts a read surface returned (a transcript page's
    /// messages, a room's, a recall pack's items), each read for links as
    /// `text` is and answered in order (Engine ruling 10-18): the explicit
    /// link-span read beside those surfaces, whose own text stays plain.
    #[serde(default)]
    pub texts: Option<Vec<String>>,
    /// A TURN ref (short id or 32-hex): each visible message of it this
    /// reader may read is read for links.
    #[serde(default)]
    pub turn_ref: Option<String>,
    /// The `next_after` the previous page of the turn gave: this page reads
    /// the turn's messages after it. `None` reads the first page.
    #[serde(default)]
    pub after: Option<String>,
    /// The most messages the page holds, 1 to
    /// [`RECORD_LINKS_TURN_PAGE_MAX`] (also the default).
    #[serde(default)]
    pub limit: Option<u32>,
    /// The caller's retrieval filter (FIX 3977): the turn's messages and
    /// every link's record are read under it.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}
