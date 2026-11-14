//! Moved from `crates/oneiron/src/verbs/asset_masked_read.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.assets.masked_read`'s answer: the ASSET's hex ref with its bytes,
/// always masked, as standard base64. A repo file a mark covers, or a value
/// custody knows reads in, answers its projection, and a file stored with
/// keys in it its copy with each key overwritten; every other ASSET answers
/// its stored bytes. Missing, withheld and non-ASSET refs answer none, not
/// this, and so does an ASSET no masked copy is served of or whose bytes
/// the release scan still reads a credential in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MaskedAssetRead {
    /// The ASSET read, as 32 hex.
    pub entity_ref: String,
    /// Its bytes as a masked reader reads them, as standard base64.
    pub body_base64: String,
}
