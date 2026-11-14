//! Moved from `crates/oneiron/src/note/files/metadata.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a file has no text in the vault: it is held by its name, and
/// never as text it does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NameOnlyReason {
    /// A format the source takes no text from.
    Unsupported,
    /// Named as text, but its bytes are not UTF-8 text.
    NotText,
    /// Its bytes could not be read, or a PDF that is encrypted or does not
    /// parse.
    Unreadable,
    /// No text: blank, or a PDF with no text layer.
    Empty,
    /// It has another name (a hard link), which may be outside the folder:
    /// its bytes are not read.
    Linked,
    /// The write door's secret scan refused its text: it is held by name,
    /// never as text (FIX 10244).
    Refused,
}

/// Whether the vault holds a file's text, or its name only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileReadiness {
    /// Its text landed as a NOTE (or as its parts).
    Text,
    /// Held by its name only.
    NameOnly { why: NameOnlyReason },
}
