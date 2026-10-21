//! A row: one element a program reads or acts on, and what its page shows
//! of it beyond its role and name (FIX 6851): where a link goes, a
//! heading's level, and the datetimes the element carries. An absent field
//! is no such datum; one the read could not give is named in `unavailable`,
//! never left silently absent. A secret's row carries the handle its value
//! became (FIX 8028), never the value.

use crate::RowSecret;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One element a program can read or act on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Row {
    /// The row's live handle: on a page, its DOM node in its document, never
    /// reused within the session; on a desktop, its locator.
    #[serde(rename = "ref")]
    pub target: String,
    /// The row's semantic locator (its role, name and named ancestors): what
    /// a replay program stores, resolved on the page as it is then.
    pub locator: String,
    pub role: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<String>,
    pub depth: u16,
    /// Where a link row goes: its whole destination, resolved against its
    /// document's base, in whatever scheme it names (http, https, mailto,
    /// tel, data, javascript, which is never run, or another). Only link
    /// rows carry one; a link with no destination carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    /// A heading row's semantic level, 1 the highest, as its engine reads
    /// it. Only heading rows carry one; `depth` stays the row's nesting
    /// among named scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    /// The `datetime` attribute texts the row's element carries, as
    /// written, in document order: its own, else its nearest DOM
    /// ancestor's, and on a link or control row every one inside it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datetimes: Vec<String>,
    /// The fields this row may hold that its read could not fill, and why:
    /// a field named here is unknown, not absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<RowFieldGap>,
    /// The secret the row's value is (FIX 8028): its kind and the run-bound
    /// handle it became where it was found, or why it has none. `value`
    /// then shows the handle, a card's last four digits with it, never the
    /// secret; a type or expect names the handle as its `secret`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<RowSecret>,
}

/// A row field its read could not fill, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RowFieldGap {
    pub field: RowGapField,
    pub reason: RowGapReason,
}

/// The row fields a gap can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RowGapField {
    Href,
    Level,
    Datetime,
}

/// Why a row field is unavailable: the reason set (FIX 6851).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RowGapReason {
    /// The row's accessibility node names no DOM node (generated text).
    NoDomNode,
    /// The page's DOM read no longer holds the row's node: the page moved
    /// between its reads.
    StaleNode,
    /// The row's node sits in a frame the engine's DOM read does not cover.
    OutsideDomRead,
    /// The DOM read failed (past the message bound, an engine error or its
    /// time); the rest of the answer stands.
    ReadFailed,
    /// The row's destination has no whole form: a relative href with no
    /// usable base, one that does not parse, or a cut accessibility
    /// destination with no href attribute to complete it.
    Unresolvable,
}
