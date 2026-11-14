//! Moved from `crates/oneiron/src/inbox/list.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::inbox::actions::NotificationAction;
use crate::inbox::notification::NotificationKind;
use crate::inbox::notification::NotificationSource;
pub use oneiron_verb_wire::inbox::list::NotificationMark;
use serde::Deserialize;
use serde::Serialize;

/// One delivered notification as its caller reads it: the caller's own seen
/// and acknowledged state, never another caller's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRow {
    pub id: String,
    /// When the row was last recorded.
    pub learned_at: u64,
    pub kind: NotificationKind,
    pub source: NotificationSource,
    pub subject_refs: Vec<String>,
    /// When the event happened.
    pub created_at: u64,
    pub origin_conversation: Option<String>,
    pub seen: bool,
    pub acked: bool,
    /// The taps the row offers its caller now, each a registered verb and
    /// its input (FIX 5629, 6505). Projected when the row is read, never
    /// stored; empty for a row with none, or whose target has settled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<NotificationAction>,
}

/// One inbox page in entity-ID order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationPage {
    pub rows: Vec<NotificationRow>,
    /// Explicit end marker: `None` means no further delivered row exists.
    pub next_after: Option<String>,
    /// The rows this page could hold: the caller's limit.
    #[serde(default)]
    pub effective_limit: usize,
    /// Whether the request was larger than one page (always false: the page
    /// holds the caller's limit; `next_after` continues when more rows remain).
    #[serde(default)]
    pub limit_clamped: bool,
}
