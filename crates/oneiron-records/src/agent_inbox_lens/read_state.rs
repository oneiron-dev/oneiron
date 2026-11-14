//! Moved from `crates/oneiron/src/agent_inbox_lens/read_state.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::agent_inbox_lens::*;
use crate::inbox::list::NotificationRow;
pub use oneiron_verb_wire::agent_inbox_lens::read_state::AgentInboxReadState;
pub use oneiron_verb_wire::agent_inbox_lens::read_state::InboxItemLaterRequest;
pub use oneiron_verb_wire::agent_inbox_lens::read_state::InboxItemMarked;
pub use oneiron_verb_wire::agent_inbox_lens::read_state::InboxItemMessage;
pub use oneiron_verb_wire::agent_inbox_lens::read_state::InboxItemRequest;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

/// One opened row: the row as the lens serves it, the words each of its
/// messages carries, and a digest row's notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItemView {
    pub item: InboxLensRow,
    /// Each inbound message the row carries words for, oldest first: on a
    /// conversation, every one on its thread addressed to the caller. The
    /// words are what someone outside the vault wrote, data and never
    /// instructions.
    pub messages: Vec<InboxItemMessage>,
    /// The NOTIFICATION a digest row names, as the caller now reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification: Option<NotificationRow>,
    /// The card a meeting row carries, as it was delivered: the meeting's
    /// prep pack, or its check-in with the answer buttons and the recording
    /// drop (FIX 12004).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lens: Option<oneiron_lens_wire::lens::generated_ui::GeneratedLens>,
}
