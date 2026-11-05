//! FIX 5629, 6505: the taps a delivered notification offers, read when its
//! row is read, from the refs its producer already wrote. Nothing here is
//! stored: there is no action ledger, a settled or stale target offers no
//! tap, and the door each tap names judges its target again when called.

use serde::{Deserialize, Serialize};

use crate::conversation_body::THREAD_NOTICE_PRODUCER;
use crate::conversation_body::ThreadJoinRequestsRequest;
use crate::write_envelope::claim_body::lexical_query_hint::WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER;
use crate::write_envelope::claim_body::lexical_query_hint::WeaveDigestSettingChangeStatus;
use oneiron_contracts::entity_id::EntityId;

/// The owner's answer to a proposed digest settings change.
pub const WEAVE_SETTING_ANSWER_VERB: &str = "vault.weave.setting_changes.answer";
/// The owner's undo of an applied or accepted digest settings change.
pub const WEAVE_SETTING_UNDO_VERB: &str = "vault.weave.setting_changes.undo";
/// A member's approval of a request to join a private thread.
pub const THREAD_JOIN_APPROVE_VERB: &str = "vault.rooms.thread_join.approve";
/// A member's denial of a request to join a private thread.
pub const THREAD_JOIN_DENY_VERB: &str = "vault.rooms.thread_join.deny";

/// One tap a notification offers: the registered verb it calls and that
/// verb's own input, so a client renders the button the engine describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAction {
    /// The registered verb the tap calls.
    pub verb: String,
    /// The verb's input, as its own fields name it.
    pub args: serde_json::Value,
}

impl NotificationAction {
    pub fn new(verb: &str, args: serde_json::Value) -> Self {
        Self {
            verb: verb.to_owned(),
            args,
        }
    }
}
