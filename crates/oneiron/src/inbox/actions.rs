//! FIX 5629, 6505: the taps a delivered notification offers, read when its
//! row is read, from the refs its producer already wrote. Nothing here is
//! stored: there is no action ledger, a settled or stale target offers no
//! tap, and the door each tap names judges its target again when called.

use serde::{Deserialize, Serialize};

use super::list::NotificationRow;
use super::notification::NotificationKind;
use crate::claim::{WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER, WeaveDigestSettingChangeStatus};
use crate::entity_id::EntityId;
use crate::memory::Memory;
use crate::workspace_roster::{THREAD_NOTICE_PRODUCER, ThreadJoinRequestsRequest};

/// The owner's answer to a proposed digest settings change.
const WEAVE_SETTING_ANSWER_VERB: &str = "vault.weave.setting_changes.answer";
/// The owner's undo of an applied or accepted digest settings change.
const WEAVE_SETTING_UNDO_VERB: &str = "vault.weave.setting_changes.undo";
/// A member's approval of a request to join a private thread.
const THREAD_JOIN_APPROVE_VERB: &str = "vault.rooms.thread_join.approve";
/// A member's denial of a request to join a private thread.
const THREAD_JOIN_DENY_VERB: &str = "vault.rooms.thread_join.deny";

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
    fn new(verb: &str, args: serde_json::Value) -> Self {
        Self {
            verb: verb.to_owned(),
            args,
        }
    }
}

impl Memory<'_> {
    /// `row` with the taps it offers this caller now.
    pub(super) fn with_notification_actions(&self, mut row: NotificationRow) -> NotificationRow {
        row.actions = self.notification_actions(&row);
        row
    }

    /// The taps `row` offers this caller now: a pending digest settings ask
    /// is accepted or declined and an applied change undone (FIX 5629), and
    /// a pending request to join a private thread is approved or denied
    /// (FIX 6505). Any other row, and a target that no longer reads or has
    /// settled, offers none.
    fn notification_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let producer = row.source.producer.as_str();
        match row.kind {
            NotificationKind::Ask | NotificationKind::WeaveDigestSettingsChanged
                if producer == WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER =>
            {
                self.weave_setting_actions(row)
            }
            NotificationKind::ThreadJoinRequested if producer == THREAD_NOTICE_PRODUCER => {
                self.thread_join_actions(row)
            }
            _ => Vec::new(),
        }
    }

    /// The producer names the change in `source.result`; the notice is the
    /// caller's own, so the caller is the owner whose change it is.
    fn weave_setting_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let Some(change) = row
            .source
            .result
            .as_deref()
            .and_then(|change| EntityId::from_hex(change).ok())
        else {
            return Vec::new();
        };
        let vault = self.vault();
        let status = vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)
            .and_then(|txn| vault.weave_digest_setting_change_tap_in(&txn, self.actor(), change));
        let change_ref = change.to_hex();
        match (row.kind, status) {
            (NotificationKind::Ask, Ok(Some(WeaveDigestSettingChangeStatus::Pending))) => {
                [true, false]
                    .into_iter()
                    .map(|accept| {
                        NotificationAction::new(
                            WEAVE_SETTING_ANSWER_VERB,
                            serde_json::json!({ "change_ref": change_ref, "accept": accept }),
                        )
                    })
                    .collect()
            }
            (
                NotificationKind::WeaveDigestSettingsChanged,
                Ok(Some(
                    WeaveDigestSettingChangeStatus::Applied
                    | WeaveDigestSettingChangeStatus::Accepted,
                )),
            ) => vec![NotificationAction::new(
                WEAVE_SETTING_UNDO_VERB,
                serde_json::json!({ "change_ref": change_ref }),
            )],
            _ => Vec::new(),
        }
    }

    /// The producer names the thread's root in `source.result` and writes
    /// its subjects as the root, the one who asked, then the request's TURN
    /// (`ThreadNotice::subjects`): approve and deny need both the root and
    /// that request, never the root alone. Shown while the request is still
    /// pending for this caller, a member of the thread now.
    fn thread_join_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let (Some(thread_ref), Some(request_ref)) =
            (row.source.result.as_deref(), row.subject_refs.get(2))
        else {
            return Vec::new();
        };
        if row.subject_refs.first().map(String::as_str) != Some(thread_ref) {
            return Vec::new();
        }
        let pending = self
            .rooms_thread_join_requests(&ThreadJoinRequestsRequest {
                thread_ref: thread_ref.to_owned(),
            })
            .is_ok_and(|requests| {
                requests
                    .iter()
                    .any(|request| request.request_ref == *request_ref)
            });
        if !pending {
            return Vec::new();
        }
        let args = serde_json::json!({ "thread_ref": thread_ref, "request_ref": request_ref });
        vec![
            NotificationAction::new(THREAD_JOIN_APPROVE_VERB, args.clone()),
            NotificationAction::new(THREAD_JOIN_DENY_VERB, args),
        ]
    }
}
