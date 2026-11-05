//! Core half of `inbox::actions`: its store-layer items live in `oneiron_store::inbox::actions` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::inbox::actions::*;

use super::list::NotificationRow;
use super::notification::NotificationKind;
use crate::claim::{WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER, WeaveDigestSettingChangeStatus};
use crate::entity_id::EntityId;
use crate::memory::Memory;
use crate::store::conversation_body::{THREAD_NOTICE_PRODUCER, ThreadJoinRequestsRequest};
use serde::{Deserialize, Serialize};

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
