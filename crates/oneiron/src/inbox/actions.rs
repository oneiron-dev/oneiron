//! FIX 5629, 6505, 4902, 4747, 5369: the taps a delivered notification offers, read
//! when its row is read, from the refs its producer already wrote. Nothing here is
//! stored: there is no action ledger, a settled or stale target offers no
//! tap, and the door each tap names judges its target again when called.

use serde::{Deserialize, Serialize};

use super::list::NotificationRow;
use super::notification::NotificationKind;
use crate::agent_dispatch::{AGENT_RUN_EFFECT_ANSWER_VERB, AGENT_RUN_EFFECT_NOTIFICATION_PRODUCER};
use crate::authority::OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER;
use crate::claim::{WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER, WeaveDigestSettingChangeStatus};
use crate::engine_executor::resume_divergence::{
    RESUME_DIVERGENCE_ANSWER_VERB, RESUME_DIVERGENCE_NOTIFICATION_PRODUCER,
};
use crate::entity_id::EntityId;
use crate::llm::model_pack::{MODEL_PACK_CHANGE_NOTIFICATION_PRODUCER, MODEL_PACK_REVERT_VERB};
use crate::memory::Memory;
use crate::outbound::{UNCERTAIN_SEND_ANSWER_VERB, UNCERTAIN_SEND_NOTIFICATION_PRODUCER};
use crate::skill_optimize::STOCK_SWITCH_NOTIFICATION_PRODUCER;
use crate::store::conversation_body::{THREAD_NOTICE_PRODUCER, ThreadJoinRequestsRequest};

/// The owner's answer to a proposed digest settings change.
const WEAVE_SETTING_ANSWER_VERB: &str = "vault.weave.setting_changes.answer";
/// The owner's undo of an applied or accepted digest settings change.
const WEAVE_SETTING_UNDO_VERB: &str = "vault.weave.setting_changes.undo";
/// The owner's undo of an applied stock-model switch.
const STOCK_SWITCH_UNDO_VERB: &str = "vault.coach.training_offers.undo";
/// A member's approval of a request to join a private thread.
const THREAD_JOIN_APPROVE_VERB: &str = "vault.rooms.thread_join.approve";
/// A member's denial of a request to join a private thread.
const THREAD_JOIN_DENY_VERB: &str = "vault.rooms.thread_join.deny";
/// The owner's answer to an outside app's OAuth sign-in request (FIX 4902).
const OAUTH_AUTHORIZATION_ANSWER_VERB: &str = "vault.oauth.authorization.answer";

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
    /// is accepted or declined and an applied change undone (FIX 5629), a
    /// pending request to join a private thread is approved or denied
    /// (FIX 6505), a waiting OAuth sign-in request is allowed at the tier it
    /// asked for or denied (FIX 4902), a send that may have gone out, or a
    /// call a moved agent run's replayed step makes that its earlier machine
    /// may have made, is sent again or left (FIX 4747), and a model pack
    /// change is reverted (FIX 5369). An applied stock switch offers the
    /// owner's undo while its binding still holds (FIX 4663). Any other row,
    /// and a target that no longer reads or has settled, offers none.
    fn notification_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let producer = row.source.producer.as_str();
        match row.kind {
            NotificationKind::Ask | NotificationKind::WeaveDigestSettingsChanged
                if producer == WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER =>
            {
                self.weave_setting_actions(row)
            }
            NotificationKind::Finding if producer == STOCK_SWITCH_NOTIFICATION_PRODUCER => {
                self.stock_switch_actions(row)
            }
            NotificationKind::ThreadJoinRequested if producer == THREAD_NOTICE_PRODUCER => {
                self.thread_join_actions(row)
            }
            NotificationKind::Ask if producer == OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER => {
                self.oauth_authorization_actions(row)
            }
            NotificationKind::Ask if producer == UNCERTAIN_SEND_NOTIFICATION_PRODUCER => {
                self.uncertain_send_actions(row)
            }
            NotificationKind::Ask if producer == AGENT_RUN_EFFECT_NOTIFICATION_PRODUCER => {
                self.agent_run_effect_actions(row)
            }
            NotificationKind::Ask if producer == RESUME_DIVERGENCE_NOTIFICATION_PRODUCER => {
                self.resume_divergence_actions(row)
            }
            NotificationKind::ModelPackChanged
                if producer == MODEL_PACK_CHANGE_NOTIFICATION_PRODUCER =>
            {
                self.model_pack_revert_actions(row)
            }
            NotificationKind::Ask if producer == crate::mail_pack::MAIL_REPLY_ASK_PRODUCER => {
                self.mail_reply_ask_actions(row)
            }
            _ => Vec::new(),
        }
    }

    /// The producer names the request in `source.result`; the ask is the
    /// vault owner's, and only his proof answers it. Shown while the request
    /// still waits: allow at the tier it asked for, or deny. The owner's own
    /// client may send another tier or a world with the same verb.
    fn oauth_authorization_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let Some(request) = row
            .source
            .result
            .as_deref()
            .and_then(|request| EntityId::from_hex(request).ok())
        else {
            return Vec::new();
        };
        let vault = self.vault();
        let asked = vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)
            .and_then(|txn| {
                vault.oauth_authorization_tap_in(&txn, request, crate::unix_seconds_now())
            });
        let Ok(Some(tier)) = asked else {
            return Vec::new();
        };
        let request_ref = request.to_hex();
        vec![
            NotificationAction::new(
                OAUTH_AUTHORIZATION_ANSWER_VERB,
                serde_json::json!({
                    "request_ref": request_ref,
                    "allow": true,
                    "tier": tier.wire_name(),
                }),
            ),
            NotificationAction::new(
                OAUTH_AUTHORIZATION_ANSWER_VERB,
                serde_json::json!({ "request_ref": request_ref, "allow": false }),
            ),
        ]
    }

    /// The producer names the connector-send TASK in `source.result`; the
    /// ask is a vault owner's, and only an owner's proof answers it. Shown
    /// while the send still waits for an answer: send it once more, or
    /// leave it.
    fn uncertain_send_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let Some(task) = row
            .source
            .result
            .as_deref()
            .and_then(|task| EntityId::from_hex(task).ok())
        else {
            return Vec::new();
        };
        let vault = self.vault();
        let waits = vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)
            .and_then(|txn| vault.uncertain_send_awaits_owner_in(&txn, task));
        if !matches!(waits, Ok(true)) {
            return Vec::new();
        }
        let task_ref = task.to_hex();
        [true, false]
            .into_iter()
            .map(|resend| {
                NotificationAction::new(
                    UNCERTAIN_SEND_ANSWER_VERB,
                    serde_json::json!({ "task_ref": task_ref, "resend": resend }),
                )
            })
            .collect()
    }

    /// The producer names the run TASK in `source.result` and the effect's
    /// intent id in `source.event` (FIX 4747 slice 7); the ask is a vault
    /// owner's, and only an owner's proof answers it. Shown while the effect
    /// still waits for an answer: make the call again, or leave it.
    fn agent_run_effect_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let Some((task, intent)) = crate::agent_dispatch::agent_run_effect_ask_target(&row.source)
        else {
            return Vec::new();
        };
        let vault = self.vault();
        let waits = vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)
            .and_then(|txn| vault.agent_run_effect_awaits_owner_in(&txn, task, &intent));
        if !matches!(waits, Ok(true)) {
            return Vec::new();
        }
        let task_ref = task.to_hex();
        [true, false]
            .into_iter()
            .map(|resend| {
                NotificationAction::new(
                    AGENT_RUN_EFFECT_ANSWER_VERB,
                    serde_json::json!({
                        "task_ref": task_ref,
                        "intent_ref": intent,
                        "resend": resend,
                    }),
                )
            })
            .collect()
    }

    /// The producer names the run in `source.result` and the step and effect digest in
    /// `source.event` (L8-23); the ask is a vault owner's, and only an owner's proof answers it.
    /// Shown while the step still waits for an answer: re-fire the changed effect steps once, or
    /// leave them.
    fn resume_divergence_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let Some((run, step_seq, digest)) =
            crate::engine_executor::resume_divergence::resume_divergence_ask_target(&row.source)
        else {
            return Vec::new();
        };
        let vault = self.vault();
        let waits = vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)
            .and_then(|txn| vault.resume_divergence_awaits_owner_in(&txn, run, step_seq, &digest));
        if !matches!(waits, Ok(true)) {
            return Vec::new();
        }
        let run_ref = run.to_hex();
        ["refire", "leave"]
            .into_iter()
            .map(|choice| {
                NotificationAction::new(
                    RESUME_DIVERGENCE_ANSWER_VERB,
                    serde_json::json!({
                        "run_ref": run_ref,
                        "step_seq": step_seq,
                        "report_digest": digest,
                        "choice": choice,
                    }),
                )
            })
            .collect()
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

    fn stock_switch_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let Some(offer) = row
            .source
            .result
            .as_deref()
            .and_then(|offer| EntityId::from_hex(offer).ok())
        else {
            return Vec::new();
        };
        let available = (|| {
            let owner = self.embedded_owner(STOCK_SWITCH_UNDO_VERB)?;
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)
                .map_err(crate::memory::MemoryError::from)?;
            crate::skill_optimize::training_offer_switch_undo_available_in_txn(
                self.vault(),
                &txn,
                &owner,
                &offer,
            )
            .map_err(crate::memory::MemoryError::from)
        })();
        if matches!(available, Ok(true)) {
            vec![NotificationAction::new(
                STOCK_SWITCH_UNDO_VERB,
                serde_json::json!({ "offer": offer.to_hex() }),
            )]
        } else {
            Vec::new()
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

    /// The producer names the change in `source.result`; the notice is an
    /// owner's own. Its revert is offered while the change is the vault's
    /// last and the pack before it is installed at its bytes and served.
    fn model_pack_revert_actions(&self, row: &NotificationRow) -> Vec<NotificationAction> {
        let Some(change_ref) = row.source.result.as_deref() else {
            return Vec::new();
        };
        let vault = self.vault();
        let runs = vault
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)
            .and_then(|txn| vault.model_pack_revert_runs_in_txn(&txn, change_ref));
        if !matches!(runs, Ok(true)) {
            return Vec::new();
        }
        vec![NotificationAction::new(
            MODEL_PACK_REVERT_VERB,
            serde_json::json!({ "change_ref": change_ref }),
        )]
    }
}
