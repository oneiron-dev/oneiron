//! The owner's standing answer to a filed courtesy ask (ARCH-0043
//! #leaving-a-company: "The reply to an erase request is each owner's
//! setting"; Engine rulings L7-09-REPLY-SETTING = A and
//! L7-09-HONOUR-REPLY-ROUTE = A).
//!
//! Filing stays pure: receiving an ask deletes nothing under any setting.
//! A later pass answers each filed ask that has no answer yet as the
//! `erase_request_reply` row says, in a writer of its own that reads the
//! row again:
//! - `ask`, or no row, answers nothing: the ask waits for the owner's pick.
//! - `decline` records a decline under a fixed reason code, with a review
//!   date a year on. Nothing is erased.
//! - `honour` records one delete choice over every copy the ask covers that
//!   is still here. A copy that a legal hold or a cooperative restriction
//!   keeps, directly, through its pad's world or through a redirect shell
//!   its erase would take, is left out and named in `excluded`. The deletes
//!   then run one by one through the delete rail as a live owner of this
//!   vault. Each delete's writes read again that the row still says
//!   `honour` and that the answer is still this one, so a changed row or
//!   the owner's own answer stops the run before its next record. No
//!   record-level retention rule exists to leave copies out by (FIX
//!   HONOUR-RETENTION-RULE).
//!
//! An answer the owner recorded is never rewritten. No reply is queued:
//! nothing here knows the requester's host. The owner's answer door sends
//! the signed reply when a client passes `reply_to` with the same choice
//! (FIX HONOUR-REPLY-ROUTE).

use std::collections::BTreeSet;

use super::answer::{AskKey, running_operation_in};
use super::{
    CooperativeDeleteOperation, CooperativeDeletionDisposition, CooperativeDeletionDispositionKind,
    EraseRequestReply, INCOMING, IncomingCooperativeDeletion,
};
use crate::deletion::SafeDeleteReason;
use crate::edge::EdgeActorClass;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError, MemoryResult,
};
use crate::ports::EntityStoreRead;
use crate::provenance::birth::birth_held_in_txn;
use crate::{EntityId, Error, Result, Vault};

/// The reason code a decline under the standing setting records.
pub const ERASE_REQUEST_SETTING_DECLINE_CODE: &str = "owner_setting_decline";
/// How long after a decline under the standing setting the ask comes up
/// for review, in seconds.
pub const ERASE_REQUEST_SETTING_DECLINE_REVIEW_SECS: u64 = 365 * 24 * 60 * 60;

/// What the setting's writer did with one filed ask.
enum SettingAnswer {
    /// Nothing: the row says `ask`, the ask is gone or already answered,
    /// or no live owner here may delete.
    Unanswered,
    /// A decline, recorded.
    Recorded(Box<IncomingCooperativeDeletion>),
    /// A delete choice, recorded, whose operation runs as `owner`.
    Delete {
        owner: EntityId,
        operation_id: EntityId,
    },
}

impl Vault {
    /// Answers every filed courtesy ask that has no answer yet as the
    /// owner's standing `erase_request_reply` row says (module doc), each in
    /// its own writer. Returns the asks it answered, each as it reads once
    /// its deletes have run. Under `ask`, or with no row, it answers
    /// nothing.
    ///
    /// # Errors
    ///
    /// Storage errors. A delete that fails leaves its record pending in the
    /// answer's operation, and the rest go on.
    pub fn answer_filed_asks_by_setting(
        &self,
        now: u64,
    ) -> Result<Vec<IncomingCooperativeDeletion>> {
        if self.erase_request_reply()?.reply == EraseRequestReply::Ask {
            return Ok(Vec::new());
        }
        let unanswered: Vec<AskKey> = {
            let txn = self.store.env.read_txn()?;
            let mut keys = Vec::new();
            for row in INCOMING.iter_from(&self.store, &txn, &[])? {
                let (key, filed) = row?;
                if filed.disposition.is_none() {
                    keys.push(key);
                }
            }
            keys
        };
        let mut answered = Vec::new();
        for key in unanswered {
            if let Some(filed) = self.answer_filed_ask_by_setting(&key, now)? {
                answered.push(filed);
            }
        }
        Ok(answered)
    }

    /// Answers the filed ask `key` as the row reads in the answer's writer,
    /// then runs a delete choice's operation.
    fn answer_filed_ask_by_setting(
        &self,
        key: &AskKey,
        now: u64,
    ) -> Result<Option<IncomingCooperativeDeletion>> {
        let operation_id = self.store.clock.entity_id()?;
        let written = self.with_write_txn_grouped(|txn| {
            let reply = self.erase_request_reply_in_txn(txn)?.reply;
            let Some(mut filed) = INCOMING.get(&self.store, txn, key)? else {
                return Ok(SettingAnswer::Unanswered);
            };
            // The owner's own answer, or an earlier pass's, stands.
            if filed.disposition.is_some() {
                return Ok(SettingAnswer::Unanswered);
            }
            let answer = match reply {
                EraseRequestReply::Ask => return Ok(SettingAnswer::Unanswered),
                EraseRequestReply::Decline => {
                    filed.disposition = Some(setting_decline(now));
                    SettingAnswer::Recorded(Box::new(filed.clone()))
                }
                EraseRequestReply::Honour => {
                    let Some(owner) = deleting_owner_in_txn(self, txn)? else {
                        tracing::warn!(
                            "no live owner of this vault may delete: a filed courtesy ask \
                             waits for the owner's pick under the honour setting"
                        );
                        return Ok(SettingAnswer::Unanswered);
                    };
                    let (unheld, held) = honoured_copies_in_txn(self, txn, &key.0, &filed)?;
                    filed.disposition = Some(setting_honour(now, operation_id, &unheld, &held));
                    SettingAnswer::Delete {
                        owner,
                        operation_id,
                    }
                }
            };
            INCOMING.put(&self.store, txn, key, &filed)?;
            Ok(answer)
        })?;
        match written {
            SettingAnswer::Unanswered => Ok(None),
            SettingAnswer::Recorded(filed) => Ok(Some(*filed)),
            SettingAnswer::Delete {
                owner,
                operation_id,
            } => self.run_setting_delete(key, owner, operation_id).map(Some),
        }
    }

    /// Runs the setting's delete choice `operation_id` on the ask `key` as
    /// `owner`, through the delete rail, each delete's writes reading again
    /// that the row still says `honour` and that the answer is still this
    /// one.
    fn run_setting_delete(
        &self,
        key: &AskKey,
        owner: EntityId,
        operation_id: EntityId,
    ) -> Result<IncomingCooperativeDeletion> {
        let memory = self.memory(owner, EdgeActorClass::Human);
        let still_honoured = |txn: &heed::RoTxn<'_>| -> MemoryResult<()> {
            let reply = self.erase_request_reply_in_txn(txn)?.reply;
            if reply == EraseRequestReply::Honour
                && running_operation_in(self, txn, key, operation_id)?.is_some()
            {
                return Ok(());
            }
            Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "erase_request_reply_changed: the owner's setting or answer that admitted \
                 this courtesy delete changed before it committed",
                &["The ask's answer is the owner's now; answer it again to delete."],
            ))
        };
        self.run_courtesy_delete_with(key, operation_id, |record| {
            memory.safe_delete_checked(
                &record.to_hex(),
                SafeDeleteReason::UserHardDelete,
                &still_honoured,
            )
        })
    }
}

/// A decline under the standing setting: its fixed reason code and a
/// review date a year on; nothing deleted.
fn setting_decline(now: u64) -> CooperativeDeletionDisposition {
    CooperativeDeletionDisposition {
        kind: CooperativeDeletionDispositionKind::Decline,
        reason_code: Some(ERASE_REQUEST_SETTING_DECLINE_CODE.to_owned()),
        review_at: Some(now.saturating_add(ERASE_REQUEST_SETTING_DECLINE_REVIEW_SECS)),
        deleted: Vec::new(),
        recorded_at: now,
        hold_ids: Vec::new(),
        excluded: Vec::new(),
        delete_operation: None,
        retention: None,
        restricted: Vec::new(),
        local_redactions: Vec::new(),
    }
}

/// An honour under the standing setting: one delete choice over `unheld`,
/// with `held` named as left out.
fn setting_honour(
    now: u64,
    operation_id: EntityId,
    unheld: &[EntityId],
    held: &[EntityId],
) -> CooperativeDeletionDisposition {
    CooperativeDeletionDisposition {
        kind: CooperativeDeletionDispositionKind::Delete,
        reason_code: None,
        review_at: None,
        deleted: Vec::new(),
        recorded_at: now,
        hold_ids: Vec::new(),
        excluded: held.iter().map(EntityId::to_hex).collect(),
        delete_operation: Some(CooperativeDeleteOperation::new(operation_id, unheld)),
        retention: None,
        restricted: Vec::new(),
        local_redactions: Vec::new(),
    }
}

/// The first live owner of this vault whose delete authority holds in
/// `txn`, the one predicate each delete's writes read again; `None` when
/// none does.
fn deleting_owner_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<EntityId>> {
    for owner in crate::policy_model::owners_in_txn(vault, txn)? {
        match crate::memory::verify_deletion_authority_in_txn(
            vault,
            txn,
            owner,
            EdgeActorClass::Human,
        ) {
            Ok(()) => return Ok(Some(owner)),
            Err(error)
                if error.code == MEMORY_CODE_FORBIDDEN
                    || error.code == MEMORY_CODE_OWNER_BINDING_REQUIRED => {}
            Err(error) => return Err(Error::Refused(error.message)),
        }
    }
    Ok(None)
}

/// Every copy the filed ask under pact `pact_id` covers that is still here
/// and not removed, split into the ones the setting deletes and the ones a
/// hold keeps. A named world that does not parse covers nothing (FIX 321).
fn honoured_copies_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pact_id: &[u8; 32],
    filed: &IncomingCooperativeDeletion,
) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
    let worlds: Option<Vec<EntityId>> = filed
        .worlds
        .iter()
        .map(|world| EntityId::from_hex(world).ok())
        .collect();
    let Some(worlds) = worlds else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut unheld = Vec::new();
    let mut held = Vec::new();
    for record in crate::federation::courtesy_scope::recipient_copies_in_txn(
        vault,
        txn,
        pact_id,
        &worlds,
        filed.epoch_cutoff,
    )? {
        if !EntityStoreRead::port_entity_present(&vault.store, txn, &record)?
            || crate::ports::removed_in_txn(&vault.store, txn, &record)?
        {
            continue;
        }
        if kept_by_hold_in_txn(vault, txn, &record)? {
            held.push(record);
        } else {
            unheld.push(record);
        }
    }
    Ok((unheld, held))
}

/// Whether a delete of `record` would be refused for a hold: the checks of
/// the owner's delete choice (`answer.rs` `preflight_delete_in_txn`) read
/// as a bool, so nothing is logged as refused. A legal hold or a
/// cooperative restriction on the record or its pad's world, or on a
/// redirect shell its erase takes with it.
fn kept_by_hold_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, record: &EntityId) -> Result<bool> {
    if birth_held_in_txn(&vault.store, txn, record)? {
        return Ok(true);
    }
    let shells = crate::identity_redirect::inbound_redirect_shells_in_txn(
        &vault.store,
        txn,
        &BTreeSet::from([*record]),
    )?;
    for shell in shells {
        if birth_held_in_txn(&vault.store, txn, &shell)? {
            return Ok(true);
        }
    }
    Ok(false)
}
