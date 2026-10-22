//! A holder's answer to a world-privacy request (FIX 4480): accept or
//! decline an agent's proposal, confirm or decline a widen ask. A yes is the
//! holder's own act, `by: Owner` with `answer` = the request, written in the
//! same commit as the request's settlement; the first present holder settles
//! it, once. Under "widen needs every owner" the yeses are collected on the
//! ask, and the last one applies it: the live Owners it needs are read again
//! at each answer, so one who left neither counts nor holds it up.
//!
//! An applied or declined request settles its waits in that same commit: the
//! tasks bound to it are signalled, and every run parked on it gets its
//! terminal state (FIX 4706). Its decision ask's waiters wake only after the
//! commit returned. A collected yes wakes nothing: the request still waits.

use crate::authority::{ActSurface, WorldEditAuthor};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::inbox::NotificationKind;
use crate::{EntityId, Vault};

use super::super::world_privacy_switch::WorldPrivacyReceipt;
use super::agent::CHANGED_NOTICE;
use super::record::{
    WorldPrivacyRequest, WorldPrivacyRequestKind, WorldPrivacyRequestStatus, parse_revision,
};
use super::{key_owner_in_txn, not_holder, unanimity, world_holders_in_txn};

/// What a holder's answer came to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldPrivacyAnswer {
    /// His yes applied the settings: the receipt.
    Applied(WorldPrivacyReceipt),
    /// His yes is counted, and the ask still waits for another owner's.
    Collected(WorldPrivacyRequest),
    /// He declined it, or cancelled it from its notice.
    Declined(WorldPrivacyRequest),
}

/// A request already settled, or one its opener's lineage or a fork of it
/// answers.
const SETTLED: &str = "this world-privacy request was already settled";
const OWN_LINEAGE: &str = "the lineage that opened a world-privacy request cannot settle it";

impl Vault {
    /// A holder's answer to request `request` from `surface` (audit only):
    /// `yes` accepts a proposal or confirms an ask, else declines or cancels
    /// it. The holder must hold the world's settings right now. In default
    /// mode that is the whole test: the holders it was first sent to are a
    /// delivery list, not a second authority gate, so a holder added since
    /// answers too (FIX 10032). An ask that needs every owner keeps its own
    /// rule: the holder was one it went to, or is a live Owner now. A yes
    /// applies the frozen settings on the frozen revision: a world whose
    /// settings moved since is a conflict.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] for a non-holder or the
    /// opener's lineage or a fork of it (FIX 5064);
    /// [`Error::EntityNotFound`] for no such request;
    /// [`Error::InvalidConfig`] for one already settled;
    /// [`Error::ConcurrentWrite`] when the world's settings changed since it
    /// was opened.
    pub fn answer_world_privacy_request(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        request: EntityId,
        yes: bool,
    ) -> Result<WorldPrivacyAnswer> {
        let (answer, settled) = self.with_world_settings_writer(|txn, secret| {
            let mut stored = self
                .world_privacy_request_in_txn(txn, request)?
                .ok_or(Error::EntityNotFound)?;
            if stored.status != WorldPrivacyRequestStatus::Pending {
                return Err(Error::InvalidConfig(SETTLED.to_owned()));
            }
            let world = stored.world_id()?;
            let actor = owner.revalidate_person_in_txn(self, txn)?;
            let holders = world_holders_in_txn(self, txn, world)?;
            // An ask under "widen needs every owner" needs the live Owners as
            // they stand at this answer, not as they stood when it opened
            // (FIX-LIST "mesh PR1d widen ask needs frozen").
            let live_needs =
                if stored.kind == WorldPrivacyRequestKind::WidenAsk && !stored.needs.is_empty() {
                    Some(unanimity::ask_needs_in_txn(self, txn)?)
                } else {
                    None
                };
            let went_to = match &live_needs {
                // Default mode: any current holder answers (FIX 10032).
                None => true,
                Some(needs) => stored.holders.contains(&actor.to_hex()) || needs.contains(&actor),
            };
            if !holders.contains(&actor) || !went_to {
                return Err(not_holder());
            }
            // The opener's lineage and its forks never settle their own
            // proposal (DEC-0006, FIX 5064): checked before a decline, a
            // collected yes or an apply.
            let opener: Vec<[u8; 32]> = stored
                .opener_lineage
                .iter()
                .filter_map(|slip| parse_revision(slip).map(|id| id.0))
                .collect();
            if owner.answers_from_slip_lineage_in_txn(self, txn, &opener)? {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    OWN_LINEAGE,
                )));
            }
            if !yes {
                stored.status = WorldPrivacyRequestStatus::Declined {
                    holder: actor.to_hex(),
                };
                self.put_world_privacy_request_in_txn(txn, &stored)?;
                crate::task_verb::deliver_world_privacy_wait_in_txn(self, txn, &stored)?;
                let settled = match stored.ask {
                    Some(seq) => self.settle_world_privacy_ask_in_txn(txn, seq, actor, false)?,
                    None => None,
                };
                return Ok((WorldPrivacyAnswer::Declined(stored), settled));
            }
            if let Some(needs) = &live_needs {
                stored.needs = needs.iter().map(EntityId::to_hex).collect();
                let me = actor.to_hex();
                if stored.needs.contains(&me) && !stored.yes.contains(&me) {
                    stored.yes.push(me);
                }
                if !stored
                    .needs
                    .iter()
                    .all(|needed| stored.yes.contains(needed))
                {
                    self.put_world_privacy_request_in_txn(txn, &stored)?;
                    return Ok((WorldPrivacyAnswer::Collected(stored), None));
                }
            }
            let author = WorldEditAuthor {
                answer: Some(request),
                ..WorldEditAuthor::holder(actor, surface)
            };
            let agent = stored.agent_id()?;
            let receipt = self.write_world_privacy_in_txn(
                txn,
                author,
                world,
                stored.settings.clone(),
                Some(stored.seen_revision()?),
                agent,
            )?;
            let key_owner = key_owner_in_txn(self, txn, actor)?;
            let receipt = self.finish_world_key_work_in_txn(txn, key_owner, receipt, secret)?;
            stored.status = WorldPrivacyRequestStatus::Applied {
                receipt_id: receipt.receipt_id.clone(),
                holder: actor.to_hex(),
            };
            self.put_world_privacy_request_in_txn(txn, &stored)?;
            crate::task_verb::deliver_world_privacy_wait_in_txn(self, txn, &stored)?;
            let settled = match stored.ask {
                Some(seq) => self.settle_world_privacy_ask_in_txn(txn, seq, actor, true)?,
                None => None,
            };
            // An agent's tighten a holder accepted tells every holder, with
            // its one-tap undo, as one it applied under its Grant does.
            if stored.kind == WorldPrivacyRequestKind::Proposal {
                self.notify_world_holders_in_txn(
                    txn,
                    NotificationKind::WorldPrivacyChanged,
                    &receipt.receipt_id,
                    world,
                    &holders,
                    CHANGED_NOTICE,
                )?;
            }
            Ok((WorldPrivacyAnswer::Applied(receipt), settled))
        })?;
        // The writer returned only once its commit was durable.
        if let Some(seq) = settled {
            self.signal_decision_answer(seq);
        }
        Ok(answer)
    }
}
