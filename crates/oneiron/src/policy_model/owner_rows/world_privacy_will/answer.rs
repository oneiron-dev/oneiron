//! A holder's answer to a world-privacy request (FIX 4480): accept or
//! decline an agent's proposal, confirm or decline a widen ask. A yes is the
//! holder's own act, `by: Owner` with `answer` = the request, written in the
//! same commit as the request's settlement; the first present holder settles
//! it, once. Under "widen needs every owner" the yeses are collected on the
//! ask, and the last one applies it.

use crate::authority::{ActSurface, WorldEditAuthor};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::inbox::NotificationKind;
use crate::{EntityId, Vault};

use super::super::world_privacy_switch::{WorldPrivacyReceipt, hex32};
use super::agent::CHANGED_NOTICE;
use super::record::{WorldPrivacyRequest, WorldPrivacyRequestKind, WorldPrivacyRequestStatus};
use super::{key_owner_in_txn, not_holder, world_holders_in_txn};

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

/// A request already settled, or one its opener's own lineage answers.
const SETTLED: &str = "this world-privacy request was already settled";
const OWN_LINEAGE: &str = "the lineage that opened a world-privacy request cannot settle it";

impl Vault {
    /// A holder's answer to request `request` from `surface` (audit only):
    /// `yes` accepts a proposal or confirms an ask, else declines or cancels
    /// it. The holder must hold the world's settings right now and have been
    /// one it went to. A yes applies the frozen settings on the frozen
    /// revision: a world whose settings moved since is a conflict.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] for a non-holder or the
    /// opener's own lineage; [`Error::EntityNotFound`] for no such request;
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
        self.with_world_settings_writer(|txn, secret| {
            let mut stored = self
                .world_privacy_request_in_txn(txn, request)?
                .ok_or(Error::EntityNotFound)?;
            if stored.status != WorldPrivacyRequestStatus::Pending {
                return Err(Error::InvalidConfig(SETTLED.to_owned()));
            }
            let world = stored.world_id()?;
            let actor = owner.revalidate_person_in_txn(self, txn)?;
            let holders = world_holders_in_txn(self, txn, world)?;
            if !holders.contains(&actor) || !stored.holders.contains(&actor.to_hex()) {
                return Err(not_holder());
            }
            let lineage = owner.credential_lineage();
            if lineage
                .iter()
                .any(|slip| stored.opener_lineage.contains(&hex32(slip)))
            {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    OWN_LINEAGE,
                )));
            }
            if !yes {
                stored.status = WorldPrivacyRequestStatus::Declined {
                    holder: actor.to_hex(),
                };
                self.put_world_privacy_request_in_txn(txn, &stored)?;
                if let Some(seq) = stored.ask {
                    self.settle_world_privacy_ask_in_txn(txn, seq, actor, false)?;
                }
                return Ok(WorldPrivacyAnswer::Declined(stored));
            }
            if stored.kind == WorldPrivacyRequestKind::WidenAsk && !stored.needs.is_empty() {
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
                    return Ok(WorldPrivacyAnswer::Collected(stored));
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
            let receipt =
                self.finish_world_key_work_in_txn(txn, Some(owner), key_owner, receipt, secret)?;
            stored.status = WorldPrivacyRequestStatus::Applied {
                receipt_id: receipt.receipt_id.clone(),
                holder: actor.to_hex(),
            };
            self.put_world_privacy_request_in_txn(txn, &stored)?;
            if let Some(seq) = stored.ask {
                self.settle_world_privacy_ask_in_txn(txn, seq, actor, true)?;
            }
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
            Ok(WorldPrivacyAnswer::Applied(receipt))
        })
    }
}
