//! FIX 5778: an agent acting for the owner inside its Grant acknowledges his
//! weave digest's due notice, and that acknowledgement counts as his
//! dismissal (DEC-0005: within its Grant an agent is the owner's delegated
//! will).
//!
//! One covering Grant decides both: a live Grant of that agent, given by
//! THIS notice's Owner, that alone stands for the agent's work under the
//! ack verb now (it names the agent, confers, its delegator a live Owner,
//! its pact standing) and that admits the notice's own record position.
//! Grants are never unioned, a foreign Owner's delegation never counts, and
//! no actor is inferred from a name. It is judged in the snapshot that
//! uses it: the mark door's admission and its writer, and the Coach's fold.
//!
//! Only ever an addition. The mark door's delivery, read and write path
//! runs first and keeps every success it has; only an Acked mark on an
//! owner's weave due notice may use the Grant instead of delivery, and the
//! mark stores the agent's own key, never the Owner's. The fold counts the
//! owner's own keys first; only when neither acknowledged does an agent's
//! own acknowledgement count. A check that does not answer adds nothing:
//! the old refusal and the old count stand.

use super::super::ScopedRead;
use super::WEAVE_DIGEST_NOTIFICATION_PRODUCER;
use crate::claim::ScopedReadActorKey;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::inbox::{NotificationBody, NotificationKind, decode_notification_body};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// The verb a covering Grant must list and admit at the notice's position
/// (CALLS `FIX 5778 WEAVE_OWNER_ACK_VERB`): the served mark operation.
pub(crate) const WEAVE_OWNER_ACK_VERB: &str = "self.inbox.mark";

/// When a covering Grant is judged (CALLS `FIX 5778
/// WEAVE_OWNER_ACK_STANDING`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckStanding {
    /// On the snapshot that uses it: at the mark and again at the fold. No
    /// historical Grant record is kept.
    CurrentSnapshot,
}

const WEAVE_OWNER_ACK_STANDING: AckStanding = AckStanding::CurrentSnapshot;

/// Whose delegation a covering Grant must be (CALLS `FIX 5778
/// WEAVE_OWNER_ACK_DELEGATOR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckDelegator {
    /// The notice's own recipient Owner.
    RecipientOwner,
}

const WEAVE_OWNER_ACK_DELEGATOR: AckDelegator = AckDelegator::RecipientOwner;

/// The Owner a weave digest due notice is for, when `body` is one: a Digest
/// notice of the weave digest producer, its recipient that Owner, its event
/// the Owner reader's for its period, its result that period.
fn owner_due_notice(body: &NotificationBody) -> Option<EntityId> {
    let recipient = body.recipient.as_deref()?;
    let owner = EntityId::from_hex(recipient).ok()?;
    let period = body.source.result.as_deref()?;
    let scheduled_for: u64 = period.parse().ok()?;
    (body.kind == NotificationKind::Digest
        && body.source.producer == WEAVE_DIGEST_NOTIFICATION_PRODUCER
        && owner.to_hex() == recipient
        && scheduled_for.to_string() == period
        && body.source.event == format!("o:{recipient}:{period}"))
    .then_some(owner)
}

/// One check's answer, a check that does not answer adding nothing.
fn answered(check: Result<Option<EntityId>>) -> bool {
    match check {
        Ok(grant) => grant.is_some(),
        Err(error) => {
            tracing::warn!(
                error_kind = ?error.kind(),
                "an agent's owner-notice acknowledgement Grant did not read; it adds nothing \
                 (FIX 5778)"
            );
            false
        }
    }
}

impl ScopedRead<'_> {
    /// Whether this lane's `actor` (of `class`) may acknowledge the
    /// notification `id` for its Owner through one covering Grant, in its
    /// own snapshot (see the module doc). The mark door asks this only for
    /// an Acked mark on a row it already read but does not deliver to the
    /// actor; `false` leaves its old refusal.
    pub(crate) fn delegated_owner_notice_ack(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        id: EntityId,
    ) -> bool {
        match self.vault.store.env.read_txn() {
            Ok(txn) => self.delegated_owner_notice_ack_in(&txn, actor, class, id),
            Err(error) => {
                tracing::warn!(
                    error_kind = ?crate::error::Error::from(error).kind(),
                    "no snapshot for an owner-notice acknowledgement; it adds nothing (FIX 5778)"
                );
                false
            }
        }
    }

    /// [`Self::delegated_owner_notice_ack`] in `txn`, the mark's writer
    /// among them: the actor's binding, the row a live owner's weave due
    /// notice, and one covering Grant of the actor's.
    pub(crate) fn delegated_owner_notice_ack_in(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        id: EntityId,
    ) -> bool {
        if self.actor_key.actor_ref() != actor.to_hex()
            || crate::memory::verify_actor_binding_in_txn(self.vault, txn, actor, class).is_err()
        {
            return false;
        }
        let owner = match live_entity_row_in_txn(&self.vault.store, txn, &id) {
            Ok(LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_NOTIFICATION,
                body,
            }) => decode_notification_body(&body)
                .ok()
                .as_ref()
                .and_then(owner_due_notice),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "an owner notice did not read; its acknowledgement adds nothing (FIX 5778)"
                );
                None
            }
        };
        owner.is_some_and(|owner| {
            answered(self.owner_notice_ack_grant_in(txn, actor, class, id, owner))
        })
    }

    /// The one live Grant of `agent` (of `class`) that covers its
    /// acknowledgement of `owner`'s notice `notice` in `txn`, first in id
    /// order; `None` when none does. A person is never an agent here, and
    /// the Owner's own key is counted apart.
    fn owner_notice_ack_grant_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
        class: EdgeActorClass,
        notice: EntityId,
        owner: EntityId,
    ) -> Result<Option<EntityId>> {
        if class == EdgeActorClass::Human || agent == owner {
            return Ok(None);
        }
        let vault = self.vault;
        let txn = match WEAVE_OWNER_ACK_STANDING {
            AckStanding::CurrentSnapshot => txn,
        };
        if crate::authority::principal_standing_in_txn(
            vault,
            txn,
            agent,
            class,
            WEAVE_OWNER_ACK_VERB,
        )?
        .is_none()
        {
            return Ok(None);
        }
        let Some(raw) = vault.store.port_entity_raw(txn, &notice)? else {
            return Ok(None);
        };
        let delegator = match WEAVE_OWNER_ACK_DELEGATOR {
            AckDelegator::RecipientOwner => owner,
        };
        let now = vault.instant_in_txn(txn)?.secs();
        let owners = crate::policy_model::owners_in_txn(vault, txn)?;
        let (grants, _undecoded) = vault.agent_grants_reporting_in_txn(txn)?;
        for standing in grants {
            if standing.delegated_by != delegator
                || !standing.stands_in_txn(vault, txn, agent, WEAVE_OWNER_ACK_VERB, now, &owners)
            {
                continue;
            }
            // The SAME Grant admits the notice's record position.
            if self.grant_admits_position_in(txn, &notice, &raw, &standing.grant.authority_scope)? {
                return Ok(Some(standing.id));
            }
        }
        Ok(None)
    }
}

impl Vault {
    /// Whether an agent acting for `owner` inside one covering Grant
    /// acknowledged his live due notice `notice` (`body`, already validated
    /// as his period's), judged in `txn`. The Coach's fold asks this only
    /// after his own keys did not acknowledge it. An acknowledging key is
    /// the actor the mark door stored; its class is its own row's.
    pub(super) fn notice_acked_by_covering_agent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        notice: EntityId,
        body: &NotificationBody,
        owner: EntityId,
    ) -> bool {
        for (key, acked) in &body.acked_by {
            let Ok(agent) = EntityId::from_hex(key) else {
                continue;
            };
            if !*acked || agent == owner {
                continue;
            }
            let class = match live_entity_row_in_txn(&self.store, txn, &agent) {
                Ok(row) => match row.live_type() {
                    Some(crate::registry::ENTITY_TYPE_AGENT_DEF) => EdgeActorClass::Agent,
                    Some(crate::registry::ENTITY_TYPE_MACHINE) => EdgeActorClass::System,
                    _ => continue,
                },
                Err(error) => {
                    tracing::warn!(
                        error_kind = ?error.kind(),
                        "an acknowledging agent did not read; its acknowledgement adds nothing \
                         (FIX 5778)"
                    );
                    continue;
                }
            };
            let Some(lane) = ScopedReadActorKey::new(key.clone()) else {
                continue;
            };
            if answered(
                self.scoped_read(lane)
                    .owner_notice_ack_grant_in(txn, agent, class, notice, owner),
            ) {
                return true;
            }
        }
        false
    }
}
