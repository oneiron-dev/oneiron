//! A Retry's proven leave to answer a room's claimed turn again (FIX 3149),
//! and the claim a Retry takes on a home room's unclaimed parent
//! (HOMERETRY-AUTHORITY = C). Entry: `RoomRegenerationPermit::prove_in`.

use super::super::retry_claim::{self, RETRY_CLAIM_RECEIPT_PREFIX, RetryClaim};
use super::*;
use crate::edge::EdgeKind;

/// A Retry's leave to answer a project room's claimed turn again (FIX
/// 3149). It is proven inside the Retry's own transactions from its action
/// and the answering agent, never carried in a message's metadata.
/// RESPONSE keeps the claim's first answer as its slot: a regenerated
/// answer answers the same parent, in the same thread, naming the same
/// agents, and its `regenerates` lineage reaches that slot. It bypasses no
/// audience, participation, speaking role, write ceiling or claim check. On
/// a claim a Retry took, the participation gate takes the requester's press
/// as the agent's address on the parent (HOMERETRY-AUTHORITY = C).
pub(crate) struct RoomRegenerationPermit {
    /// The room row of the turn the Retry answers again.
    pub(crate) source: RoomTurn,
    /// The answer RESPONSE holds for the claimed parent.
    slot: EntityId,
    /// The claim the Retry takes on a parent that holds none
    /// (HOMERETRY-AUTHORITY = C), until its reply's write lands it.
    takes: Option<RetryClaim>,
    /// The parent whose claim this permit's write took.
    took: Option<EntityId>,
    /// The parent the requester's press addresses the agent on, when its
    /// claim is one a Retry takes or took (REVIEW-9153 round 2).
    pressed_parent: Option<EntityId>,
}

impl RoomRegenerationPermit {
    /// Proves `action`, a standing Retry, lets `actor` answer its source's
    /// claimed parent again: the source is `actor`'s room turn of the
    /// action's conversation holding its MESSAGE, `actor` and the requester
    /// both still read its thread, `actor` still holds the parent's claim,
    /// and the MESSAGE's `regenerates` lineage, each step `actor`'s live
    /// answer to the same parent in the same thread, reaches the slot. A
    /// parent that holds no claim is claimed by the Retry itself when the
    /// claim door's checks admit it (HOMERETRY-AUTHORITY = C): the source is
    /// then the slot, and [`Self::take_claim_in_txn`] writes the claim. On a
    /// parent whose claim a Retry took, a press admitted as the first one
    /// was addresses the agent there; without one, the agent answers again
    /// only where it is named or holds a task, as on any other claim.
    pub(crate) fn prove_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        action: &crate::conversation::TurnActionAttempt,
        actor: EntityId,
    ) -> Result<Self> {
        let old = turn_in(vault, txn, action.assistant_turn)?;
        if action.action != crate::conversation::TurnAction::Retry
            || !action.requester_live_in(vault, txn)
            || old.room_id != action.conversation.to_hex()
            || old.actor != actor.to_hex()
            || !old.message_ids.contains(&action.message.to_hex())
        {
            return Err(invalid());
        }
        for reader in [actor, action.actor] {
            if !record_thread_admits_in(vault, txn, action.assistant_turn, reader)? {
                return Err(invalid());
            }
        }
        let parent = EntityId::from_hex(old.reply_to.as_deref().ok_or_else(invalid)?)?;
        let parent_row = turn_in(vault, txn, parent)?;
        if parent_row.room_id != old.room_id {
            return Err(invalid());
        }
        let (slot, takes, pressed) = match CLAIMS.get(&vault.store, txn, &parent)? {
            Some(claim) => {
                if claim.room_id != old.room_id || claim.actor != old.actor {
                    return Err(invalid());
                }
                // The press only adds an address: a press that is not
                // admitted (an agent's, say) leaves the participation gate
                // to read a naming or a task, as for any other claim.
                let pressed = claim.receipt_ref.starts_with(RETRY_CLAIM_RECEIPT_PREFIX)
                    && retry_claim::admit_press_in(vault, txn, action, actor, &parent_row).is_ok();
                let slot = RESPONSE
                    .get(&vault.store, txn, &parent)?
                    .ok_or_else(invalid)?;
                (slot, None, pressed)
            }
            None => {
                let claim = RetryClaim::admit_in(vault, txn, action, actor, parent, &parent_row)?;
                (claim.slot(), Some(claim), true)
            }
        };
        let edge = |message: &EntityId, kind: EdgeKind| {
            crate::memory::sole_edge_target(&vault.store, txn, message, kind, "message")
                .map_err(|_| invalid())
        };
        // The whole lineage is read, however long (rule 5); a cycle refuses.
        let mut count = crate::scan_check::ScanCount::start(
            &vault.store,
            txn,
            crate::scan_check::EngineScan::RoomRetryLineageRows,
            action.message.as_bytes(),
        )?;
        let mut cursor = action.message;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(cursor) {
                return Err(invalid());
            }
            count.row();
            if !live_entity_row_in_txn(&vault.store, txn, &cursor)?.is_live()
                || edge(&cursor, EdgeKind::AuthoredBy)? != Some(actor)
                || edge(&cursor, EdgeKind::BelongsTo)? != Some(action.conversation)
            {
                return Err(invalid());
            }
            let turn = edge(&cursor, EdgeKind::PartOf)?.ok_or_else(invalid)?;
            let row = turn_in(vault, txn, turn)?;
            if row.actor != old.actor
                || row.room_id != old.room_id
                || row.reply_to != old.reply_to
                || row.thread_of != old.thread_of
            {
                return Err(invalid());
            }
            if turn == slot {
                count.defer(&vault.store);
                return Ok(Self {
                    source: old,
                    slot,
                    takes,
                    took: None,
                    pressed_parent: pressed.then_some(parent),
                });
            }
            cursor = edge(&cursor, EdgeKind::Regenerates)?.ok_or_else(invalid)?;
        }
    }

    /// The parent this permit's Retry claims, while its claim is not yet
    /// written: both the agent and the requester must read it, as a
    /// claimant reads the turn it claims.
    pub(crate) fn claimed_parent(&self) -> Option<EntityId> {
        self.takes.as_ref().map(RetryClaim::parent)
    }

    /// The parent the requester's press addresses the agent on, when the
    /// parent's claim is one a Retry takes or took: the participation gate
    /// takes it in place of a naming on that parent or a thread task
    /// (HOMERETRY-AUTHORITY = C; REVIEW-9153 round 2).
    pub(crate) const fn pressed_parent(&self) -> Option<EntityId> {
        self.pressed_parent
    }

    /// The parent whose claim this permit's write took, once
    /// [`Self::take_claim_in_txn`] wrote it: its live windows take the claim
    /// after the write commits (FIX 1794).
    pub(crate) const fn took_claim(&self) -> Option<EntityId> {
        self.took
    }

    /// Writes the claim this permit's Retry takes, if any, at `at` in `txn`,
    /// the write that lands its reply, before the room's witness admits the
    /// reply (HOMERETRY-AUTHORITY = C).
    pub(crate) fn take_claim_in_txn(
        &mut self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        at: u64,
    ) -> Result<()> {
        if let Some(claim) = self.takes.take() {
            claim.take_in_txn(vault, txn, at)?;
            self.took = Some(claim.parent());
        }
        Ok(())
    }

    /// Whether `actor`'s answer in `room` to `reply_to`, in `thread_of`,
    /// naming `mentions`, while RESPONSE holds `prior`, is the one this
    /// permit proved.
    pub(super) fn admits(
        &self,
        room: EntityId,
        actor: EntityId,
        reply_to: Option<EntityId>,
        thread_of: Option<EntityId>,
        mentions: &BTreeSet<String>,
        prior: EntityId,
    ) -> bool {
        self.takes.is_none()
            && self.slot == prior
            && self.source.room_id == room.to_hex()
            && self.source.actor == actor.to_hex()
            && self.source.reply_to == reply_to.map(|id| id.to_hex())
            && self.source.thread_of == thread_of.map(|id| id.to_hex())
            && self.source.addressed_agents == *mentions
    }
}
