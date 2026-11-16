//! The claim a Retry takes on its source's unclaimed parent in a project's
//! home room (HOMERETRY-AUTHORITY = C, lead 16 Nov 23:2x). The person's Retry
//! press is the address: the claim names the answering agent as the holder
//! of the parent's next turn, and its receipt names the person who pressed
//! it. It is admitted through the claim door's own checks and written in the
//! write that lands the Retry's reply, so a refused Retry leaves no claim.
//! RESPONSE takes the source, the agent's first answer to that parent, as
//! the claim's slot; the reply then answers it again under the room's
//! regeneration permit (FIX 3149), as a claimed turn's Retry does.
use super::participation::{Claimant, addressable_agent_in_txn, participant_in_txn};
use super::*;
use crate::conversation::TurnActionAttempt;
use crate::workspace_roster::JoinSubject;

/// The receipt prefix of a claim a Retry took; the rest is the id of the
/// person who pressed it.
pub(super) const RETRY_CLAIM_RECEIPT_PREFIX: &str = "vault.conversations.turn.retry:";

/// The claim one Retry takes, admitted and not yet written.
pub(super) struct RetryClaim {
    room: EntityId,
    /// The answering agent, the claim's holder.
    agent: EntityId,
    /// The parent turn the claim holds.
    parent: EntityId,
    /// The agent's first answer to the parent: the source turn, RESPONSE's
    /// slot once the claim lands.
    slot: EntityId,
    /// The person who pressed Retry.
    requester: EntityId,
    claimant: Claimant,
    task: Option<EntityId>,
}

impl RetryClaim {
    /// Admits the claim `action`'s Retry takes for `agent` on `parent`, its
    /// source's parent, which holds no claim and no answer. The requester
    /// must be a person who may address `agent` in the room: it stands in
    /// the parent's thread from its seat or its own Ready join, speaks there
    /// as a persona, and `agent` is a member of the room or may be named in
    /// it. An agent's press addresses no one, since an agent speaks only on
    /// its own claim or task. `agent` must then claim the parent as the
    /// claim door admits an agent, the press standing for its address. A
    /// parent that names other agents is theirs to answer.
    pub(super) fn admit_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        action: &TurnActionAttempt,
        agent: EntityId,
        parent: EntityId,
        parent_row: &RoomTurn,
    ) -> Result<Self> {
        let room = action.conversation;
        if parent_row.room_id != room.to_hex()
            || RESPONSE.get(&vault.store, txn, &parent)?.is_some()
            || (!parent_row.addressed_agents.is_empty()
                && !parent_row.addressed_agents.contains(&agent.to_hex()))
        {
            return Err(invalid());
        }
        let requester = action.actor;
        let now = vault.store.clock.now_recorded_at();
        if matches!(
            participant_in_txn(vault, txn, requester, now)?,
            Some(JoinSubject::Agent(_))
        ) {
            return Err(invalid());
        }
        let person = Claimant::admit_in_txn(vault, txn, room, parent_row, requester)?;
        if person.is_agent() {
            return Err(invalid());
        }
        person.admit_speech_in(vault, txn)?;
        if !room_access_in(vault, txn, room)?
            .member_ids
            .contains(&agent.to_hex())
            && !addressable_agent_in_txn(vault, txn, agent, now)?
        {
            return Err(invalid());
        }
        let claimant = Claimant::admit_in_txn(vault, txn, room, parent_row, agent)?;
        if !claimant.is_agent() {
            return Err(invalid());
        }
        claimant.admit_speech_in(vault, txn)?;
        let task = claimant.held_task_in_txn(vault, txn, parent_row)?;
        Ok(Self {
            room,
            agent,
            parent,
            slot: action.assistant_turn,
            requester,
            claimant,
            task,
        })
    }

    /// The turn RESPONSE holds for the parent once the claim lands.
    pub(super) const fn slot(&self) -> EntityId {
        self.slot
    }

    /// The parent turn the claim holds.
    pub(super) const fn parent(&self) -> EntityId {
        self.parent
    }

    /// Writes the claim at `at`, its slot, and the agent's participation as
    /// addressed on the parent (with the thread's task it holds), in `txn`,
    /// the write that lands the Retry's reply. A claim or answer that landed
    /// since the admission refuses.
    pub(super) fn take_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        at: u64,
    ) -> Result<()> {
        if CLAIMS.get(&vault.store, txn, &self.parent)?.is_some()
            || RESPONSE.get(&vault.store, txn, &self.parent)?.is_some()
        {
            return Err(invalid());
        }
        let receipt = RoomClaimReceipt {
            room_id: self.room.to_hex(),
            turn_id: self.parent.to_hex(),
            actor: self.agent.to_hex(),
            receipt_ref: format!("{RETRY_CLAIM_RECEIPT_PREFIX}{}", self.requester.to_hex()),
            at,
        };
        CLAIMS.put(&vault.store, txn, &self.parent, &receipt)?;
        RESPONSE.put(&vault.store, txn, &self.parent, &self.slot)?;
        self.claimant
            .record_in_txn(vault, txn, self.parent, true, self.task)
    }
}
