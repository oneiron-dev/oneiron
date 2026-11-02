//! Who answers a widen proposal as the board above (FIX 9565): a revalidated
//! root Owner of this vault, or the parent agent whose live host lease holds
//! the board attempt, on a board TASK whose folded authority is live. An
//! agent's act lands as a recorded board act: it never stands in for an
//! owner and mints no owner consent.

use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};

use super::super::codec::record_dispatch_input;
use super::super::widen_record::{BoardProof, invalid};
use super::super::{AgentDispatcher, ContextWidenProposal};

/// Who answers a proposal as the board above.
pub(super) enum BoardActor<'a> {
    /// A human root Owner of this vault, revalidated in the answering writer.
    Owner(&'a AuthenticatedOwner),
    /// The board attempt's own agent: the lease its host captured, rechecked
    /// live in the answering writer.
    Agent(&'a AttemptRecord),
}

/// A proven board act: who answered, under which proof.
pub(super) struct BoardAct {
    pub(super) actor: EntityId,
    pub(super) proof: BoardProof,
}

impl AgentDispatcher<'_> {
    /// Proves `actor` may answer as `board`, the immediate board above a
    /// proposal's parent, in `txn`. A root Owner holds the vault's whole
    /// grant, so it answers with or without a board above. An agent answers
    /// only as the board attempt its lease holds now, while that board's
    /// TASK authority is live.
    pub(super) fn authorize_board_act_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        board: Option<AttemptId>,
        actor: &BoardActor<'_>,
    ) -> Result<BoardAct> {
        match actor {
            BoardActor::Owner(owner) => {
                let person = owner.revalidate_in_txn(self.vault, txn)?;
                self.require_active_human(txn, person)?;
                Ok(BoardAct {
                    actor: person,
                    proof: BoardProof::RootOwner,
                })
            }
            BoardActor::Agent(lease) => {
                let board = board.ok_or_else(|| invalid("widen has no provable board above"))?;
                let current = AttemptQueue::new(self.vault)
                    .get_in_txn(txn, board)?
                    .ok_or_else(|| invalid("widen board attempt is missing"))?;
                if lease.id != board
                    || current.state != AttemptState::Leased
                    || current.lease_owner.is_none()
                    || current.lease_owner != lease.lease_owner
                    || current.attempt_count != lease.attempt_count
                {
                    return Err(invalid(
                        "the board above is not leased to this worker at this generation",
                    ));
                }
                Ok(BoardAct {
                    actor: self.live_board_agent_in_txn(txn, board)?,
                    proof: BoardProof::ParentAgent,
                })
            }
        }
    }

    /// Replays a landed board act live, at every read of the slice it
    /// landed. A root Owner's act holds while its actor is a live human who
    /// is an owner of this vault or owns the board's TASK; an agent's while
    /// the board's TASK authority is live and the board is still that
    /// agent's.
    pub(super) fn replay_board_act_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        board: Option<AttemptId>,
        actor: EntityId,
        proof: BoardProof,
    ) -> Result<()> {
        match proof {
            BoardProof::RootOwner => {
                let owns_board = match board {
                    Some(board) => self.board_task_owner_in_txn(txn, board)? == Some(actor),
                    None => false,
                };
                if !owns_board
                    && !crate::policy_model::is_live_vault_owner_in_txn(self.vault, txn, &actor)?
                {
                    return Err(invalid("board owner is no longer an owner of this vault"));
                }
                self.require_active_human(txn, actor)
            }
            BoardProof::ParentAgent => {
                let board = board.ok_or_else(|| invalid("an agent's board act names no board"))?;
                if self.live_board_agent_in_txn(txn, board)? != actor {
                    return Err(invalid("the board above is no longer the agent that acted"));
                }
                Ok(())
            }
        }
    }

    /// Records an agent's board act (`outcome` `approved` or `denied`) in
    /// the decision ledger beside the pending row its proposal opened, on
    /// the same effect digest. A board act, not a consent: no consent reader
    /// takes it for one.
    pub(super) fn record_board_act_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        act: &BoardAct,
        proposal: &ContextWidenProposal,
        outcome: &str,
        at: u64,
    ) -> Result<()> {
        self.vault.store.append_gate_decision_in_txn(
            wtxn,
            &GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id: GateDecisionId::from_bytes(*self.vault.new_entity_id()?.as_bytes()),
                created_at: at,
                outcome: outcome.to_owned(),
                reason_codes: vec!["gate.context.board_widen".to_owned()],
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: "agent".to_owned(),
                actor_ref: Some(act.actor.to_hex()),
                content_kind: "board_widen".to_owned(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
                claim_id: None,
                grant_ref: None,
                diff_handle: proposal.consent.effect_digest.as_bytes().to_vec(),
                read_frontier_hash: [0; 32],
                context: Default::default(),
                redacted_at: None,
            },
        )
    }

    /// The board attempt's agent, while the board's folded TASK authority
    /// is live: an agent dispatch, on a TASK whose facts prove an owner and
    /// that is not cancelled.
    fn live_board_agent_in_txn(&self, txn: &heed::RoTxn<'_>, board: AttemptId) -> Result<EntityId> {
        let row = AttemptQueue::new(self.vault)
            .get_in_txn(txn, board)?
            .ok_or_else(|| invalid("widen board attempt is missing"))?;
        let input = record_dispatch_input(&row)
            .ok_or_else(|| invalid("widen board is not an agent dispatch"))?;
        let standing = self
            .vault
            .task_authority_state_in(txn, board_task(&row)?)?
            .ok_or_else(|| invalid("widen board TASK has no owner proof"))?;
        if standing.cancelled {
            return Err(invalid("widen board TASK is cancelled"));
        }
        input.target.agent_definition_ref()
    }

    /// The owner the board's TASK facts prove, while it is not cancelled.
    fn board_task_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        board: AttemptId,
    ) -> Result<Option<EntityId>> {
        let Some(row) = AttemptQueue::new(self.vault).get_in_txn(txn, board)? else {
            return Ok(None);
        };
        let Ok(task) = board_task(&row) else {
            return Ok(None);
        };
        Ok(self
            .vault
            .task_authority_state_in(txn, task)?
            .filter(|standing| !standing.cancelled)
            .map(|standing| standing.owner_ref))
    }

    /// Refuses `person` unless it is a live PERSON row, active.
    fn require_active_human(&self, txn: &heed::RoTxn<'_>, person: EntityId) -> Result<()> {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.vault.store, txn, &person)?
            .ok_or_else(|| invalid("board owner is no longer present"))?;
        if crate::batch::EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_PERSON)
            || self.vault.entity_lifecycle_state_in_txn(txn, &person)?
                != crate::identity_topology::EntityLifecycleState::Active
        {
            return Err(invalid("board owner is no longer an active human"));
        }
        Ok(())
    }
}

/// The authority-bearing TASK a board attempt works on.
fn board_task(row: &AttemptRecord) -> Result<EntityId> {
    row.task_ref
        .as_deref()
        .and_then(|id| EntityId::from_hex(id).ok())
        .ok_or_else(|| invalid("widen board has no authority-bearing TASK"))
}
