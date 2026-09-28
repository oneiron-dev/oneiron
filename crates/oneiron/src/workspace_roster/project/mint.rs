//! Owner-confirmed project birth: one card, one atomic Grant and project branch.
use super::{ProjectRecord, ROOT, encode, invalid, project_type, record};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::genui::{ConsentActionRequest, ProjectMintIntent, ProjectProposalCard};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL,
    ENTITY_TYPE_TURN,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::GateDecisionId;
use crate::{EntityId, Error, Result, TimeRange, Vault};
use serde::{Deserialize, Serialize};

/// Durable owner tap of one project card: the tap digest and the mint receipt. Key: blake3
/// hash32 of the card id.
const TAPS: SideTable<[u8; 32], ([u8; 32], ProjectMintReceipt), Named> =
    SideTable::new(&side_table::PROJECT_MINT_TAP);

/// The goal is data for the leader, not instructions in its prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalRecord {
    pub project_id: String,
    pub goal: String,
    pub why: String,
    pub axes: Vec<String>,
}

/// The share is expressed against the root project's budget, never a grant
/// to spend more than the parent has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectBudgetShare {
    pub project_id: String,
    pub parent_id: String,
    pub share_bps: u16,
}

/// A durable tap result; `grant_decision_id` identifies the Gate receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMintReceipt {
    pub project_id: String,
    pub card_id: String,
    pub grant_decision_id: GateDecisionId,
    pub grant_ref: String,
}

/// An exact tap replay re-proves its mint against the recorded Grant
/// decision, so the retention sweep keeps each durable tap's decision.
pub(crate) fn project_mint_gate_refs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<std::collections::HashSet<GateDecisionId>> {
    Ok(TAPS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, (_, receipt))| receipt.grant_decision_id)
        .collect())
}

fn checked_ref(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reference: &str,
    kind: u8,
) -> Result<EntityId> {
    let id = EntityId::from_hex(reference).map_err(|_| invalid())?;
    if id.to_hex() != reference
        || !vault
            .store
            .entities
            .get(txn, id.as_bytes())?
            .is_some_and(|raw| {
                EntityMetadataHeader::parse(&raw).is_some_and(|h| h.entity_type == kind)
                    && raw.len() > ENTITY_METADATA_HEADER_LEN
            })
    {
        return Err(invalid());
    }
    Ok(id)
}

impl Vault {
    /// Return the durable tap only when its card, project, Grant and receipt
    /// still agree. A revoked Grant is not reminted by replay.
    fn project_tap_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        tap_key: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<Option<ProjectMintReceipt>> {
        let Some(raw) = TAPS.get_bytes(&self.store, txn, tap_key)? else {
            return Ok(None);
        };
        let (stored_digest, receipt) = TAPS.decode_value(&raw).map_err(|_| invalid())?;
        if stored_digest != *digest {
            return Err(invalid());
        }
        let id = EntityId::from_hex(&receipt.project_id).map_err(|_| invalid())?;
        let decision = self
            .store
            .gate_decision_in_txn(txn, receipt.grant_decision_id)?;
        if record::<ProjectRecord>(&self.store, txn, id, self.project_type_byte()?)?.is_none()
            || self
                .consent_grant_in_txn(txn, &receipt.grant_ref)?
                .is_none()
            || decision
                .is_none_or(|row| row.grant_ref.as_deref() != Some(receipt.grant_ref.as_str()))
        {
            return Err(invalid());
        }
        Ok(Some(receipt))
    }

    /// Consumes a host-held card and its authenticated owner tap. The project,
    /// room, first witnessed trunk header, forks, bounded Grant, Gate receipt
    /// and tap mapping are one write transaction. A failed witness commits none.
    pub fn mint_project_from_card(
        &self,
        card: &ProjectProposalCard,
        tap: &ConsentActionRequest,
        owner: &AuthenticatedOwner,
    ) -> Result<ProjectMintReceipt> {
        let intent = card.evaluate_action(tap, owner)?;
        let digest = *blake3::hash(&encode(&(card, owner.actor()))?).as_bytes();
        let tap_key = *blake3::hash(card.card_id.as_bytes()).as_bytes();
        let source = EntityId::from_hex(&intent.source_message_ref).map_err(|_| invalid())?;
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        if let Some(receipt) = self.project_tap_in_txn(&txn, &tap_key, &digest)? {
            return Ok(receipt);
        }
        // PartOf is the witness door's canonical message → turn link. The
        // opening header points to that turn, not a copy of its contents.
        let turns = self
            .store
            .port_edges(
                &txn,
                &source,
                EdgeDirection::Out,
                Some(EdgeKind::PartOf),
                None,
            )?
            .collect::<Result<Vec<_>>>()?;
        if turns.len() != 1 {
            return Err(invalid());
        }
        let source_turn = turns[0].target;
        drop(txn);
        let id = EntityId::now();
        let header_turn = EntityId::now();
        let header_message = EntityId::now();
        let room = super::home_room_id(id)?;
        let header = WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(header_turn.to_hex()),
            messages: vec![WitnessMessage {
                id: Some(header_message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "project_header".into(),
                // The reference is structured metadata. Source text is never copied.
                content: String::new(),
                metadata: Some(serde_json::json!({
                    "project_source_message": source.to_hex(),
                    "project_source_thread": source_turn.to_hex(),
                })),
                is_visible: true,
                order: 0,
            }],
            occurred_at: tap.occurred_at,
        };
        let mut minted = None;
        let result = self
            .memory(owner.actor(), EdgeActorClass::Human)
            .witness_with_room_birth(&header, |txn| {
                let receipt = self
                    .mint_project_in_txn(
                        txn,
                        &intent,
                        owner,
                        id,
                        source_turn,
                        &tap_key,
                        &digest,
                        tap.occurred_at,
                    )
                    .map_err(crate::memory::MemoryError::from)?;
                minted = Some(receipt);
                Ok(())
            });
        match result {
            Ok(_) => minted.ok_or_else(invalid),
            Err(err) => {
                // Two simultaneous taps can both see an absent mapping before
                // witness acquires the writer. The loser rereads the winner's
                // exact durable result; any different card or failed first tap
                // remains a refusal, never a second project.
                let txn = self.store.env.read_txn()?;
                owner.revalidate_in_txn(self, &txn)?;
                if let Some(receipt) = self.project_tap_in_txn(&txn, &tap_key, &digest)? {
                    return Ok(receipt);
                }
                Err(Error::InvalidConfig(err.to_string()))
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one authenticated tap's pinned transaction inputs"
    )]
    fn mint_project_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        intent: &ProjectMintIntent,
        owner: &AuthenticatedOwner,
        id: EntityId,
        source_turn: EntityId,
        tap_key: &[u8; 32],
        digest: &[u8; 32],
        at: u64,
    ) -> Result<ProjectMintReceipt> {
        owner.revalidate_in_txn(self, txn)?;
        if self.project_tap_in_txn(txn, tap_key, digest)?.is_some() {
            return Err(invalid());
        }
        if self.store.entities.get(txn, id.as_bytes())?.is_some() {
            return Err(invalid());
        }
        let root_id = ROOT.get(&self.store, txn, &())?.ok_or_else(invalid)?;
        let root: ProjectRecord = record(
            &self.store,
            txn,
            root_id,
            project_type(&self.store).ok_or_else(invalid)?,
        )?
        .ok_or_else(invalid)?;
        let leader = checked_ref(
            self,
            txn,
            &intent.leader_agent_def_ref,
            ENTITY_TYPE_AGENT_DEF,
        )?;
        let born_from = checked_ref(self, txn, &intent.source_message_ref, ENTITY_TYPE_MESSAGE)?;
        checked_ref(self, txn, &source_turn.to_hex(), ENTITY_TYPE_TURN)?;
        if self
            .store
            .port_edge_get(txn, &born_from, EdgeKind::PartOf, &source_turn)?
            .is_none()
        {
            return Err(invalid());
        }
        let mut board = Vec::with_capacity(intent.board_human_refs.len());
        for human in &intent.board_human_refs {
            board.push(checked_ref(self, txn, human, ENTITY_TYPE_PERSON)?);
        }
        let mut skills = Vec::with_capacity(intent.starting_skill_refs.len());
        for source in &intent.starting_skill_refs {
            skills.push(checked_ref(self, txn, source, ENTITY_TYPE_SKILL)?);
        }
        let period = TimeRange { start: at, end: at };
        let mut project = ProjectRecord::new(
            id,
            Some(root_id),
            EntityId::from_hex(&root.claims_scope_ref).map_err(|_| invalid())?,
            leader,
        )?;
        project.board = board.iter().map(EntityId::to_hex).collect();
        project.roster.extend(project.board.iter().cloned());
        if !project.roster.contains(&owner.actor().to_hex()) {
            project.roster.push(owner.actor().to_hex());
        }
        project.born_from = Some(born_from.to_hex());
        project.why = Some(intent.goal.why.clone());
        for (index, parent) in skills.iter().enumerate() {
            let fork_id = EntityId::now();
            let fork_name = format!("project.{}.{}", id.to_hex(), index);
            self.fork_skill_record_in_txn(txn, parent, &fork_id, &fork_name, period, at)?;
            project.skill_forks.push(fork_id.to_hex());
        }
        project.goal_record = Some(ProjectGoalRecord {
            project_id: id.to_hex(),
            goal: intent.goal.goal.clone(),
            why: intent.goal.why.clone(),
            axes: intent.goal.axes.clone(),
        });
        project.budget_share = Some(ProjectBudgetShare {
            project_id: id.to_hex(),
            parent_id: root_id.to_hex(),
            share_bps: intent.budget_share_bps,
        });
        // The authenticated tap is the owner's creation act. An owner-rooted
        // vault records the creation-default birth it resolves now.
        crate::gate::project_depth::put_local_birth_in_txn(self, txn, id, at)?;
        self.batch_in()
            .put(
                &id,
                project_type(&self.store).ok_or_else(invalid)?,
                period,
                at,
                &encode(&project)?,
            )
            .apply(txn)?;
        let bound = GrantBound::action(
            ActorBound::new(leader.to_hex())?.with_actor_class("agent")?,
            ActionClass::new("project.run")?,
            ActionEnvelope::new([format!("project:{}", id.to_hex())])?
                .with_target(id.to_hex())?
                .with_budget(u64::from(intent.budget_share_bps))
                .with_receipt_required(true),
        )?;
        let grant_receipt = self.create_standing_grant_in_txn(txn, owner, bound)?;
        let grant_ref = grant_receipt.grant_ref().ok_or_else(invalid)?;
        let receipt = ProjectMintReceipt {
            project_id: id.to_hex(),
            card_id: intent.origin_component_id.clone(),
            grant_decision_id: grant_receipt.decision_id(),
            grant_ref,
        };
        let tap = (*digest, receipt);
        TAPS.put(&self.store, txn, tap_key, &tap)?;
        Ok(tap.1)
    }

    pub fn project_goal_record(&self, id: EntityId) -> Result<Option<ProjectGoalRecord>> {
        Ok(self.project(id)?.and_then(|project| project.goal_record))
    }

    pub fn project_budget_share(&self, id: EntityId) -> Result<Option<ProjectBudgetShare>> {
        Ok(self.project(id)?.and_then(|project| project.budget_share))
    }
}
