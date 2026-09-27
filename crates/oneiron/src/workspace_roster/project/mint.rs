//! Owner-confirmed project birth: one card, one atomic Grant and project branch.
use super::{ProjectRecord, ROOT, decode, encode, invalid, project_type, record};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::genui::{ConsentActionRequest, ProjectProposalCard};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL,
};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{EntityId, Result, TimeRange, Vault};
use serde::{Deserialize, Serialize};

const TAP: &[u8] = b"project.mint.tap.v1/";

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
}

pub(super) fn key(prefix: &[u8], id: &[u8]) -> Vec<u8> {
    [prefix, id].concat()
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
    /// Consumes a host-held card and its authenticated owner tap. An intent
    /// supplied by a client cannot call this door: the tap is checked again
    /// against the card, then all referenced entities are resolved in the write
    /// transaction. Failure commits neither forks nor project nor Grant.
    pub fn mint_project_from_card(
        &self,
        card: &ProjectProposalCard,
        tap: &ConsentActionRequest,
        owner: &AuthenticatedOwner,
    ) -> Result<ProjectMintReceipt> {
        let intent = card.evaluate_action(tap, owner)?;
        let digest = blake3::hash(&encode(&(card, owner.actor()))?);
        let tap_key = key(TAP, blake3::hash(card.card_id.as_bytes()).as_bytes());
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            if let Some(raw) = self.store.vault_meta.get(txn, &tap_key)? {
                let (stored_digest, receipt): ([u8; 32], ProjectMintReceipt) = decode(&raw)?;
                if stored_digest != *digest.as_bytes() {
                    return Err(invalid());
                }
                // A deleted or rewritten project cannot be resurrected by a
                // stale tap mapping. The grant is an audit record, not authority
                // to create it again.
                let id = EntityId::from_hex(&receipt.project_id).map_err(|_| invalid())?;
                if record::<ProjectRecord>(&self.store, txn, id, self.project_type_byte()?)?
                    .is_none()
                    || self
                        .store
                        .gate_decision_in_txn(txn, receipt.grant_decision_id)?
                        .is_none()
                {
                    return Err(invalid());
                }
                return Ok(receipt);
            }
            let root_id = EntityId::from_bytes(
                self.store
                    .vault_meta
                    .get(txn, ROOT)?
                    .ok_or_else(invalid)?
                    .as_ref()
                    .try_into()
                    .map_err(|_| invalid())?,
            )?;
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
            let born_from =
                checked_ref(self, txn, &intent.source_message_ref, ENTITY_TYPE_MESSAGE)?;
            let mut board = Vec::with_capacity(intent.board_human_refs.len());
            for human in &intent.board_human_refs {
                board.push(checked_ref(self, txn, human, ENTITY_TYPE_PERSON)?);
            }
            let mut skills = Vec::with_capacity(intent.starting_skill_refs.len());
            for source in &intent.starting_skill_refs {
                skills.push(checked_ref(self, txn, source, ENTITY_TYPE_SKILL)?);
            }
            let id = EntityId::now();
            let at = tap.occurred_at;
            let period = TimeRange { start: at, end: at };
            let mut project = ProjectRecord::new(
                id,
                Some(root_id),
                EntityId::from_hex(&root.claims_scope_ref).map_err(|_| invalid())?,
                leader,
            );
            project.board = board.iter().map(EntityId::to_hex).collect();
            project.roster.extend(project.board.iter().cloned());
            project.born_from = Some(born_from.to_hex());
            project.why = Some(intent.goal.why.clone());
            for (index, parent) in skills.iter().enumerate() {
                let fork_id = EntityId::now();
                let fork_name = format!("project.{}.{}", id.to_hex(), index);
                self.fork_skill_record_in_txn(txn, parent, &fork_id, &fork_name, period, at)?;
                project.skill_forks.push(fork_id.to_hex());
            }
            let goal = ProjectGoalRecord {
                project_id: id.to_hex(),
                goal: intent.goal.goal,
                why: intent.goal.why,
                axes: intent.goal.axes,
            };
            let budget = ProjectBudgetShare {
                project_id: id.to_hex(),
                parent_id: root_id.to_hex(),
                share_bps: intent.budget_share_bps,
            };
            project.goal_record = Some(goal);
            project.budget_share = Some(budget);
            self.batch_in()
                .put(
                    &id,
                    project_type(&self.store).ok_or_else(invalid)?,
                    period,
                    at,
                    &encode(&project)?,
                )
                .apply(txn)?;
            let mut decision = GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id: GateDecisionId::now(),
                created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
                outcome: "approved".into(),
                reason_codes: vec!["gate.project_mint".into()],
                receipt_reasons: vec![],
                system_notices: vec![],
                actor_class: "human".into(),
                actor_ref: Some(owner.actor().to_hex()),
                content_kind: "project_mint".into(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                claim_id: None,
                grant_ref: Some(id.to_hex()),
                diff_handle: digest.as_bytes().to_vec(),
                read_frontier_hash: [0; 32],
                redacted_at: None,
            };
            self.store
                .append_fresh_gate_decision_in_txn(txn, &mut decision)?;
            let receipt = ProjectMintReceipt {
                project_id: id.to_hex(),
                card_id: card.card_id.clone(),
                grant_decision_id: decision.decision_id,
            };
            self.store
                .vault_meta
                .put(txn, &tap_key, &encode(&(*digest.as_bytes(), &receipt))?)?;
            Ok(receipt)
        })
    }

    pub fn project_goal_record(&self, id: EntityId) -> Result<Option<ProjectGoalRecord>> {
        Ok(self.project(id)?.and_then(|project| project.goal_record))
    }

    pub fn project_budget_share(&self, id: EntityId) -> Result<Option<ProjectBudgetShare>> {
        Ok(self.project(id)?.and_then(|project| project.budget_share))
    }
}
