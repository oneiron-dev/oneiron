//! Node-local frozen fan-out plans and transaction-owned surface sink.

use super::{
    ConsultFanOutMeter, ConsultFanOutPause, ConsultFanOutPolicy, ConsultFanOutReceipt,
    ConsultFanOutSpec, ConsultPayloadRef,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::outbound_chokepoint::{
    FanoutApprovalRow, FanoutEstimate, FanoutPlan, FanoutPlanEdge, FanoutSurfaceSink,
};
use crate::receipt::ReceiptRecord;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use serde::{Deserialize, Serialize};

pub(super) const RUN_PREFIX: &[u8] = b"tasks/fanout/v1/";
pub(super) const POLICY_KEY: &[u8] = b"tasks/fanout_policy/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct FrozenInput {
    question: String,
    contexts: Vec<String>,
    pub(super) assignees: Vec<String>,
    pub(super) deadline_at: u64,
    label: Option<String>,
    now: u64,
}

impl FrozenInput {
    pub(super) fn new(input: &ConsultFanOutSpec, now: u64) -> Self {
        let mut assignees: Vec<_> = input.assignees.iter().map(EntityId::to_hex).collect();
        assignees.sort_unstable();
        Self {
            question: input.question_ref.short_ref(),
            contexts: input
                .context_refs
                .iter()
                .map(|item| item.short_ref())
                .collect(),
            assignees,
            deadline_at: input.deadline_at,
            label: input.label.clone(),
            now,
        }
    }

    pub(super) fn thaw(&self, vault: &Vault, now: u64) -> MemoryResult<ConsultFanOutSpec> {
        Ok(ConsultFanOutSpec {
            question_ref: ConsultPayloadRef::parse(vault, &self.question)?,
            context_refs: self
                .contexts
                .iter()
                .map(|item| ConsultPayloadRef::parse(vault, item))
                .collect::<Result<Vec<_>>>()?,
            assignees: self
                .assignees
                .iter()
                .map(|item| EntityId::from_hex(item))
                .collect::<Result<Vec<_>>>()?,
            deadline_at: self.deadline_at,
            label: self.label.clone(),
            now: Some(now),
        })
    }

    pub(super) fn plan(
        &self,
        actor: EntityId,
        correlation: EntityId,
        policy: &ConsultFanOutPolicy,
    ) -> Result<FanoutPlan> {
        // Bind EVERY task field (not only assignee counts) into the existing
        // graph digest via plan_ref. Resume never takes a replacement input.
        let request_hash = blake3::hash(&encode(self)?).to_hex().to_string();
        Ok(FanoutPlan {
            plan_ref: format!("{}:{request_hash}", correlation.to_hex()),
            brief_ref: self.question.clone(),
            actor_ref: actor.to_hex(),
            mode: policy.mode,
            edges: self
                .assignees
                .iter()
                .map(|peer| FanoutPlanEdge {
                    from_peer_ref: actor.to_hex(),
                    to_peer_ref: peer.clone(),
                    count: 1,
                })
                .collect(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredFanout {
    pub(super) correlation: String,
    pub(super) input: FrozenInput,
    pub(super) plan: FanoutPlan,
    pub(super) estimate: FanoutEstimate,
    pub(super) pause: Option<FanoutApprovalRow>,
    pub(super) dispatched_at: Option<u64>,
    pub(super) task_refs: Vec<String>,
    pub(super) denied: bool,
    pub(super) choice_receipt_ref: Option<String>,
}

impl StoredFanout {
    pub(super) fn scope(&self) -> String {
        // A cap is for this actor, this durable question and the consult verb.
        format!("consult:{}:{}", self.plan.actor_ref, self.plan.brief_ref)
    }

    pub(super) fn receipt(&self) -> MemoryResult<ConsultFanOutReceipt> {
        Ok(ConsultFanOutReceipt {
            correlation_ref: EntityId::from_hex(&self.correlation)?,
            task_refs: self
                .task_refs
                .iter()
                .map(|item| EntityId::from_hex(item))
                .collect::<Result<Vec<_>>>()?,
            meter: ConsultFanOutMeter {
                total_count: self.estimate.total_count,
                per_peer: self.estimate.per_peer.clone(),
                plan_digest: self.estimate.plan_digest,
                board_rows: crate::context_board::fanout_agent_rows(
                    &self.correlation,
                    &self.estimate,
                    self.pause.as_ref().and_then(|row| row.pathology.as_ref()),
                    self.dispatched_at.is_none(),
                    self.denied,
                ),
            },
            paused: self
                .pause
                .as_ref()
                .filter(|_| self.dispatched_at.is_none())
                .map(|row| ConsultFanOutPause {
                    surface_ref: row.row_ref.clone(),
                    denied: self.denied,
                }),
            choice_receipt_ref: self.choice_receipt_ref.clone(),
        })
    }
}

pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| Error::InvariantViolation("fanout encoding"))
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::CorruptedIndex("fanout row"))
}

fn run_key(correlation: &str) -> Vec<u8> {
    [RUN_PREFIX, correlation.as_bytes()].concat()
}

pub(super) fn save_run(vault: &Vault, txn: &mut heed::RwTxn<'_>, run: &StoredFanout) -> Result<()> {
    vault
        .store
        .vault_meta
        .put(txn, &run_key(&run.correlation), &encode(run)?)?;
    Ok(())
}

pub(super) fn load_run(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    correlation: EntityId,
) -> MemoryResult<StoredFanout> {
    let raw = vault
        .store
        .vault_meta
        .get(txn, &run_key(&correlation.to_hex()))?
        .ok_or_else(|| MemoryError::not_found("fan-out plan not found"))?;
    Ok(decode(&raw)?)
}

pub(super) fn runs_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<StoredFanout>> {
    vault
        .store
        .vault_meta
        .prefix_iter(txn, RUN_PREFIX)?
        .map(|entry| {
            let (_, raw) = entry?;
            decode(&raw)
        })
        .collect()
}

pub(super) fn policy_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ConsultFanOutPolicy> {
    vault
        .store
        .vault_meta
        .get(txn, POLICY_KEY)?
        .map(|raw| decode(&raw))
        .transpose()
        .map(Option::unwrap_or_default)
}

/// The caller commits this transaction before returning any durable ref.
/// A failed mint rolls back pause, choice, policy and TASK rows together.
pub(super) struct TxnSurface<'a, 'env> {
    pub(super) vault: &'a Vault,
    pub(super) txn: &'a mut heed::RwTxn<'env>,
    pub(super) run: &'a mut StoredFanout,
}

impl FanoutSurfaceSink for TxnSurface<'_, '_> {
    fn persist_pause_row(&mut self, row: &FanoutApprovalRow) -> Result<String> {
        self.run.pause = Some(row.clone());
        save_run(self.vault, self.txn, self.run)?;
        Ok(row.row_ref.clone())
    }

    fn persist_choice_receipt(&mut self, receipt: &ReceiptRecord) -> Result<String> {
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, self.txn)?;
        let mut decision = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::now(),
            created_at: receipt.occurred_at / 1000,
            outcome: receipt.outcome.clone(),
            reason_codes: vec!["gate.fanout.human_ruling".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "human".to_owned(),
            actor_ref: receipt.actor.clone(),
            content_kind: "consult_fanout".to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(self.run.correlation.clone()),
            diff_handle: self.run.estimate.plan_digest.to_vec(),
            read_frontier_hash: policy.read_frontier_hash()?,
            redacted_at: None,
        };
        self.vault
            .store
            .append_fresh_gate_decision_in_txn(self.txn, &mut decision)?;
        let receipt_ref = format!("gate:{}", decision.decision_id.to_hex());
        self.run.choice_receipt_ref = Some(receipt_ref.clone());
        Ok(receipt_ref)
    }
}
