//! Node-local frozen fan-out plans and transaction-owned surface sink.

use super::{
    ConsultFanOutMeter, ConsultFanOutPause, ConsultFanOutPolicy, ConsultFanOutReceipt,
    ConsultFanOutScope, ConsultFanOutSpec, ConsultPayloadRef,
};
use crate::Vault;
use crate::agent_dispatch::{FanoutStatement, WidthCheckClass};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::outbound_chokepoint::{
    FanoutApprovalRow, FanoutEstimate, FanoutPlan, FanoutPlanEdge, FanoutSurfaceSink,
    FanoutWidthCheck, FanoutWidthClass,
};
use crate::receipt::ReceiptRecord;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use serde::{Deserialize, Serialize};

/// One fan-out run's frozen plan and progress, keyed by its correlation id.
pub(super) const FANOUT_RUNS: SideTable<HexId, StoredFanout, Named> =
    SideTable::new(&side_table::TASK_FANOUT_RUN);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct FrozenInput {
    question: String,
    contexts: Vec<String>,
    pub(super) assignees: Vec<String>,
    pub(super) deadline_at: u64,
    label: Option<String>,
    pub(super) now: u64,
    /// An explicit preset scopes a counted fan-out standing ruling.
    pub(super) preset: Option<String>,
    pub(super) policy_scope: ConsultFanOutScope,
}

impl FrozenInput {
    pub(super) fn new(
        input: &ConsultFanOutSpec,
        now: u64,
        preset: Option<&str>,
        policy_scope: ConsultFanOutScope,
    ) -> Self {
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
            preset: preset.map(str::to_owned),
            policy_scope,
        }
    }

    pub(super) fn thaw(&self, vault: &Vault) -> MemoryResult<ConsultFanOutSpec> {
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
            now: Some(self.now),
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
            edges: {
                let mut counts = std::collections::BTreeMap::<&str, u32>::new();
                for peer in &self.assignees {
                    let count = counts.entry(peer).or_default();
                    *count = count
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow("fan-out per-peer count"))?;
                }
                counts
                    .into_iter()
                    .map(|(peer, count)| FanoutPlanEdge {
                        from_peer_ref: actor.to_hex(),
                        to_peer_ref: peer.to_owned(),
                        count,
                    })
                    .collect()
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredFanout {
    pub(super) correlation: String,
    pub(super) input: FrozenInput,
    pub(super) plan: FanoutPlan,
    pub(super) estimate: FanoutEstimate,
    /// Stated before any TASK was minted; every read returns this copy.
    pub(super) statement: FanoutStatement,
    pub(super) pause: Option<FanoutApprovalRow>,
    /// The non-blocking question row of the exceptional-width check of a
    /// full-access run above the threshold. The run was minted regardless.
    pub(super) check_row: Option<FanoutApprovalRow>,
    pub(super) dispatched_at: Option<u64>,
    pub(super) task_refs: Vec<String>,
    pub(super) denied: bool,
    pub(super) choice_receipt_ref: Option<String>,
    /// Shipped default rows the admission decision read in place of rows
    /// missing from the vault manifest. Runs stored before this field read
    /// as empty.
    #[serde(default)]
    pub(super) shipped_policy_rows: Vec<String>,
}

impl StoredFanout {
    pub(super) fn scope(&self) -> String {
        // A cap is for this actor, this durable question and the consult verb.
        match &self.input.preset {
            Some(preset) => format!("consult:{}:preset:{preset}", self.plan.actor_ref),
            None => format!("consult:{}:{}", self.plan.actor_ref, self.plan.brief_ref),
        }
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
                board_rows: super::consult_fanout_types::fanout_meter_rows(
                    &self.correlation,
                    &self.estimate,
                    self.pause.as_ref().and_then(|row| row.pathology.as_ref()),
                    self.dispatched_at.is_none(),
                    self.denied,
                ),
                statement: self.statement.clone(),
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
            shipped_policy_rows: self.shipped_policy_rows.clone(),
        })
    }
}

pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| Error::InvariantViolation("fanout encoding"))
}

pub(super) fn save_run(vault: &Vault, txn: &mut heed::RwTxn<'_>, run: &StoredFanout) -> Result<()> {
    let correlation = EntityId::from_hex(&run.correlation)?;
    FANOUT_RUNS.put(&vault.store, txn, &HexId(correlation), run)
}

pub(super) fn load_run(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    correlation: EntityId,
) -> MemoryResult<StoredFanout> {
    FANOUT_RUNS
        .get(&vault.store, txn, &HexId(correlation))?
        .ok_or_else(|| MemoryError::not_found("fan-out plan not found"))
}

pub(super) fn runs_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<StoredFanout>> {
    Ok(FANOUT_RUNS
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, run)| run)
        .collect())
}

pub(super) fn policy_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &ConsultFanOutScope,
) -> Result<crate::gate::fanout_policy::ResolvedFanoutPolicy> {
    crate::gate::resolve_policy_manifest(&vault.store, txn)?.consult_fanout_policy_for(scope)
}

/// The caller commits this transaction before returning any durable ref.
/// A failed mint rolls back pause, check, choice, policy and TASK rows
/// together.
pub(super) struct TxnSurface<'a, 'env> {
    pub(super) vault: &'a Vault,
    pub(super) txn: &'a mut heed::RwTxn<'env>,
    pub(super) run: &'a mut StoredFanout,
    /// The accepted standing policy row an AUTO clearance stood on, if any.
    pub(super) clearance: Option<String>,
}

impl FanoutSurfaceSink for TxnSurface<'_, '_> {
    fn persist_pause_row(&mut self, row: &FanoutApprovalRow) -> Result<String> {
        self.run.pause = Some(row.clone());
        save_run(self.vault, self.txn, self.run)?;
        Ok(row.row_ref.clone())
    }

    fn persist_width_check(&mut self, check: &FanoutWidthCheck) -> Result<Option<String>> {
        let (classification, row) = match &check.class {
            FanoutWidthClass::AutoClear => (
                WidthCheckClass::AutoClear {
                    policy_ref: self.clearance.clone(),
                },
                None,
            ),
            FanoutWidthClass::Asked { row } => (
                WidthCheckClass::Asked {
                    row_ref: row.row_ref.clone(),
                },
                Some(row),
            ),
        };
        self.run
            .statement
            .raise_width_check(u64::from(check.threshold), classification);
        let surface_ref = row.map(|row| {
            let mut row = (**row).clone();
            row.statement = Some(self.run.statement.clone());
            let row_ref = row.row_ref.clone();
            self.run.check_row = Some(row);
            row_ref
        });
        save_run(self.vault, self.txn, self.run)?;
        Ok(surface_ref)
    }

    fn persist_choice_receipt(&mut self, receipt: &ReceiptRecord) -> Result<String> {
        let receipt_ref = append_human_ruling(
            self.vault,
            self.txn,
            receipt,
            "consult_fanout",
            self.run.correlation.clone(),
            self.run.estimate.plan_digest,
        )?;
        self.run.choice_receipt_ref = Some(receipt_ref.clone());
        Ok(receipt_ref)
    }
}

/// Appends a human fan-out ruling to the gate decision ledger in the
/// caller's transaction and returns its `gate:` ref. `grant_ref` names the
/// ruled run, `plan_digest` the exact plan the human saw.
pub(super) fn append_human_ruling(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &ReceiptRecord,
    content_kind: &str,
    grant_ref: String,
    plan_digest: [u8; 32],
) -> Result<String> {
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let mut decision = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::from_bytes(*vault.new_entity_id()?.as_bytes()),
        created_at: receipt.occurred_at / 1000,
        outcome: receipt.outcome.clone(),
        reason_codes: vec!["gate.fanout.human_ruling".to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "human".to_owned(),
        actor_ref: receipt.actor.clone(),
        content_kind: content_kind.to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: None,
        grant_ref: Some(grant_ref),
        diff_handle: plan_digest.to_vec(),
        read_frontier_hash: policy.read_frontier_hash()?,
        redacted_at: None,
    };
    vault
        .store
        .append_fresh_gate_decision_in_txn(txn, &mut decision)?;
    Ok(format!("gate:{}", decision.decision_id.to_hex()))
}
