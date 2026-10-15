use std::collections::{HashMap, VecDeque};

use crate::entity_id::EntityId;

use super::ClaimMaterialization;

#[derive(Debug)]
pub(crate) struct ApplyOpsGateMode {
    pub(super) hub_admission: Option<crate::skill_hub::HubAdmissionProof>,
    pub(super) refinement_admission: Option<crate::skill_hub::RefinementAdmissionProof>,
    pub(super) record_decisions: bool,
    pub(super) persist_pending_consent: bool,
    pub(super) include_source_in_gate_input: bool,
    pub(super) claim_gate_prechecked: bool,
    pub(super) claim_materializations: VecDeque<ClaimMaterialization>,
    pub(super) claim_transitions: VecDeque<super::VerifiedClaimTransition>,
    pub(super) preflight_gate_decision_ids:
        HashMap<EntityId, VecDeque<Option<crate::store::GateDecisionId>>>,
    /// The caller's active mask: the FACET every NOTE and ASSET born in this
    /// batch is stamped with. `None` stamps the vault default.
    pub(super) birth_mask: Option<EntityId>,
    /// BM25 analyses of this batch's text ops, done before the write
    /// transaction opened; consumed per id in op order.
    pub(super) pre_analyzed_text: HashMap<EntityId, VecDeque<Option<crate::bm25::AnalyzedText>>>,
    /// HNSW insert plans of this batch's vector ops, searched under a read
    /// snapshot before the write transaction opened; consumed per id in op
    /// order.
    pub(super) nsw_plans: HashMap<EntityId, VecDeque<crate::hnsw::InsertPlan>>,
}

impl ApplyOpsGateMode {
    pub(crate) fn new(record_decisions: bool, persist_pending_consent: bool) -> Self {
        Self {
            hub_admission: None,
            refinement_admission: None,
            record_decisions,
            persist_pending_consent,
            include_source_in_gate_input: false,
            claim_gate_prechecked: false,
            claim_materializations: VecDeque::new(),
            claim_transitions: VecDeque::new(),
            preflight_gate_decision_ids: HashMap::new(),
            birth_mask: None,
            pre_analyzed_text: HashMap::new(),
            nsw_plans: HashMap::new(),
        }
    }

    pub(crate) fn with_refinement_admission(
        mut self,
        proof: crate::skill_hub::RefinementAdmissionProof,
    ) -> Self {
        self.refinement_admission = Some(proof);
        self
    }

    pub(super) fn with_birth_mask(mut self, mask: Option<EntityId>) -> Self {
        self.birth_mask = mask;
        self
    }

    /// Hands the apply the work a committing batch did before its write
    /// transaction opened (RESEARCH-1115 Bend 2): BM25 analyses and HNSW
    /// neighbour searches. Each is checked against the transaction's own state
    /// before use, so a stale one falls back to the in-transaction path.
    pub(super) fn with_prepared(mut self, prepared: super::PreparedIndexWork) -> Self {
        self.pre_analyzed_text = prepared.text;
        self.nsw_plans = prepared.vectors;
        self
    }

    pub(crate) fn with_hub_admission(mut self, proof: crate::skill_hub::HubAdmissionProof) -> Self {
        self.hub_admission = Some(proof);
        self
    }

    pub(crate) fn with_claim_materializations(
        mut self,
        bindings: Vec<ClaimMaterialization>,
    ) -> Self {
        self.claim_materializations = bindings.into();
        self
    }

    pub(crate) fn with_verified_claim_transitions(
        mut self,
        proofs: Vec<super::VerifiedClaimTransition>,
    ) -> Self {
        self.claim_transitions = proofs.into();
        self
    }

    pub(crate) fn with_source_in_gate_input(mut self) -> Self {
        self.include_source_in_gate_input = true;
        self
    }

    /// Marks local CLAIM puts as already authorized in this transaction.
    /// Structural validation and materialization still run; only the duplicate
    /// gate evaluation in `apply_put` is skipped.
    pub(super) fn with_prechecked_claim_gate(mut self) -> Self {
        self.claim_gate_prechecked = true;
        self
    }

    /// Binds the receipt identities a same-transaction gate preflight already
    /// recorded. Reachable crate-wide because `commitment::lapse_commitments_in_txn`
    /// composes the batch apply from inside a `CommitmentGapDecay` op and must
    /// carry its preflight identities forward rather than mint fresh ones.
    pub(crate) fn with_preflight_gate_decision_ids(
        mut self,
        preflight_gate_decision_ids: HashMap<
            EntityId,
            VecDeque<Option<crate::store::GateDecisionId>>,
        >,
    ) -> Self {
        self.preflight_gate_decision_ids = preflight_gate_decision_ids;
        self
    }
}
