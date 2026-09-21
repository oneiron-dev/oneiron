use std::collections::{HashMap, VecDeque};

use crate::entity_id::EntityId;

use super::ClaimMaterialization;

#[derive(Debug)]
pub(crate) struct ApplyOpsGateMode {
    pub(super) record_decisions: bool,
    pub(super) persist_pending_consent: bool,
    pub(super) include_source_in_gate_input: bool,
    pub(super) claim_gate_prechecked: bool,
    pub(super) claim_materializations: VecDeque<ClaimMaterialization>,
    pub(super) preflight_gate_decision_ids:
        HashMap<EntityId, VecDeque<Option<crate::store::GateDecisionId>>>,
}

impl ApplyOpsGateMode {
    pub(crate) fn new(record_decisions: bool, persist_pending_consent: bool) -> Self {
        Self {
            record_decisions,
            persist_pending_consent,
            include_source_in_gate_input: false,
            claim_gate_prechecked: false,
            claim_materializations: VecDeque::new(),
            preflight_gate_decision_ids: HashMap::new(),
        }
    }

    pub(super) fn with_claim_materializations(
        mut self,
        bindings: Vec<ClaimMaterialization>,
    ) -> Self {
        self.claim_materializations = bindings.into();
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
