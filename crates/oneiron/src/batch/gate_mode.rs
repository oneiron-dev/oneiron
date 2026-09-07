use std::collections::{HashMap, VecDeque};

use crate::entity_id::EntityId;

use super::{ClaimMaterialization, StagedClaimGateOutcome};

#[derive(Debug)]
pub(crate) struct ApplyOpsGateMode {
    pub(super) record_decisions: bool,
    pub(super) persist_pending_consent: bool,
    pub(super) include_source_in_gate_input: bool,
    pub(super) claim_gate_prechecked: bool,
    pub(super) claim_materializations: VecDeque<ClaimMaterialization>,
    pub(super) preflight_gate_decision_ids:
        HashMap<EntityId, VecDeque<Option<crate::store::GateDecisionId>>>,
    /// ONE-1453: the gate verdicts this transaction's preflight already
    /// recorded, keyed by operation receipt identity. Only claims whose ORIGINAL event the
    /// burst breaker booked appear here; everything else keeps the landed
    /// `apply_put` gate path byte for byte.
    pub(super) staged_claim_gate:
        Option<HashMap<crate::store::GateDecisionId, StagedClaimGateOutcome>>,
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
            staged_claim_gate: None,
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

    /// Binds the gate verdicts this transaction's preflight already recorded
    /// for local claims the ONE-1453 burst breaker booked (ONE-1453).
    ///
    /// Not a general gate bypass: the map is crate-private, `BatchBuilder`
    /// builds it only from decisions IT staged in THIS transaction, and the
    /// door that consumes it enforces rather than re-evaluates.
    pub(crate) fn with_staged_claim_gate(
        mut self,
        staged_claim_gate: HashMap<crate::store::GateDecisionId, StagedClaimGateOutcome>,
    ) -> Self {
        self.staged_claim_gate = Some(staged_claim_gate);
        self
    }
}
