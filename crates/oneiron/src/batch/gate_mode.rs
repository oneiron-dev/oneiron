use std::collections::{HashMap, VecDeque};

use crate::batch::export::OwnerArchiveRestorePermit;
use crate::entity_id::EntityId;

use super::ClaimMaterialization;

/// One exact preflight Pending-Auto occurrence, staged only in a rolled-back
/// reader-bound probe. Ordinary apply modes carry none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingAutoProbe {
    pub(super) claim: EntityId,
    pub(super) decision: crate::store::GateDecisionId,
}

impl PendingAutoProbe {
    pub(super) fn matches(
        self,
        claim: &EntityId,
        decision: Option<crate::store::GateDecisionId>,
    ) -> bool {
        self.claim == *claim && Some(self.decision) == decision
    }
}

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
    pub(super) pending_auto_probes: HashMap<crate::store::GateDecisionId, PendingAutoProbe>,
    /// The caller's active mask: the FACET every NOTE, ASSET, EVENT and TURN
    /// born in this batch is stamped with. `None` stamps the vault default.
    /// A CLAIM carries its facet in its body and ignores the mask (FIX 7757).
    pub(super) birth_mask: Option<EntityId>,
    /// Every source each ASSET_TEXT this batch births was written from: its
    /// birth copies their one facet (`BatchBuilder::asset_text_birth`).
    pub(super) text_births: HashMap<EntityId, Vec<EntityId>>,
    /// The Rule A birth envelope of each row this batch births, stamped
    /// after every op has applied.
    pub(super) births: Vec<(EntityId, crate::store::row_birth::RowBirth)>,
    /// BM25 analyses of this batch's text ops, done before the write
    /// transaction opened; consumed per id in op order.
    pub(super) pre_analyzed_text:
        HashMap<EntityId, VecDeque<Option<crate::store::text_index::AnalyzedText>>>,
    /// HNSW insert plans of this batch's vector ops, searched under a read
    /// snapshot before the write transaction opened; consumed per id in op
    /// order.
    pub(super) nsw_plans: HashMap<EntityId, VecDeque<crate::store::vector_insert_plan::InsertPlan>>,
    /// The vault owner's in-person authorship of this batch's claim
    /// candidates, revalidated in the transaction that applies them. Raw puts
    /// never read it.
    pub(super) owner_authored: Option<crate::consent::OwnerAuthoredWrite>,
    /// The vault owner's in-person approval of ONE stored proposal, bound to
    /// its claim id and revalidated in the transaction that approves it
    /// (`ClaimMaterialization::apply_owner_approval`). The raw Put of that
    /// claim alone reads it; every other Put in the batch reads nothing.
    pub(super) owner_approval: Option<(EntityId, crate::consent::OwnerAuthoredWrite)>,
    /// Call-scoped Imported-source permit for one expression batch of the owner's archive restore.
    pub(super) owner_archive_restore: Option<OwnerArchiveRestorePermit>,
    /// The body file each ASSET put this batch stages as a manifest names,
    /// published before the batch (FIX 3677); consumed by that put.
    pub(super) asset_files: HashMap<EntityId, crate::store::AssetBodyFacts>,
    /// The bytes of each interpreted body file this batch puts, read by the
    /// door's secret scan and mask in place of its manifest (FIX 22075).
    pub(super) asset_file_bodies: HashMap<EntityId, Vec<u8>>,
    /// The rows this batch's replication applier put
    /// (`BatchBuilder::put_replicated`) and nothing else (FIX 7925): replay
    /// keeps its signed bytes for read quarantine instead of the local
    /// write-window refusal.
    pub(super) replicated_puts: std::collections::BTreeSet<EntityId>,
    /// Each ASSET `BatchBuilder::put_marked_carrier` queued, by the BLAKE3
    /// of its bytes (FIX 9034): a batch of nothing else skips the door's
    /// scan, its detection being the carrier's mark.
    pub(super) marked_carriers: std::collections::BTreeMap<EntityId, [u8; 32]>,
    /// Each bound raw CLAIM put's verified caller envelope
    /// (`BatchBuilder::caller_envelope`, FIX 8118), read by that put.
    pub(super) caller_envelopes: HashMap<EntityId, crate::WriteEnvelope>,
    pub(super) prepared_person_substrate: Option<super::PreparedPersonSubstrate>,
    pub(super) prepared_agent_birth: Option<crate::agent_def::PreparedAgentDefinitionBirth>,
    pub(super) prepared_setup_owner: Option<crate::agent_def::PreparedSetupOwner>,
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
            pending_auto_probes: HashMap::new(),
            birth_mask: None,
            text_births: HashMap::new(),
            births: Vec::new(),
            pre_analyzed_text: HashMap::new(),
            nsw_plans: HashMap::new(),
            owner_authored: None,
            owner_approval: None,
            owner_archive_restore: None,
            asset_files: HashMap::new(),
            asset_file_bodies: HashMap::new(),
            replicated_puts: std::collections::BTreeSet::new(),
            marked_carriers: std::collections::BTreeMap::new(),
            caller_envelopes: HashMap::new(),
            prepared_person_substrate: None,
            prepared_agent_birth: None,
            prepared_setup_owner: None,
        }
    }

    pub(crate) fn for_agent_setup(
        birth: crate::agent_def::PreparedAgentDefinitionBirth,
        owner: Option<crate::agent_def::PreparedSetupOwner>,
    ) -> Self {
        Self::new(false, true)
            .with_prepared_agent_birth(Some(birth))
            .with_prepared_setup_owner(owner)
    }

    pub(crate) fn with_prepared_setup_owner(
        mut self,
        owner: Option<crate::agent_def::PreparedSetupOwner>,
    ) -> Self {
        self.prepared_setup_owner = owner;
        self
    }

    pub(super) fn take_setup_owner_before(
        &mut self,
        id: EntityId,
    ) -> Option<crate::agent_def::PreparedSetupOwner> {
        if self
            .prepared_setup_owner
            .as_ref()
            .is_some_and(|owner| owner.is_before(id))
        {
            self.prepared_setup_owner.take()
        } else {
            None
        }
    }

    /// Marks this batch's claim candidates as the vault owner's own: a
    /// critical one carries its own confirmation and attaches none.
    pub(crate) fn with_owner_authored(
        mut self,
        owner_authored: Option<crate::consent::OwnerAuthoredWrite>,
    ) -> Self {
        self.owner_authored = owner_authored;
        self
    }

    /// Binds the owner's approval proof to the one claim this batch approves.
    pub(super) fn with_owner_approval(
        mut self,
        claim: EntityId,
        owner_approval: Option<crate::consent::OwnerAuthoredWrite>,
    ) -> Self {
        self.owner_approval = owner_approval.map(|proof| (claim, proof));
        self
    }

    pub(crate) fn with_owner_archive_restore(mut self, permit: &OwnerArchiveRestorePermit) -> Self {
        self.owner_archive_restore = Some(permit.clone());
        self
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

    /// Binds each ASSET_TEXT this batch births to every source it was
    /// written from; a text put that births no row here copies nothing.
    pub(crate) fn with_text_births(mut self, births: HashMap<EntityId, Vec<EntityId>>) -> Self {
        self.text_births = births;
        self
    }

    /// Binds each ASSET put whose body is a manifest to the body file it
    /// names (FIX 3677).
    pub(super) fn with_asset_files(
        mut self,
        files: HashMap<EntityId, crate::store::AssetBodyFacts>,
    ) -> Self {
        self.asset_files = files;
        self
    }

    /// Hands the door the bytes of each interpreted body file this batch
    /// puts (FIX 22075).
    pub(super) fn with_asset_file_bodies(mut self, bodies: HashMap<EntityId, Vec<u8>>) -> Self {
        self.asset_file_bodies = bodies;
        self
    }

    /// Binds each bound raw CLAIM put to its caller's envelope (FIX 8118).
    pub(super) fn with_caller_envelopes(
        mut self,
        envelopes: HashMap<EntityId, crate::WriteEnvelope>,
    ) -> Self {
        self.caller_envelopes = envelopes;
        self
    }

    pub(super) fn with_prepared_agent_birth(
        mut self,
        birth: Option<crate::agent_def::PreparedAgentDefinitionBirth>,
    ) -> Self {
        self.prepared_agent_birth = birth;
        self
    }

    pub(super) fn with_prepared_person_substrate(
        mut self,
        substrate: Option<super::PreparedPersonSubstrate>,
    ) -> Self {
        self.prepared_person_substrate = substrate;
        self
    }

    /// Binds each marked carrier's ASSET put to its bytes (FIX 9034).
    pub(super) fn with_marked_carriers(
        mut self,
        carriers: std::collections::BTreeMap<EntityId, [u8; 32]>,
    ) -> Self {
        self.marked_carriers = carriers;
        self
    }

    /// Marks the rows the replication applier put (FIX 7925).
    pub(super) fn with_replicated_puts(
        mut self,
        ids: std::collections::BTreeSet<EntityId>,
    ) -> Self {
        self.replicated_puts = ids;
        self
    }

    /// Stamps each row's Rule A birth envelope once the batch's ops apply.
    pub(crate) fn with_births(
        mut self,
        births: Vec<(EntityId, crate::store::row_birth::RowBirth)>,
    ) -> Self {
        self.births = births;
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

    pub(super) fn with_pending_auto_probes(
        mut self,
        probes: HashMap<crate::store::GateDecisionId, PendingAutoProbe>,
    ) -> Self {
        self.pending_auto_probes = probes;
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
