//! The gate hooks the store layer's open, write, erase and read paths run,
//! supplied by the engine when a store opens: the trait the engine
//! implements, and the store-layer scrub each gate side-table declaration
//! names.

use heed::{RoTxn, RwTxn};
use oneiron_store::consolidation_reader::ConsolidationReader;
use oneiron_store::policy_scoped_grant::PolicyScopedGrant;
use oneiron_store::project_depth_record::ProjectDepthBirth;

use crate::config::HostingPrivacyPosture;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GateDecisionRetentionPolicy, Store};
use crate::write_envelope::claim_body::ClaimBody;

/// The engine's gate hooks. A store holds one implementation from the moment
/// it is assembled (see [`crate::store::StoreHooks`]); a store being created
/// gets it from the open door's hooks before it is assembled. The store layer
/// calls each method at the point where it called the engine function of the
/// same name, with the same arguments, and keeps its result.
pub(crate) trait StoreGateHooks: Send + Sync {
    /// The engine's `gate::default_policy_manifest`.
    fn default_policy_manifest(&self) -> Result<Vec<u8>>;

    /// The engine's `gate::default_policy_manifest_with_scoped_grants`.
    #[cfg(any(test, feature = "test-support"))]
    fn default_policy_manifest_with_scoped_grants(&self, rows: Vec<rmpv::Value>)
    -> Result<Vec<u8>>;

    /// The engine's `gate::resolve_gate_decision_retention`.
    fn resolve_gate_decision_retention(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
    ) -> Result<Option<GateDecisionRetentionPolicy>>;

    /// The engine's `gate::retention_edit_target`.
    fn retention_edit_target(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
    ) -> Result<(GateDecisionRetentionPolicy, EntityId)>;

    /// The engine's `gate::normalize_policy_manifest_scope`.
    fn normalize_policy_manifest_scope(&self, data: &[u8]) -> Option<Vec<u8>>;

    /// The engine's `gate::show_owner_answer_item_in_txn`.
    fn show_owner_answer_item_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        written: Option<&ClaimBody>,
    ) -> Result<()>;

    /// The engine's `gate::reconcile_critical_write_confirm_on_replicated_overwrite`.
    fn reconcile_critical_write_confirm_on_replicated_overwrite(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        body_changed_or_missing: bool,
    ) -> Result<()>;

    /// The engine's `gate::attach_replicated_critical_confirm_in_txn`.
    fn attach_replicated_critical_confirm_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        body: &ClaimBody,
    ) -> Result<()>;

    /// The engine's `gate::manifest_authenticity::stamp_manifest_origin`.
    fn stamp_manifest_origin(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        body: &[u8],
        replicated: bool,
    ) -> Result<()>;

    /// The engine's `gate::manifest_authenticity::update_manifest_origin`.
    fn update_manifest_origin(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        kind: u8,
        body: &[u8],
        replicated: bool,
    ) -> Result<()>;

    /// The engine's `gate::project_depth::validate_contribution_put`.
    fn validate_contribution_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        body: &[u8],
        replicated: bool,
        posture: HostingPrivacyPosture,
    ) -> Result<()>;

    /// The engine's `gate::project_depth::birth_for_project`.
    fn birth_for_project(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        project: EntityId,
    ) -> Result<Option<(EntityId, ProjectDepthBirth)>>;

    /// The engine's `gate::project_depth::implicit_birth_applies`.
    fn implicit_birth_applies(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        posture: HostingPrivacyPosture,
        project: EntityId,
    ) -> Result<bool>;

    /// The engine's `gate::validate_own_device_witness_message_body`.
    fn validate_own_device_witness_message_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        machine: EntityId,
        body: &[u8],
    ) -> Result<()>;

    /// The engine's `gate::claim_consolidation_eligible_in_txn`.
    fn claim_consolidation_eligible_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
        reader: ConsolidationReader,
    ) -> Result<bool>;

    /// The engine's `gate::scoped_read_grant_reads_world`.
    fn scoped_read_grant_reads_world(
        &self,
        grant: &PolicyScopedGrant,
        world: Option<EntityId>,
        credential: Option<&oneiron_authority::federation::Scope>,
    ) -> bool;

    /// The engine's `gate::proposal_observation::erase_count_actor_in_txn`
    /// (side table `PROPOSAL_ACTOR_COUNT`).
    fn erase_count_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `gate::proposal_observation::erase_history_actor_in_txn`
    /// (side table `PROPOSAL_RECEIPT_HISTORY`).
    fn erase_history_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `gate::proposal_observation::erase_submission_actor_in_txn`
    /// (side table `PROPOSAL_SUBMISSION`).
    fn erase_submission_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;
}

/// The actor scrub `PROPOSAL_ACTOR_COUNT` declares:
/// the engine's `gate::proposal_observation::erase_count_actor_in_txn`.
pub(crate) fn erase_count_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .gate_hooks
        .erase_count_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `PROPOSAL_RECEIPT_HISTORY` declares:
/// the engine's `gate::proposal_observation::erase_history_actor_in_txn`.
pub(crate) fn erase_history_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .gate_hooks
        .erase_history_actor_in_txn(vault, wtxn, actor)
}

/// The actor scrub `PROPOSAL_SUBMISSION` declares:
/// the engine's `gate::proposal_observation::erase_submission_actor_in_txn`.
pub(crate) fn erase_submission_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    vault
        .store
        .gate_hooks
        .erase_submission_actor_in_txn(vault, wtxn, actor)
}
