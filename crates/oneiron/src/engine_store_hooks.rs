//! The engine's implementation of the store layer's hooks: each method
//! forwards to the engine function of the same name.

use heed::{RoTxn, RwTxn};
use oneiron_authority::federation::Sensitivity;

use crate::entity_id::EntityId;
use crate::error::Result;
use std::collections::{BTreeSet, HashSet};

use crate::analyzer::MultilingualAnalyzer;
use crate::batch::row_put::RowPut;
use crate::config::{HostingPrivacyPosture, VaultConfig};
#[cfg(feature = "sync")]
use crate::deletion::delete_bearing_update::DeleteBearingUpdate;
use crate::edge::EdgeKind;
#[cfg(feature = "sync")]
use crate::store::StoreSyncHooks;
#[cfg(feature = "sync")]
use crate::store::window_rows::CarrierRemoval;
use crate::store::{
    GateDecisionId, GateDecisionRetentionPolicy, Store, StoreActorScrubs, StoreDeleteGuards,
    StoreGateHooks, StoreHooks, StoreProjectWrites, StoreRecordHooks, StoreScopeStamps,
};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::write_envelope::claim_body::ClaimBody;
#[cfg(feature = "sync")]
use loro::LoroDoc;

/// The hooks every vault's store opens with.
pub(crate) const ENGINE_STORE_HOOKS: StoreHooks = StoreHooks {
    delete_guards: &EngineDeleteGuards,
    scope_stamps: &EngineScopeStamps,
    project_writes: &EngineProjectWrites,
    record_hooks: &EngineRecordHooks,
    actor_scrubs: &EngineActorScrubs,
    gate_hooks: &EngineGateHooks,
    #[cfg(feature = "sync")]
    sync_hooks: &EngineSyncHooks,
};

/// The engine's delete guards.
pub(crate) struct EngineDeleteGuards;

/// The engine's record-scope stamp hooks.
pub(crate) struct EngineScopeStamps;

/// The engine's project write hooks.
pub(crate) struct EngineProjectWrites;

/// The engine's record hooks.
pub(crate) struct EngineRecordHooks;

/// The engine's actor scrubs for store-declared side tables.
pub(crate) struct EngineActorScrubs;

/// The engine's gate hooks.
pub(crate) struct EngineGateHooks;

/// The engine's sync hooks.
#[cfg(feature = "sync")]
pub(crate) struct EngineSyncHooks;

impl StoreDeleteGuards for EngineDeleteGuards {
    fn reject_audience_edit_delete(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::reject_audience_edit_delete(store, txn, id)
    }

    fn reject_ruling_delete(&self, store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<()> {
        crate::federation::reject_ruling_delete(store, txn, id)
    }

    fn refuse_revision_delete(&self, store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<()> {
        crate::workspace_roster::refuse_revision_delete(store, txn, id)
    }

    fn precheck_goal_delete(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        gated: bool,
    ) -> Result<()> {
        crate::workspace_roster::precheck_goal_delete(store, txn, id, gated)
    }

    fn guard_goal_delete(&self, store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<()> {
        crate::workspace_roster::guard_goal_delete(store, txn, id)
    }

    fn retire_goal_for_delete(
        &self,
        vault: &crate::Vault,
        txn: &mut RwTxn<'_>,
        id: EntityId,
    ) -> Result<()> {
        crate::workspace_roster::retire_goal_for_delete(vault, txn, id)
    }

    fn guard_batch_identity_delete_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::identity_topology::guard_batch_identity_delete_in_txn(store, txn, id)
    }

    fn deindex_project_room(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool, Vec<EntityId>)> {
        crate::workspace_roster::deindex_project_room(store, txn, id)
    }
}

impl StoreScopeStamps for EngineScopeStamps {
    fn retire_stamp(&self, store: &Store, txn: &mut RwTxn<'_>, id: EntityId) -> Result<()> {
        crate::federation::record_scope::retire_stamp(store, txn, id)
    }

    fn stamp_put(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        kind: u8,
        data: &[u8],
        put: RowPut,
    ) -> Result<()> {
        crate::federation::record_scope::stamp_put(store, txn, id, kind, data, put)
    }

    fn restamp_document_pointer(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        kind: u8,
        original: &[u8],
        pointer: &[u8],
    ) -> Result<()> {
        crate::federation::record_scope::restamp_document_pointer(
            store, txn, id, kind, original, pointer,
        )
    }

    fn stamp_blob_project(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        project: EntityId,
    ) -> Result<()> {
        crate::federation::record_scope::stamp_blob_project(store, txn, id, project)
    }

    fn restrict_stamp_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        band: Sensitivity,
    ) -> Result<()> {
        crate::federation::record_scope::restrict_stamp_in_txn(store, txn, id, band)
    }

    fn settle_epoch_birth(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        world: EntityId,
        facet: EntityId,
    ) -> Result<()> {
        crate::federation::record_scope::settle_epoch_birth(store, txn, id, world, facet)
    }

    fn backfill_task_base(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        data: &[u8],
    ) -> Result<()> {
        crate::federation::record_scope::backfill_task_base(store, txn, id, data)
    }

    fn has_stored_position(&self, store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<bool> {
        crate::federation::record_scope::has_stored_position(store, txn, id)
    }
}

impl StoreProjectWrites for EngineProjectWrites {
    fn refresh_project_frontiers(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        posture: HostingPrivacyPosture,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()> {
        crate::workspace_roster::refresh_project_frontiers(store, txn, posture, touched)
    }

    fn reconcile_project_rooms(
        &self,
        store: &Store,
        config: &VaultConfig,
        analyzer: &MultilingualAnalyzer,
        trusted: bool,
        txn: &mut RwTxn<'_>,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()> {
        crate::workspace_roster::reconcile_project_rooms(
            store, config, analyzer, trusted, txn, touched,
        )
    }

    fn validate_local_leader_chat_turns(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        turns: &BTreeSet<EntityId>,
    ) -> Result<()> {
        crate::workspace_roster::validate_local_leader_chat_turns(store, txn, turns)
    }

    fn capture_project_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        kind: u8,
        data: &[u8],
    ) -> Result<Vec<(EntityId, Vec<u8>)>> {
        crate::workspace_roster::capture_project_put(store, txn, id, kind, data)
    }

    fn guard_goal_claim_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        incoming: Option<&ClaimBody>,
        bytes: &[u8],
        replicated: bool,
    ) -> Result<()> {
        crate::workspace_roster::guard_goal_claim_put(store, txn, id, incoming, bytes, replicated)
    }

    fn guard_goal_pointer_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        bytes: &[u8],
        replicated: bool,
    ) -> Result<()> {
        crate::workspace_roster::guard_goal_pointer_put(store, txn, id, bytes, replicated)
    }

    fn normalize_project_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        bytes: &[u8],
        posture: HostingPrivacyPosture,
    ) -> Result<Vec<u8>> {
        crate::workspace_roster::normalize_project_body(store, txn, id, bytes, posture)
    }

    fn validate_project_body(&self, id: EntityId, bytes: &[u8]) -> Result<Vec<EntityId>> {
        crate::workspace_roster::validate_project_body(id, bytes)
    }

    fn validate_project_transition(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        kind: u8,
        bytes: &[u8],
        posture: HostingPrivacyPosture,
    ) -> Result<()> {
        crate::workspace_roster::validate_project_transition(store, txn, id, kind, bytes, posture)
    }

    fn note_project_proof(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        kind: u8,
        data: &[u8],
    ) -> Result<()> {
        crate::workspace_roster::note_project_proof(store, txn, id, kind, data)
    }

    fn validate_room_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        data: &[u8],
    ) -> Result<()> {
        crate::workspace_roster::validate_room_body(store, txn, id, data)
    }

    fn root_project_in(&self, store: &Store, txn: &RoTxn<'_>) -> Result<Option<EntityId>> {
        crate::workspace_roster::root_project_in(store, txn)
    }

    fn seed_root_project(&self, vault: &crate::Vault) -> Result<()> {
        crate::workspace_roster::seed_root_project(vault)
    }

    fn project_mint_gate_refs_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
    ) -> Result<HashSet<GateDecisionId>> {
        crate::workspace_roster::project_mint_gate_refs_in_txn(vault, txn)
    }
}

impl StoreRecordHooks for EngineRecordHooks {
    fn redact_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: EntityId,
        now: u64,
    ) -> Result<Vec<EntityId>> {
        crate::identity_topology::redact_actor_in_txn(vault, wtxn, actor, now)
    }

    fn redact_author_attribution_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        target: EntityId,
        now: u64,
    ) -> Result<Vec<EntityId>> {
        crate::identity_topology::redact_author_attribution_in_txn(vault, wtxn, target, now)
    }

    fn validate_identity_topology_event_body_bytes(&self, data: &[u8]) -> Result<()> {
        crate::identity_topology::validate_identity_topology_event_body_bytes(data)
    }

    fn forget_claim_reassignments_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        claim: &EntityId,
    ) -> Result<()> {
        crate::identity_topology::forget_claim_reassignments_in_txn(store, wtxn, claim)
    }

    fn identity_topology_shell_sources_for_store_in_txn(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<BTreeSet<EntityId>>> {
        crate::identity_topology::identity_topology_shell_sources_for_store_in_txn(store, rtxn, id)
    }

    fn actor_for_txn(&self, vault: &crate::Vault, txn: &RoTxn<'_>) -> Result<Option<WriteActor>> {
        crate::federation::actor_for_txn(vault, txn)
    }

    fn split_recipient_copies_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        pact_id: &[u8; 32],
        worlds: &[EntityId],
        epoch_cutoff: u64,
        records: &[EntityId],
    ) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
        crate::federation::courtesy_scope::split_recipient_copies_in_txn(
            vault,
            txn,
            pact_id,
            worlds,
            epoch_cutoff,
            records,
        )
    }

    fn validate_federation_grant_body_bytes(&self, bytes: &[u8]) -> Result<()> {
        crate::federation::validate_federation_grant_body_bytes(bytes)
    }

    fn guard_ruling_overwrite(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
        kind: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<()> {
        crate::federation::guard_ruling_overwrite(store, txn, id, kind, occurred, learned_at, data)
    }

    fn note_authority_row(&self) {
        crate::federation::note_authority_row()
    }

    fn reject_audience_edit_unlink(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::reject_audience_edit_unlink(store, txn, src, kind, tgt)
    }

    fn record_thread_admits_in(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        id: EntityId,
        actor: EntityId,
    ) -> Result<bool> {
        crate::workspace_roster::record_thread_admits_in(vault, txn, id, actor)
    }

    fn erase_room_side_rows(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_room_side_rows(store, txn, id)
    }

    fn erase_audience_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_audience_actor_in_txn(vault, wtxn, actor)
    }
}

#[cfg(feature = "sync")]
impl StoreSyncHooks for EngineSyncHooks {
    fn check_federation_imports_in_txn(&self, vault: &crate::Vault, txn: &RoTxn<'_>) -> Result<()> {
        crate::sync::federation_burst::check_active_in_txn(vault, txn)
    }

    fn push_embed_job_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        entity_id: &EntityId,
        priority: u8,
    ) -> Result<()> {
        crate::sync::queue::push_embed_job_in_txn(store, wtxn, entity_id, priority)
    }

    fn delete_embed_job_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        entity_id: &EntityId,
    ) -> Result<bool> {
        crate::sync::queue::delete_embed_job_in_txn(store, wtxn, entity_id)
    }

    fn queued_window_labels_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
    ) -> Result<BTreeSet<String>> {
        crate::sync::queue::queued_window_labels_in_txn(vault, txn)
    }

    fn queued_window_update_count_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        window_key: &str,
    ) -> Result<usize> {
        crate::sync::queue::queued_window_update_count_in_txn(store, txn, window_key)
    }

    fn scrub_window_updates_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        window_key: &str,
    ) -> Result<u32> {
        crate::sync::queue::scrub_window_updates_in_txn(vault, wtxn, window_key)
    }

    fn indexed_windows_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        prefix: &str,
    ) -> Result<BTreeSet<String>> {
        crate::sync::residence::indexed_windows_in_txn(store, txn, prefix)
    }

    fn birth_carriers_remain_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        actors: &BTreeSet<EntityId>,
    ) -> Result<bool> {
        crate::sync::row_birth::actor_erase::birth_carriers_remain_in_txn(vault, txn, actors)
    }

    fn persist_window_update_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        window_key: &str,
        update_bytes: &[u8],
    ) -> Result<()> {
        crate::sync::bridge::persist_window_update_in_txn(vault, wtxn, window_key, update_bytes)
    }

    fn merge_window_heads(&self, doc: &LoroDoc) -> Result<()> {
        crate::sync::window::merge_window_heads(doc)
    }

    fn erase_carried_born_with_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::sync::selector::erase_carried_born_with_in_txn(store, wtxn, id)
    }

    fn erase_retained_copies_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::sync::federation_burst::erase_retained_copies_in_txn(store, txn, id)
    }

    fn apply_tombstone_to_window_doc(
        &self,
        doc: &LoroDoc,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<()> {
        crate::sync::window::apply_tombstone_to_window_doc(doc, id, raw_value)
    }

    fn mark_removed_carriers_first(
        &self,
        vault: &crate::Vault,
        path: CarrierRemoval,
        carriers: &[(EntityId, Vec<u8>)],
    ) -> Result<()> {
        crate::sync::window::mark_removed_carriers_first(vault, path, carriers)
    }

    fn push_delete_bearing_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        window_key: &str,
        update: &DeleteBearingUpdate,
    ) -> Result<u64> {
        crate::sync::queue::push_delete_bearing_in_txn(vault, wtxn, window_key, update)
    }

    fn compact_document(&self, vault: &crate::Vault, id: EntityId, erased: bool) -> Result<()> {
        crate::sync::documents::compact(vault, id, erased)
    }
}

impl StoreActorScrubs for EngineActorScrubs {
    fn erase_card_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_card_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_pending_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_pending_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_host_pin_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_host_pin_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_join_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_join_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_offer_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_offer_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_turn_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_turn_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_companion_principal_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_companion_principal_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_member_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_member_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_member_intent_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_member_intent_actor_in_txn(vault, wtxn, actor)
    }
}

impl StoreGateHooks for EngineGateHooks {
    fn default_policy_manifest(&self) -> Result<Vec<u8>> {
        crate::gate::default_policy_manifest()
    }

    #[cfg(any(test, feature = "test-support"))]
    fn default_policy_manifest_with_scoped_grants(
        &self,
        rows: Vec<rmpv::Value>,
    ) -> Result<Vec<u8>> {
        crate::gate::default_policy_manifest_with_scoped_grants(rows)
    }

    fn resolve_gate_decision_retention(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
    ) -> Result<Option<GateDecisionRetentionPolicy>> {
        crate::gate::resolve_gate_decision_retention(store, txn)
    }

    fn retention_edit_target(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
    ) -> Result<(GateDecisionRetentionPolicy, EntityId)> {
        crate::gate::retention_edit_target(store, txn)
    }

    fn normalize_policy_manifest_scope(&self, data: &[u8]) -> Option<Vec<u8>> {
        crate::gate::normalize_policy_manifest_scope(data)
    }

    fn show_owner_answer_item_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        written: Option<&ClaimBody>,
    ) -> Result<()> {
        crate::gate::show_owner_answer_item_in_txn(store, wtxn, claim_id, written)
    }

    fn reconcile_critical_write_confirm_on_replicated_overwrite(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        body_changed_or_missing: bool,
    ) -> Result<()> {
        crate::gate::reconcile_critical_write_confirm_on_replicated_overwrite(
            store,
            wtxn,
            claim_id,
            body_changed_or_missing,
        )
    }

    fn attach_replicated_critical_confirm_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        body: &ClaimBody,
    ) -> Result<()> {
        crate::gate::attach_replicated_critical_confirm_in_txn(store, wtxn, claim_id, body)
    }

    fn stamp_manifest_origin(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        body: &[u8],
        replicated: bool,
    ) -> Result<()> {
        crate::gate::manifest_authenticity::stamp_manifest_origin(store, txn, id, body, replicated)
    }

    fn update_manifest_origin(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        kind: u8,
        body: &[u8],
        replicated: bool,
    ) -> Result<()> {
        crate::gate::manifest_authenticity::update_manifest_origin(
            store, txn, id, kind, body, replicated,
        )
    }

    fn validate_contribution_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        body: &[u8],
        replicated: bool,
        posture: HostingPrivacyPosture,
    ) -> Result<()> {
        crate::gate::project_depth::validate_contribution_put(
            store, txn, id, body, replicated, posture,
        )
    }

    fn birth_for_project(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        project: EntityId,
    ) -> Result<
        Option<(
            EntityId,
            oneiron_store::project_depth_record::ProjectDepthBirth,
        )>,
    > {
        crate::gate::project_depth::birth_for_project(store, txn, project)
    }

    fn implicit_birth_applies(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        posture: HostingPrivacyPosture,
        project: EntityId,
    ) -> Result<bool> {
        crate::gate::project_depth::implicit_birth_applies(store, txn, posture, project)
    }

    fn validate_own_device_witness_message_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        machine: EntityId,
        body: &[u8],
    ) -> Result<()> {
        crate::gate::validate_own_device_witness_message_body(store, txn, machine, body)
    }

    fn claim_consolidation_eligible_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
        reader: oneiron_store::consolidation_reader::ConsolidationReader,
    ) -> Result<bool> {
        crate::gate::claim_consolidation_eligible_in_txn(store, txn, id, reader)
    }

    fn scoped_read_grant_reads_world(
        &self,
        grant: &oneiron_store::policy_scoped_grant::PolicyScopedGrant,
        world: Option<EntityId>,
        credential: Option<&oneiron_authority::federation::Scope>,
    ) -> bool {
        crate::gate::scoped_read_grant_reads_world(grant, world, credential)
    }

    fn erase_count_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::gate::proposal_observation::erase_count_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_history_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::gate::proposal_observation::erase_history_actor_in_txn(vault, wtxn, actor)
    }

    fn erase_submission_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::gate::proposal_observation::erase_submission_actor_in_txn(vault, wtxn, actor)
    }
}
