//! Native record behavior supplied by the engine when a store opens:
//! identity, federation, room, voice, secret custody and campaign/query lifecycle.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_record::SecretCustodyRecord;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// The engine's record hooks. A store holds one implementation from the
/// moment it is assembled (see [`crate::store::StoreHooks`]). Store and Memory
/// callers keep their admission and ordering, while these hooks run the native
/// behavior with the original arguments.
pub trait StoreRecordHooks: Send + Sync {
    /// The engine's `campaign::surface::create_campaign`.
    fn create_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::CreateCampaignRequest,
        now: u64,
    ) -> Result<crate::memory::campaign_records::CampaignRecord>;

    /// The engine's `campaign::surface::launch_campaign`.
    fn launch_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        actor_class: crate::edge::EdgeActorClass,
        campaign_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> Result<crate::memory::campaign_records::CampaignRecord>;

    /// The engine's `campaign::surface::read_campaign`.
    fn read_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        campaign_ref: EntityId,
    ) -> Result<Option<crate::memory::campaign_records::CampaignRecord>>;

    /// The engine's `campaign::surface::update_campaign`.
    fn update_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        campaign_ref: EntityId,
        request: &crate::memory::campaign_records::UpdateCampaignRequest,
        now: u64,
    ) -> Result<crate::memory::campaign_records::CampaignRecord>;

    /// The engine's `campaign::surface::archive_campaign`.
    fn archive_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        campaign_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> Result<crate::memory::campaign_records::CampaignRecord>;

    /// The engine's `saved_query::create_saved_query`.
    fn create_saved_query(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        owner_actor_class: crate::edge::EdgeActorClass,
        request: &crate::memory::query_records::CreateSavedQueryRequest,
        now: u64,
    ) -> Result<crate::memory::query_records::SavedQueryRecord>;

    /// The engine's `saved_query::read_saved_query`.
    fn read_saved_query(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        query_ref: EntityId,
    ) -> Result<Option<crate::memory::query_records::SavedQueryRecord>>;

    /// The engine's `saved_query::update_saved_query`.
    fn update_saved_query(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        query_ref: EntityId,
        request: &crate::memory::query_records::UpdateSavedQueryRequest,
        now: u64,
    ) -> Result<crate::memory::query_records::SavedQueryRecord>;

    /// The engine's `saved_query::archive_saved_query`.
    fn archive_saved_query(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        query_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> Result<crate::memory::query_records::SavedQueryRecord>;

    /// The engine's `campaign::surface::read_campaign_members`.
    fn read_campaign_members(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        req: &crate::memory::campaign_records::MembershipReadRequest,
    ) -> Result<crate::memory::campaign_records::MembershipPage>;

    /// The engine's `campaign::surface::read_saved_query_members`.
    fn read_saved_query_members(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        req: &crate::memory::campaign_records::MembershipReadRequest,
    ) -> Result<crate::memory::campaign_records::MembershipPage>;

    /// The native program create and its record projection/step-body filing.
    /// Evaluates `filer` once after creation, before the filing clock is read.
    fn create_campaign_program(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::program::CreateCampaignProgramRequest,
        filer: &dyn Fn() -> WriteActor,
    ) -> Result<crate::memory::campaign_records::program::CampaignProgramRecord>;

    /// The native program read and its record projection.
    fn read_campaign_program(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::program::CampaignProgramReadRequest,
    ) -> Result<crate::memory::campaign_records::program::CampaignProgramReadResult>;

    /// The native program update and its record projection/step-body filing.
    /// Evaluates `filer` once before filing, which precedes the program write.
    fn update_campaign_program(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::program::UpdateCampaignProgramRequest,
        filer: &dyn Fn() -> WriteActor,
    ) -> Result<crate::memory::campaign_records::program::CampaignProgramRecord>;

    /// The native program archive and its record projection.
    fn archive_campaign_program(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::program::ArchiveCampaignProgramRequest,
    ) -> Result<crate::memory::campaign_records::program::CampaignProgramRecord>;

    /// The engine's `comm::resolve_party_ref_from_store_in_txn`.
    fn resolve_party_ref_from_store_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        party: &str,
    ) -> crate::write_envelope::communication::CommResult<Option<EntityId>>;

    /// The engine's `comm::comm_party_keys_in_txn`.
    fn comm_party_keys_in_txn(&self, store: &Store, rtxn: &RoTxn<'_>) -> Result<BTreeSet<String>>;

    /// The engine's `comm::person_party_key_in_txn`.
    fn person_party_key_in_txn(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<String>>;

    /// The engine's `comm::resolve_party_ref_in_txn`.
    fn resolve_party_ref_in_txn(
        &self,
        vault: &crate::Vault,
        rtxn: &RoTxn<'_>,
        party: &str,
    ) -> crate::write_envelope::communication::CommResult<Option<EntityId>>;

    /// The engine's `comm::count_active_party_claims_in_txn`.
    fn count_active_party_claims_in_txn(
        &self,
        vault: &crate::Vault,
        rtxn: &RoTxn<'_>,
        party_ref: EntityId,
        predicate: &str,
        channel_class: &str,
    ) -> crate::write_envelope::communication::CommResult<usize>;

    /// The engine's `identity_topology::redact_actor_in_txn`.
    fn redact_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: EntityId,
        now: u64,
    ) -> Result<Vec<EntityId>>;

    /// The engine's `identity_topology::redact_author_attribution_in_txn`.
    fn redact_author_attribution_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        target: EntityId,
        now: u64,
    ) -> Result<Vec<EntityId>>;

    /// The engine's `campaign::enrollment::drive_enrollment_outbound_leg`.
    fn drive_enrollment_outbound_leg(
        &self,
        vault: &crate::Vault,
        local_node_id: u64,
        attempt: &crate::attempt_queue::AttemptRecord,
        sender: &mut (dyn crate::outbound_consent::OutboundResultSender + '_),
        now_ms: u64,
    ) -> std::result::Result<
        crate::campaign::enrollment::EnrollmentLegDrive,
        crate::outbound_intent_ledger::IntentLedgerError,
    >;

    /// The engine's `comm::record_comm_send_receipt`.
    fn record_comm_send_receipt(
        &self,
        vault: &crate::Vault,
        party: &str,
        channel_class: &str,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()>;

    /// The engine's `comm::record_comm_actor_send_receipt_in_txn`.
    fn record_comm_actor_send_receipt_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: EntityId,
        display_name: &str,
        channel_class: &str,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()>;

    /// The engine's `comm::record_comm_thread_event`.
    fn record_comm_thread_event(
        &self,
        vault: &crate::Vault,
        thread_ref: &str,
        party: &str,
        joined: bool,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()>;

    /// The engine's soft `comm::run_comm_projector_housekeeping_step`.
    fn run_comm_projector_housekeeping_step(&self, vault: &crate::Vault);

    /// The engine's `identity_topology::validate_identity_topology_event_body_bytes`.
    fn validate_identity_topology_event_body_bytes(&self, data: &[u8]) -> Result<()>;

    /// The engine's `comm::record_comm_thread_event_in_txn`.
    fn record_comm_thread_event_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &mut RwTxn<'_>,
        thread_ref: &str,
        party: &str,
        joined: bool,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()>;

    /// The engine's `comm::record_comm_inbound_reply_in_txn`.
    fn record_comm_inbound_reply_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        party: &str,
        channel_class: &str,
        occurred_at: u64,
    ) -> Result<()>;

    /// The engine's `comm::record_comm_inbound_stop_in_txn`.
    fn record_comm_inbound_stop_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        party: &str,
        channel_class: &str,
        occurred_at: u64,
    ) -> Result<()>;

    /// The engine's `identity_topology::forget_claim_reassignments_in_txn`.
    fn forget_claim_reassignments_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        claim: &EntityId,
    ) -> Result<()>;

    /// The engine's `identity_topology::identity_topology_shell_sources_for_store_in_txn`.
    fn identity_topology_shell_sources_for_store_in_txn(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<BTreeSet<EntityId>>>;

    /// The engine's `comm::send_override_for_send_in_txn`.
    fn send_override_for_send_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        party_ref: &EntityId,
        channel_class: &str,
        send_ref: Option<&str>,
        now: u64,
    ) -> crate::write_envelope::communication::CommResult<
        Option<crate::write_envelope::communication::SendOverrideMatch>,
    >;

    /// The engine's `comm::send_stop_reason_in_txn`.
    fn send_stop_reason_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        persons: &[EntityId],
        counterparty: &str,
        channel_class: &str,
    ) -> crate::write_envelope::communication::CommResult<Option<&'static str>>;

    /// The engine's `comm::active_thread_refs_in_txn`.
    fn active_thread_refs_in_txn(
        &self,
        vault: &crate::Vault,
        rtxn: &RoTxn<'_>,
        party_ref: EntityId,
    ) -> crate::write_envelope::communication::CommResult<BTreeSet<String>>;

    /// The engine's `comm::check_claim_against_descriptor_in_txn`.
    fn check_claim_against_descriptor_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        body: &crate::claim::ClaimBody,
    ) -> Result<()>;

    /// The engine's `comm::seed_claim_class_descriptors`.
    fn seed_claim_class_descriptors(&self, vault: &crate::Vault) -> Result<()>;

    /// The engine's `comm::supersede_party_opt_out_head_in_txn`.
    fn supersede_party_opt_out_head_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        party: &str,
        reason: crate::counterparty_contact::CounterpartyOptOutReason,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()>;

    /// The engine's `federation::actor_for_txn`.
    fn actor_for_txn(&self, vault: &crate::Vault, txn: &RoTxn<'_>) -> Result<Option<WriteActor>>;

    /// The engine's `federation::courtesy_scope::split_recipient_copies_in_txn`.
    fn split_recipient_copies_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        pact_id: &[u8; 32],
        worlds: &[EntityId],
        epoch_cutoff: u64,
        records: &[EntityId],
    ) -> Result<(Vec<EntityId>, Vec<EntityId>)>;

    /// The engine's `Vault::campaign_step_body_text`.
    fn campaign_step_body_text(
        &self,
        vault: &crate::Vault,
        content_ref: &str,
    ) -> Result<Option<String>>;

    /// The engine's `Memory::compliance_install_as`.
    fn compliance_install_as(
        &self,
        memory: &crate::memory::Memory<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        input: &crate::campaign::compliance::ComplianceAmendRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt>;

    /// The engine's `Memory::compliance_amend`.
    fn compliance_amend(
        &self,
        memory: &crate::memory::Memory<'_>,
        input: &crate::campaign::compliance::ComplianceAmendRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt>;

    /// The engine's `Memory::compliance_approve_as`.
    fn compliance_approve_as(
        &self,
        memory: &crate::memory::Memory<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        input: &crate::campaign::compliance::ComplianceApprovalRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt>;

    /// The engine's `Memory::compliance_reject_as`.
    fn compliance_reject_as(
        &self,
        memory: &crate::memory::Memory<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        input: &crate::campaign::compliance::ComplianceApprovalRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt>;

    /// The engine's `Memory::compliance_verify_as`.
    fn compliance_verify_as(
        &self,
        memory: &crate::memory::Memory<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        input: &crate::campaign::compliance::ComplianceVerifyRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt>;

    /// The engine's `Memory::compliance_result`.
    fn compliance_result(
        &self,
        memory: &crate::memory::Memory<'_>,
        input: &crate::campaign::compliance::ComplianceResultRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceResult>;

    /// The engine's `federation::validate_federation_grant_body_bytes`.
    fn validate_federation_grant_body_bytes(&self, bytes: &[u8]) -> Result<()>;

    /// The engine's `counterparty_contact::fold_party_opt_out_heads_for_store_in_txn`.
    fn fold_party_opt_out_heads_in_txn(
        &self,
        vault: &crate::Vault,
        rtxn: &RoTxn<'_>,
        record: &mut crate::counterparty_contact::CounterpartyContactRecord,
    ) -> Result<()>;

    /// The engine's `federation::guard_ruling_overwrite`.
    #[allow(clippy::too_many_arguments)]
    fn guard_ruling_overwrite(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
        kind: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<()>;

    /// The engine's `federation::note_authority_row`.
    fn note_authority_row(&self);

    /// The engine's `federation::witness_grant_rulings_in_txn`.
    fn witness_grant_rulings_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        grant: &EntityId,
        row: &[u8],
    ) -> Result<()>;

    /// The engine's `skill_attribution::note_direct_derivation_in_txn`.
    fn note_direct_derivation_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        derived: EntityId,
        source: EntityId,
    );

    /// The engine's `memory::erase_stream_seeds_in_txn`, an entity side-row eraser.
    fn erase_stream_seeds_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `memory::erase_reply_assertions_in_txn`, an entity side-row eraser.
    fn erase_reply_assertions_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `memory::erase_turn_wake_label_in_txn`, an entity side-row eraser.
    fn erase_turn_wake_label_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `memory::release_asset_blob_in_txn`, an entity side-row eraser.
    fn release_asset_blob_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        deindex: &dyn Fn(
            &mut heed::RwTxn<'_>,
            &EntityId,
        ) -> crate::error::Result<(bool, bool, bool, Vec<EntityId>)>,
    ) -> Result<()>;

    /// The engine's `workspace_roster::reject_audience_edit_unlink`.
    fn reject_audience_edit_unlink(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::record_thread_admits_in`.
    fn record_thread_admits_in(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        id: EntityId,
        actor: EntityId,
    ) -> Result<bool>;

    /// The engine's `comm::erase_skipped_send_receipt_in_txn`.
    fn erase_skipped_send_receipt_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `counterparty_contact::erase_trusted_contact_rows_in_txn`.
    fn erase_trusted_contact_rows_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `calendar::inbox_card::erase_inbox_cards_in_txn`.
    fn erase_inbox_cards_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_room_side_rows`, an entity
    /// side-row eraser of `deletion::derived_rows`.
    fn erase_room_side_rows(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        deindex: &dyn Fn(
            &mut heed::RwTxn<'_>,
            &EntityId,
        ) -> Result<(bool, bool, bool, Vec<EntityId>)>,
    ) -> Result<()>;

    /// The engine's `voice_identity::erase_recognition_for_subject_in_txn`,
    /// an entity side-row eraser of `deletion::derived_rows`.
    fn erase_recognition_for_subject_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::erase_audience_actor_in_txn`.
    fn erase_audience_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `campaign::claims::do_not_contact_subjects_in_txn`.
    fn do_not_contact_subjects_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        counterparty: &str,
    ) -> Result<Vec<EntityId>>;

    /// The engine's `campaign::claims::subjects_do_not_contact_in_txn`.
    fn subjects_do_not_contact_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        subjects: &[EntityId],
        channel: Option<&str>,
        scope: &str,
    ) -> Result<bool>;

    /// The engine's `campaign::send_hygiene::apply_suppression_in_txn`.
    fn apply_suppression_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        cause: crate::write_envelope::cohort_claims::suppression::SuppressionCause,
        input: &crate::write_envelope::cohort_claims::suppression::SuppressionInput,
    ) -> Result<crate::write_envelope::cohort_claims::suppression::SuppressionReceipt>;

    /// The engine's `comm::is_restrictive_comm_predicate`.
    fn is_restrictive_comm_predicate(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        predicate: &str,
    ) -> Result<bool>;

    /// The engine's `secret_custody::read_secret_custody_meta_in_txn`.
    fn read_secret_custody_meta_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<SecretCustodyRecord>>;

    /// The engine's `affect::state_inputs::spoke_in`.
    fn spoke_in(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        subject: &EntityId,
        turn: &EntityId,
    ) -> Result<bool>;

    /// The engine's `saved_query::repair_saved_queries_after_pack_move_in_txn`.
    /// The install door drops the per-query resolutions, so this reports only
    /// success.
    #[allow(clippy::too_many_arguments)]
    fn repair_saved_queries_after_pack_move_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        pack: &str,
        from_version: &str,
        to_version: &str,
        from_source: &str,
        to_source: &str,
        from_predicates: &BTreeSet<String>,
        to_predicates: &BTreeSet<String>,
        shipped: Option<crate::store::pack_predicate_rewrites::PackMigrationMap>,
        now: u64,
    ) -> Result<()>;

    /// The engine's `affect::processed_subjects`, using the caller's read lane.
    fn processed_subjects(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        subjects: &[EntityId],
    ) -> Result<BTreeSet<EntityId>>;
}
