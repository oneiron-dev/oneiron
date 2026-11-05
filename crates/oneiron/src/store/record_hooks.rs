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

    /// The engine's `identity_topology::validate_identity_topology_event_body_bytes`.
    fn validate_identity_topology_event_body_bytes(&self, data: &[u8]) -> Result<()>;

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

    /// The engine's `federation::validate_federation_grant_body_bytes`.
    fn validate_federation_grant_body_bytes(&self, bytes: &[u8]) -> Result<()>;

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

    /// The engine's `workspace_roster::erase_room_side_rows`, an entity
    /// side-row eraser of `deletion::derived_rows`.
    fn erase_room_side_rows(&self, store: &Store, txn: &mut RwTxn<'_>, id: &EntityId)
    -> Result<()>;

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
}
