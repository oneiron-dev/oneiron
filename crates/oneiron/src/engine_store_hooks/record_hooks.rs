use super::*;

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

    fn erase_recognition_for_subject_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::voice_identity::erase_recognition_for_subject_in_txn(store, txn, id)
    }

    fn erase_audience_actor_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::erase_audience_actor_in_txn(vault, wtxn, actor)
    }

    fn read_secret_custody_meta_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<crate::secret_record::SecretCustodyRecord>> {
        crate::secret_custody::read_secret_custody_meta_in_txn(store, txn, id)
    }

    fn create_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::CreateCampaignRequest,
        now: u64,
    ) -> Result<crate::memory::campaign_records::CampaignRecord> {
        crate::campaign::surface::create_campaign(vault, authenticated_principal, request, now)
    }

    fn launch_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        actor_class: crate::edge::EdgeActorClass,
        campaign_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> Result<crate::memory::campaign_records::CampaignRecord> {
        crate::campaign::surface::launch_campaign(
            vault,
            authenticated_principal,
            actor_class,
            campaign_ref,
            expected_definition_version,
            now,
        )
    }

    fn read_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        campaign_ref: EntityId,
    ) -> Result<Option<crate::memory::campaign_records::CampaignRecord>> {
        crate::campaign::surface::read_campaign(vault, authenticated_principal, campaign_ref)
    }

    fn update_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        campaign_ref: EntityId,
        request: &crate::memory::campaign_records::UpdateCampaignRequest,
        now: u64,
    ) -> Result<crate::memory::campaign_records::CampaignRecord> {
        crate::campaign::surface::update_campaign(
            vault,
            authenticated_principal,
            campaign_ref,
            request,
            now,
        )
    }

    fn archive_campaign(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        campaign_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> Result<crate::memory::campaign_records::CampaignRecord> {
        crate::campaign::surface::archive_campaign(
            vault,
            authenticated_principal,
            campaign_ref,
            expected_definition_version,
            now,
        )
    }

    fn create_saved_query(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        owner_actor_class: crate::edge::EdgeActorClass,
        request: &crate::memory::query_records::CreateSavedQueryRequest,
        now: u64,
    ) -> Result<crate::memory::query_records::SavedQueryRecord> {
        crate::saved_query::create_saved_query(
            vault,
            authenticated_principal,
            owner_actor_class,
            request,
            now,
        )
    }

    fn read_saved_query(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        query_ref: EntityId,
    ) -> Result<Option<crate::memory::query_records::SavedQueryRecord>> {
        crate::saved_query::read_saved_query(vault, authenticated_principal, query_ref)
    }

    fn update_saved_query(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        query_ref: EntityId,
        request: &crate::memory::query_records::UpdateSavedQueryRequest,
        now: u64,
    ) -> Result<crate::memory::query_records::SavedQueryRecord> {
        crate::saved_query::update_saved_query(
            vault,
            authenticated_principal,
            query_ref,
            request,
            now,
        )
    }

    fn archive_saved_query(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        query_ref: EntityId,
        expected_definition_version: u64,
        now: u64,
    ) -> Result<crate::memory::query_records::SavedQueryRecord> {
        crate::saved_query::archive_saved_query(
            vault,
            authenticated_principal,
            query_ref,
            expected_definition_version,
            now,
        )
    }

    fn read_campaign_members(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        req: &crate::memory::campaign_records::MembershipReadRequest,
    ) -> Result<crate::memory::campaign_records::MembershipPage> {
        crate::campaign::surface::read_campaign_members(read, req)
    }

    fn read_saved_query_members(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        req: &crate::memory::campaign_records::MembershipReadRequest,
    ) -> Result<crate::memory::campaign_records::MembershipPage> {
        crate::campaign::surface::read_saved_query_members(read, req)
    }

    fn create_campaign_program(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::program::CreateCampaignProgramRequest,
        filer: &dyn Fn() -> WriteActor,
    ) -> Result<crate::memory::campaign_records::program::CampaignProgramRecord> {
        let draft = request.draft()?;
        let program = crate::campaign::enrollment::create_campaign_program(
            vault,
            authenticated_principal,
            request.campaign_ref,
            request.schema_version,
            &draft,
            vault.store.clock.now_recorded_at(),
        )?;
        // The program ref above is minted inside the create, so its step
        // bodies file after it. A filer failure is returned, never
        // swallowed: the program row persists, its sends fail closed, and
        // an update re-files.
        let filer = filer();
        let filed_at = vault.store.clock.now_recorded_at();
        for step in &program.steps {
            if let Some(outbound) = step.outbound.as_ref() {
                vault.save_campaign_step_body(
                    program.program.program_ref,
                    step.step_ref,
                    outbound.call_seq,
                    &outbound.payload,
                    filer,
                    filed_at,
                )?;
            }
        }
        Ok(crate::memory::campaign_records::program::campaign_program_record(&program))
    }

    fn read_campaign_program(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::program::CampaignProgramReadRequest,
    ) -> Result<crate::memory::campaign_records::program::CampaignProgramReadResult> {
        let program = crate::campaign::enrollment::read_campaign_program(
            vault,
            authenticated_principal,
            request.campaign_ref,
            request.program_ref,
        )?;
        Ok(
            crate::memory::campaign_records::program::CampaignProgramReadResult {
                found: program.is_some(),
                record: program
                    .as_ref()
                    .map(crate::memory::campaign_records::program::campaign_program_record),
            },
        )
    }

    fn update_campaign_program(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::program::UpdateCampaignProgramRequest,
        filer: &dyn Fn() -> WriteActor,
    ) -> Result<crate::memory::campaign_records::program::CampaignProgramRecord> {
        let draft = request.draft()?;
        let filer = filer();
        let filed_at = vault.store.clock.now_recorded_at();
        for step in &draft.steps {
            if let Some(outbound) = step.outbound.as_ref() {
                vault.save_campaign_step_body(
                    request.program_ref,
                    step.step_ref,
                    outbound.call_seq,
                    &outbound.payload,
                    filer,
                    filed_at,
                )?;
            }
        }
        let program = crate::campaign::enrollment::update_campaign_program(
            vault,
            authenticated_principal,
            request.campaign_ref,
            request.program_ref,
            request.expected_definition_version,
            &draft,
            vault.store.clock.now_recorded_at(),
        )?;
        Ok(crate::memory::campaign_records::program::campaign_program_record(&program))
    }

    fn archive_campaign_program(
        &self,
        vault: &crate::Vault,
        authenticated_principal: EntityId,
        request: &crate::memory::campaign_records::program::ArchiveCampaignProgramRequest,
    ) -> Result<crate::memory::campaign_records::program::CampaignProgramRecord> {
        let program = crate::campaign::enrollment::archive_campaign_program(
            vault,
            authenticated_principal,
            request.campaign_ref,
            request.program_ref,
            request.expected_definition_version,
            vault.store.clock.now_recorded_at(),
        )?;
        Ok(crate::memory::campaign_records::program::campaign_program_record(&program))
    }
}
