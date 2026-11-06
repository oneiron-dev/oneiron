use super::*;

impl StoreRecordHooks for EngineRecordHooks {
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

    fn resolve_party_ref_from_store_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        party: &str,
    ) -> crate::write_envelope::communication::CommResult<Option<EntityId>> {
        crate::comm::resolve_party_ref_from_store_in_txn(store, txn, party)
    }

    fn comm_party_keys_in_txn(&self, store: &Store, rtxn: &RoTxn<'_>) -> Result<BTreeSet<String>> {
        crate::comm::comm_party_keys_in_txn(store, rtxn)
    }

    fn person_party_key_in_txn(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<String>> {
        crate::comm::person_party_key_in_txn(store, rtxn, id)
    }

    fn resolve_party_ref_in_txn(
        &self,
        vault: &crate::Vault,
        rtxn: &RoTxn<'_>,
        party: &str,
    ) -> crate::write_envelope::communication::CommResult<Option<EntityId>> {
        crate::comm::resolve_party_ref_in_txn(vault, rtxn, party)
    }

    fn count_active_party_claims_in_txn(
        &self,
        vault: &crate::Vault,
        rtxn: &RoTxn<'_>,
        party_ref: EntityId,
        predicate: &str,
        channel_class: &str,
    ) -> crate::write_envelope::communication::CommResult<usize> {
        crate::comm::count_active_party_claims_in_txn(
            vault,
            rtxn,
            party_ref,
            predicate,
            channel_class,
        )
    }

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
    > {
        crate::campaign::enrollment::drive_enrollment_outbound_leg(
            vault,
            local_node_id,
            attempt,
            sender,
            now_ms,
        )
    }

    fn record_comm_send_receipt(
        &self,
        vault: &crate::Vault,
        party: &str,
        channel_class: &str,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()> {
        crate::comm::record_comm_send_receipt(vault, party, channel_class, occurred_at)
    }

    fn record_comm_actor_send_receipt_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        actor: EntityId,
        display_name: &str,
        channel_class: &str,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()> {
        crate::comm::record_comm_actor_send_receipt_in_txn(
            vault,
            wtxn,
            actor,
            display_name,
            channel_class,
            occurred_at,
        )
    }

    fn record_comm_thread_event(
        &self,
        vault: &crate::Vault,
        thread_ref: &str,
        party: &str,
        joined: bool,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()> {
        crate::comm::record_comm_thread_event(vault, thread_ref, party, joined, occurred_at)
    }

    fn run_comm_projector_housekeeping_step(&self, vault: &crate::Vault) {
        crate::comm::run_comm_projector_housekeeping_step(vault)
    }

    fn validate_identity_topology_event_body_bytes(&self, data: &[u8]) -> Result<()> {
        crate::identity_topology::validate_identity_topology_event_body_bytes(data)
    }

    fn record_comm_thread_event_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &mut RwTxn<'_>,
        thread_ref: &str,
        party: &str,
        joined: bool,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()> {
        crate::comm::record_comm_thread_event_in_txn(
            vault,
            txn,
            thread_ref,
            party,
            joined,
            occurred_at,
        )
    }

    fn record_comm_inbound_reply_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        party: &str,
        channel_class: &str,
        occurred_at: u64,
    ) -> Result<()> {
        crate::comm::record_comm_inbound_reply_in_txn(
            vault,
            wtxn,
            party,
            channel_class,
            occurred_at,
        )
    }

    fn record_comm_inbound_stop_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        party: &str,
        channel_class: &str,
        occurred_at: u64,
    ) -> Result<()> {
        crate::comm::record_comm_inbound_stop_in_txn(vault, wtxn, party, channel_class, occurred_at)
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
    > {
        crate::comm::send_override_for_send_in_txn(
            store,
            txn,
            party_ref,
            channel_class,
            send_ref,
            now,
        )
    }

    fn send_stop_reason_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        persons: &[EntityId],
        counterparty: &str,
        channel_class: &str,
    ) -> crate::write_envelope::communication::CommResult<Option<&'static str>> {
        crate::comm::send_stop_reason_in_txn(store, txn, persons, counterparty, channel_class)
    }

    fn active_thread_refs_in_txn(
        &self,
        vault: &crate::Vault,
        rtxn: &RoTxn<'_>,
        party_ref: EntityId,
    ) -> crate::write_envelope::communication::CommResult<BTreeSet<String>> {
        crate::comm::active_thread_refs_in_txn(vault, rtxn, party_ref)
    }

    fn check_claim_against_descriptor_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        body: &crate::claim::ClaimBody,
    ) -> Result<()> {
        crate::comm::check_claim_against_descriptor_in_txn(store, txn, body)
    }

    fn seed_claim_class_descriptors(&self, vault: &crate::Vault) -> Result<()> {
        crate::comm::seed_claim_class_descriptors(vault)
    }

    fn supersede_party_opt_out_head_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        party: &str,
        reason: crate::counterparty_contact::CounterpartyOptOutReason,
        occurred_at: u64,
    ) -> crate::write_envelope::communication::CommResult<()> {
        crate::comm::supersede_party_opt_out_head_in_txn(vault, wtxn, party, reason, occurred_at)
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

    fn campaign_step_body_text(
        &self,
        vault: &crate::Vault,
        content_ref: &str,
    ) -> Result<Option<String>> {
        vault.campaign_step_body_text(content_ref)
    }

    fn compliance_install_as(
        &self,
        memory: &crate::memory::Memory<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        input: &crate::campaign::compliance::ComplianceAmendRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt> {
        memory.compliance_install_as(owner, input)
    }

    fn compliance_amend(
        &self,
        memory: &crate::memory::Memory<'_>,
        input: &crate::campaign::compliance::ComplianceAmendRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt> {
        memory.compliance_amend(input)
    }

    fn compliance_approve_as(
        &self,
        memory: &crate::memory::Memory<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        input: &crate::campaign::compliance::ComplianceApprovalRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt> {
        memory.compliance_approve_as(owner, input)
    }

    fn compliance_reject_as(
        &self,
        memory: &crate::memory::Memory<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        input: &crate::campaign::compliance::ComplianceApprovalRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt> {
        memory.compliance_reject_as(owner, input)
    }

    fn compliance_verify_as(
        &self,
        memory: &crate::memory::Memory<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        input: &crate::campaign::compliance::ComplianceVerifyRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceReceipt> {
        memory.compliance_verify_as(owner, input)
    }

    fn compliance_result(
        &self,
        memory: &crate::memory::Memory<'_>,
        input: &crate::campaign::compliance::ComplianceResultRequest,
    ) -> crate::memory::MemoryResult<crate::campaign::compliance::ComplianceResult> {
        memory.compliance_result(input)
    }

    fn validate_federation_grant_body_bytes(&self, bytes: &[u8]) -> Result<()> {
        crate::federation::validate_federation_grant_body_bytes(bytes)
    }

    fn fold_party_opt_out_heads_in_txn(
        &self,
        vault: &crate::Vault,
        rtxn: &RoTxn<'_>,
        record: &mut crate::counterparty_contact::CounterpartyContactRecord,
    ) -> Result<()> {
        crate::counterparty_contact::fold_party_opt_out_heads_for_store_in_txn(vault, rtxn, record)
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

    fn witness_grant_rulings_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        grant: &EntityId,
        row: &[u8],
    ) -> Result<()> {
        crate::federation::witness_grant_rulings_in_txn(store, wtxn, grant, row)
    }

    fn note_direct_derivation_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        derived: EntityId,
        source: EntityId,
    ) {
        crate::skill_attribution::note_direct_derivation_in_txn(store, wtxn, derived, source)
    }

    fn erase_stream_seeds_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::memory::erase_stream_seeds_in_txn(store, wtxn, id)
    }

    fn erase_reply_assertions_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::memory::erase_reply_assertions_in_txn(store, wtxn, id)
    }

    fn erase_turn_wake_label_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::memory::erase_turn_wake_label_in_txn(store, wtxn, id)
    }

    fn release_asset_blob_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        deindex: &dyn Fn(
            &mut heed::RwTxn<'_>,
            &EntityId,
        ) -> crate::error::Result<(bool, bool, bool, Vec<EntityId>)>,
    ) -> Result<()> {
        crate::memory::release_asset_blob_in_txn(store, wtxn, id, deindex)
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

    fn erase_skipped_send_receipt_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::comm::erase_skipped_send_receipt_in_txn(store, wtxn, id)
    }

    fn erase_trusted_contact_rows_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::counterparty_contact::erase_trusted_contact_rows_in_txn(store, wtxn, id)
    }

    fn erase_inbox_cards_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::calendar::inbox_card::erase_inbox_cards_in_txn(store, wtxn, id)
    }

    fn erase_room_side_rows(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        deindex: &dyn Fn(
            &mut heed::RwTxn<'_>,
            &EntityId,
        ) -> Result<(bool, bool, bool, Vec<EntityId>)>,
    ) -> Result<()> {
        crate::workspace_roster::erase_room_side_rows(store, txn, id, deindex)
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

    fn do_not_contact_subjects_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        counterparty: &str,
    ) -> Result<Vec<EntityId>> {
        crate::campaign::claims::do_not_contact_subjects_in_txn(store, txn, counterparty)
    }

    fn subjects_do_not_contact_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        subjects: &[EntityId],
        channel: Option<&str>,
        scope: &str,
    ) -> Result<bool> {
        crate::campaign::claims::subjects_do_not_contact_in_txn(
            store, txn, subjects, channel, scope,
        )
    }

    fn apply_suppression_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        cause: crate::write_envelope::cohort_claims::suppression::SuppressionCause,
        input: &crate::write_envelope::cohort_claims::suppression::SuppressionInput,
    ) -> Result<crate::write_envelope::cohort_claims::suppression::SuppressionReceipt> {
        crate::campaign::send_hygiene::apply_suppression_in_txn(vault, wtxn, cause, input)
    }

    fn is_restrictive_comm_predicate(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        predicate: &str,
    ) -> Result<bool> {
        crate::comm::is_restrictive_comm_predicate(store, txn, predicate)
    }

    fn read_secret_custody_meta_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<crate::secret_record::SecretCustodyRecord>> {
        crate::secret_custody::read_secret_custody_meta_in_txn(store, txn, id)
    }

    fn spoke_in(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        subject: &EntityId,
        turn: &EntityId,
    ) -> Result<bool> {
        crate::affect::state_inputs::spoke_in(vault, txn, subject, turn)
    }

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
    ) -> Result<()> {
        let moved = crate::skill_hub::pack_catalog::predicate_rewrites::PackMove {
            pack,
            from_version,
            to_version,
            from_source,
            to_source,
            from_predicates,
            to_predicates,
            shipped,
        };
        crate::saved_query::repair_saved_queries_after_pack_move_in_txn(vault, wtxn, &moved, now)
            .map(|_| ())
    }

    fn processed_subjects(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        subjects: &[EntityId],
    ) -> Result<BTreeSet<EntityId>> {
        crate::affect::processed_subjects(read, subjects)
    }
}
