use super::*;

impl StoreRecordHooks for EngineRecordHooks {
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
    ) -> Result<()> {
        crate::memory::release_asset_blob_in_txn(store, wtxn, id)
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

    fn processed_subjects(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        subjects: &[EntityId],
    ) -> Result<BTreeSet<EntityId>> {
        crate::affect::processed_subjects(read, subjects)
    }
}
