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
}
