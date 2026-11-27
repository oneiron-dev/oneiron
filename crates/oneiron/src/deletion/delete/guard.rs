use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::deletion::LegalHoldActorKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::legal_hold::HoldActor;

use super::super::gate::{
    GatedDeletion, reverify_deletion_authority_before_publication,
    reverify_owner_proof_before_publication,
};
use super::super::rendezvous::{DeleteRendezvous, signal_delete_rendezvous};
use super::super::tombstone::DeleteReason;
use super::DeleteEntityOutcome;
use crate::consent::AuthenticatedOwner;
use crate::error::RegistryError;

/// What the delete guards decided: the headerful leg's header, the
/// headerless leg, or an outcome that ends the delete before any writer
/// opens.
pub(super) enum DeleteGuard {
    Proceed {
        requested_at: u64,
        header: EntityMetadataHeader,
    },
    /// The id has no header: the headerless leg deletes its residue.
    Headerless {
        requested_at: u64,
    },
    Done(DeleteEntityOutcome),
}

impl Vault {
    /// Refuses deleting the PERSON that holds the vault's last Active owner
    /// binding (the lead's L9-52-OWNER-SELF-DELETE = B, 14 Nov 2026), on
    /// every delete door: the vault would keep no owner, and no ceremony
    /// brings the deleted person back ("A deleted owner is not brought back").
    /// The kit's recovery (`recover_owner_authority_from_kit`) re-roots the
    /// vault and binds no person, so it brings no deleted owner back either.
    /// Another live PERSON holding an Active `human` binding lets the delete
    /// through (an added Owner gains one with their first owner key,
    /// `enrol_owner_signing_key_as`), as does a row that holds no live owner
    /// binding. No door writes a `human` binding on an unrooted, hosted or
    /// relay vault, so the guard refuses nothing there.
    ///
    /// The guard phase runs this as the early refusal; each linearizing write
    /// transaction re-runs it against its own view, which is the check that
    /// decides (round-1 P1 of #7900).
    pub(crate) fn refuse_last_bound_owner_delete_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        if !matches!(
            crate::vault::live_entity_row_in_txn(&self.store, txn, id)?,
            crate::vault::LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_PERSON,
                ..
            }
        ) {
            return Ok(());
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.vault_id.is_none() || !crate::authority::actor_binding_is_active(&fold, id, "human")
        {
            return Ok(());
        }
        for binding in fold.actor_bindings.values() {
            if binding.status == crate::authority::ActorBindingStatus::Active
                && binding.actor_class == "human"
                && binding.actor_ref != *id
                && crate::authority::actor_binding_is_live_in(
                    &self.store,
                    txn,
                    &fold,
                    &binding.actor_ref,
                    "human",
                )?
            {
                return Ok(());
            }
        }
        Err(Error::Record(
            crate::error::RecordError::LastBoundOwnerDelete,
        ))
    }

    /// Refuses a protected, held or unsafe delete before any tombstone can be
    /// published; a headerless id is handed to the headerless leg instead.
    pub(super) fn delete_guard_phase(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: &Option<GatedDeletion<'_>>,
        allow_replay_test: bool,
        owner: Option<&AuthenticatedOwner>,
    ) -> Result<DeleteGuard> {
        crate::store::base_agent::guard_actor_delete(id)?;
        {
            let rtxn = self.store.env.read_txn()?;
            self.refuse_last_bound_owner_delete_in(&rtxn, id)?;
            // The root project refuses here, before a privacy erase's
            // audience-edit write below can commit anything.
            crate::workspace_roster::reject_root_project_delete(&self.store, &rtxn, id)?;
            // A hard purge refuses a project with a live child; it refuses
            // here, before its publication fences the project's reads.
            if reason.active_store_hard_purge_v1() {
                crate::workspace_roster::reject_project_with_live_children(&self.store, &rtxn, id)?;
            }
            crate::origin::lfs::reject_direct_lfs_chunk_delete(&self.store, &rtxn, id)?;
            self.require_room_delete_gate(&rtxn, id, gate.as_ref(), allow_replay_test)?;
        }
        if reason == DeleteReason::ArchivedByCleanup {
            return Err(Error::InvariantViolation(
                "cleanup archives require the cleanup proposal/decision door",
            ));
        }
        crate::blob_artifact::esign::reject_event_delete(
            &self.store,
            &self.store.env.read_txn()?,
            id,
        )?;
        // A privacy erase keeps a thread audience edit its live root folds,
        // made by no one (FIX 5639); any other delete of it refuses below.
        if reason == DeleteReason::GdprDelete
            && let Some(outcome) = crate::workspace_roster::erase_audience_edit(
                self,
                id,
                gate.as_ref()
                    .map_or(HoldActor::UNATTRIBUTED, GatedDeletion::hold_actor),
                reason,
                |txn| {
                    reverify_deletion_authority_before_publication(gate.as_ref(), txn)?;
                    reverify_owner_proof_before_publication(self, owner, txn)
                },
            )?
        {
            return Ok(DeleteGuard::Done(outcome));
        }
        {
            let txn = self.store.env.read_txn()?;
            self.store
                .delete_guards
                .reject_ruling_delete(&self.store, &txn, id)?;
            crate::store::task_authority_guard::reject_fact_delete(&self.store, &txn, id)?;
            self.store
                .delete_guards
                .reject_audience_edit_delete(&self.store, &txn, id)?;
            self.store.delete_guards.precheck_goal_delete(
                &self.store,
                &txn,
                *id,
                gate.is_some(),
            )?;
            self.store.guard_pack_map_carrier_delete_in_txn(&txn, id)?;
        }
        signal_delete_rendezvous(
            self,
            DeleteRendezvous::AfterProtectedRecordPrecheck,
            id,
            None,
        );
        // Refuse a held record, whoever deletes it (a soft scrub destroys
        // body bytes too), and an unsafe explicit hard purge, before any
        // tombstone can be published. The plain `delete_entity` door now
        // defaults to a soft tombstone; an explicitly requested purge is
        // never downgraded.
        {
            let txn = self.store.env.read_txn()?;
            self.store.reject_restricted_records_in_txn(&txn, &[*id])?;
            // A pad is held by its world's restrictions too (OF-470,
            // FIX 3059).
            crate::world_keys::reject_held_pad_world_in_txn(&self.store, &txn, &[*id])?;
            if reason.active_store_hard_purge_v1() {
                self.guard_active_merge_hard_delete_in_txn(&txn, id)?;
            }
            // A live artifact's lone version claim goes with its version, so cooperative
            // restrictions on the artifact and its bytes refuse it too.
            if let Some((artifact, hash)) =
                crate::blob_artifact::live_version_claim_reference(&self.store, &txn, id)?
            {
                let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&hash)?;
                self.store
                    .reject_restricted_records_in_txn(&txn, &[artifact, asset])?;
            }
        }
        if let Some(outcome) = self.delete_lone_version_claim(id, gate.as_ref())? {
            return Ok(DeleteGuard::Done(outcome));
        }
        let requested_at = self.store.clock.now_recorded_at();
        let Some(header) = self.read_entity_header(id)? else {
            return Ok(DeleteGuard::Headerless { requested_at });
        };
        if crate::batch::delete_door_protected(header.entity_type)
            || crate::store::project_kind::is_project_revision_type(&self.store, header.entity_type)
        {
            return Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
                header.entity_type,
            )));
        }
        if reason == DeleteReason::UserDelete {
            let rtxn = self.store.env.read_txn()?;
            if crate::deletion::topology_delete_reservation_in_txn(&self.store, &rtxn, id)?
                .is_some()
                && crate::ports::EntityStoreRead::port_entity_raw(&self.store, &rtxn, id)?
                    .is_some_and(|raw| raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN)
            {
                // A previous soft scrub already committed its propagation
                // marker and request-bound reservation. A second UserDelete
                // must not mint a conflicting request or withdraw that intent.
                return Ok(DeleteGuard::Done(DeleteEntityOutcome::missing()));
            }
        }
        Ok(DeleteGuard::Proceed {
            requested_at,
            header,
        })
    }

    /// A live artifact's lone `blob.version` claim goes with its version (ARCH-0005a
    /// #erase-refcount-open, ASTRA-R2-002; Engine ruling 13 Nov 17:56). The owner's delete or
    /// erase runs as that version's release, in one write that re-proves the owner's deletion
    /// authority; the delete of an agent, a member or anyone else is refused, and the refusal
    /// names the way out. The in-process door, which carries no gate, is the owner's.
    ///
    /// `None` for any other record, and for a claim whose artifact went before the write: the
    /// ordinary delete runs.
    fn delete_lone_version_claim(
        &self,
        id: &EntityId,
        gate: Option<&GatedDeletion<'_>>,
    ) -> Result<Option<DeleteEntityOutcome>> {
        {
            let txn = self.store.env.read_txn()?;
            if crate::blob_artifact::live_version_claim_reference(&self.store, &txn, id)?.is_none()
            {
                return Ok(None);
            }
        }
        if gate.is_some_and(|gate| gate.hold_actor().kind != LegalHoldActorKind::Owner) {
            return Err(crate::blob_artifact::lone_version_claim_refusal());
        }
        let write = crate::secret_custody::CustodyWrite::of(self);
        let released = self.with_write_txn_grouped(|wtxn| {
            reverify_deletion_authority_before_publication(gate, wtxn)?;
            let Some((artifact, hash)) =
                crate::blob_artifact::live_version_claim_reference(&self.store, wtxn, id)?
            else {
                return Ok(None);
            };
            crate::blob_artifact::release_claimed_version_in_txn(&write, wtxn, id, &artifact, &hash)
                .map(Some)
        })?;
        match released {
            None => Ok(None),
            Some(true) => Ok(Some(DeleteEntityOutcome {
                existed: true,
                receipt_id: None,
                sweep_key: None,
                turn_program_details: Vec::new(),
                version_release: true,
                released_file_digests: Vec::new(),
            })),
            // A cooperative restriction can keep the version after preflight.
            Some(false) => Err(Error::ConcurrentWrite(
                "a cooperative restriction keeps the blob version this claim records",
            )),
        }
    }
}
