use uuid::Uuid;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::GateDecisionRecord;

use super::super::erase::ProvenanceCapture;
use super::super::gate::GatedDeletion;
use super::super::rendezvous::{
    DeleteRendezvous, signal_after_delete_probe, signal_delete_rendezvous,
};
use super::super::tombstone::{DeleteReason, TombstoneValueV2, window_label_from_timestamp};

/// Everything the plan leg minted or captured before the first destructive
/// transaction: the request identity, tombstone, gate decision, erase details,
/// publication window and provenance capture.
pub(super) struct DeletePlan {
    pub(super) request_uuid: Uuid,
    pub(super) tombstone: TombstoneValueV2,
    pub(super) gate_decision: Option<GateDecisionRecord>,
    pub(super) turn_program_details: Vec<String>,
    pub(super) window_label: String,
    pub(super) captured: ProvenanceCapture,
}

impl Vault {
    /// Signs the install, reserves the delete, and mints its tombstone,
    /// gate decision and provenance capture.
    pub(super) fn delete_plan_phase(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: &Option<GatedDeletion<'_>>,
        requested_at: u64,
        header: EntityMetadataHeader,
    ) -> Result<DeletePlan> {
        // ONE-1149 race-test rendezvous: the header is proven `Some` (the
        // lock-free `read_entity_header` read_txn has completed and committed
        // the headerful path) but no write lock is held yet. The deterministic
        // raced-delete harness recv()s here so the eraser commits AFTER this
        // header read, forcing the headerful leg every run. No-op in
        // production.
        // The receipt is signed in the last txn; load the device key before
        // the first, so no tombstone commits on an install that cannot sign.
        self.prepare_install_signing()?;
        signal_after_delete_probe(self);
        signal_delete_rendezvous(self, DeleteRendezvous::BeforeFirstDeletionTxn, id, None);
        self.reserve_user_brief_delete(id, reason, gate.as_ref())?;
        // ONE-1132: ONE deletion request UUID correlates the CRDT tombstone's
        // `request_id` with the REDACTION_AUDIT receipt's `request_id`.
        // ONE-1149: minted only AFTER the header read proves there is
        // something to erase — a delete that finds nothing must never mint a
        // request id (the headerless leg mints after its own scope probe).
        let request_uuid = Uuid::from_bytes(self.store.clock.ulid()?);

        let tombstone = TombstoneValueV2 {
            reason: reason.into(),
            deleted_at: requested_at,
            request_id: *request_uuid.as_bytes(),
        };
        let mut gate_decision = gate.as_ref().map(|gate| {
            gate.context
                .decision_record(*request_uuid.as_bytes(), id, reason, requested_at)
        });
        // FIX 5736: a purge names the turn-program rows it removes whole
        // because they do not decode. FIX 5775: the count rides the returned
        // outcome too, so a delete with no gate decision carries it.
        let turn_program_details = if reason.active_store_hard_purge_v1() {
            crate::dreamer_runner::turn_program_erase_details(self, id)?
        } else {
            Vec::new()
        };
        if reason.active_store_hard_purge_v1()
            && let Some(decision) = gate_decision.as_mut()
        {
            decision
                .system_notices
                .extend(crate::store::GateSystemNoticeRecord::receipt_details(
                    "deletion",
                    turn_program_details.clone(),
                ));
        }
        let mut window_label = window_label_from_timestamp(header.learned_at);
        // Capture the world before soft erasure or hard purge removes the
        // CLAIM or key pad body. The cfg-off pending marker and sync
        // publication must address the same world-month document.
        let pad = header.entity_type == crate::registry::ENTITY_TYPE_WORLD_KEY_PAD;
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM || pad {
            match self.get_raw_unsealed(id)? {
                Some(raw) if raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN => {
                    // A pad that does not decode stays in the base window.
                    let world = if pad {
                        crate::world_keys::pad_body_world(&raw).and_then(Result::ok)
                    } else {
                        self.erase_claim_world(id, &raw, reason)?
                    };
                    if let Some(world) = world {
                        window_label.push('@');
                        window_label.push_str(&world.to_hex());
                    }
                }
                _ => {
                    // A repeated soft delete sees only a shell; a concurrent
                    // purge can remove even that after the header probe.
                    let txn = self.store.env.read_txn()?;
                    window_label = super::super::timeline::deletion_window_label(
                        &self.store,
                        &txn,
                        id,
                        header.learned_at,
                    )?;
                }
            }
        }

        // ARCH-0038 DELETE interplay: an `edge.provenance` Claim's subject
        // EdgeRef and sweep refs are only readable PRE-purge (SoftErase
        // truncates the payload to the 25 B header) — capture them now.
        // `NotApplicable` for every non-Claim / non-provenance entity: zero
        // new behavior on those paths. A hard erase of a classified corrupt
        // CLAIM takes the audited exception (FIX 7800).
        let captured = self.capture_provenance_delete(id, reason.active_store_hard_purge_v1())?;
        Ok(DeletePlan {
            request_uuid,
            tombstone,
            gate_decision,
            turn_program_details,
            window_label,
            captured,
        })
    }
}
