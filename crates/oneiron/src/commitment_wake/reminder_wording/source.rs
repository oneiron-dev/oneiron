//! The exact native reminder source each model destination may receive.

use super::*;
use crate::claim::{ScopedReadActorKey, ScopedReadReceipt, decode_claim_body};
use crate::commitment::decode_commitment_claim;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::settings::{ReadDestination, ReleaseHold};

/// A reminder's source at the revision its destination was admitted to.
#[derive(Debug, Clone)]
pub struct CommitmentReminderWordingSource {
    pub request: CommitmentReminderWordingRequest,
    pub head: EntityId,
    /// The stored source body's revision, not a permission or a model result.
    pub revision: [u8; 32],
    pub receipt: ScopedReadReceipt,
}

/// Absence of a current reminder is distinct from a destination withholding it.
#[derive(Debug, Clone)]
pub enum CommitmentReminderWordingRead {
    Missing,
    Held(ReleaseHold),
    Ready(CommitmentReminderWordingSource),
}

impl Vault {
    /// Reads this native worker's current reminder for one actual model
    /// destination. The selected head, admitted words, receipt, route and
    /// model-world verdict all use one snapshot. The existing raw request
    /// and fixed-send paths do not use this new read.
    ///
    /// # Errors
    ///
    /// The existing principal, claim, scoped-read or world-policy read failed.
    pub fn commitment_reminder_wording_source_for(
        &self,
        payload: &CommitmentReminderWordingPayload,
        destination: &ReadDestination,
    ) -> Result<CommitmentReminderWordingRead> {
        use CommitmentReminderWordingRead::{Held, Missing, Ready};
        let Some(reminder) = ReminderRef::parse(&payload.content_ref) else {
            return Ok(Missing);
        };
        let actor = self.dreamer_authority()?.entity_ref();
        let key = ScopedReadActorKey::with_actor_class(actor.to_hex(), "system")
            .ok_or(Error::InvalidConfig(
                "invalid reminder worker read key".into(),
            ))?
            .require_relationship_grants(Some(actor))
            .for_destination(destination);
        let reader = self.scoped_read(key);
        reader.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        let head = self.commitment_head_in_txn(&txn, &reminder.instance_id)?;
        let Some(current_body) = self.get_claim_in_txn(&txn, &head)? else {
            return Ok(Missing);
        };
        let current = decode_commitment_claim(&current_body)?.ok_or(Error::InvalidClaimBody(
            "claim predicate is not commitment.record",
        ))?;
        if current.status != CommitmentStatus::Open {
            return Ok(Missing);
        }
        // This is the admitted body's read, not permission inferred from
        // the principal's write authority or the timer that queued it.
        let row = reader
            .get_entities_parts_in_txn(&txn, std::slice::from_ref(&head))?
            .pop()
            .flatten();
        let Some((kind, _, bytes)) = row else {
            let world = Some(
                current_body
                    .world
                    .unwrap_or_else(crate::claim::base_world_id),
            );
            let hold = self
                .model_call_hold_in_txn(&txn, world, destination)?
                .unwrap_or(ReleaseHold::Placement);
            return Ok(Held(hold));
        };
        if kind != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("reminder source is not a claim"));
        }
        let body = decode_claim_body(&bytes, true)?;
        let world = Some(body.world.unwrap_or_else(crate::claim::base_world_id));
        if let Some(hold) = self.model_call_hold_in_txn(&txn, world, destination)? {
            return Ok(Held(hold));
        }
        let record = decode_commitment_claim(&body)?.ok_or(Error::InvalidClaimBody(
            "claim predicate is not commitment.record",
        ))?;
        if record.status != CommitmentStatus::Open {
            return Ok(Missing);
        }
        let offset = self
            .commitment_reminder_route_in_txn(&txn)?
            .and_then(|route| route.utc_offset_minutes_at(reminder.due_at));
        let source = self
            .store
            .port_entity_record(&txn, &head)?
            .ok_or(Error::EntityNotFound)?;
        let revision = *blake3::hash(&source.body).as_bytes();
        let receipt = reader.read_receipt_in(&txn, None, 0)?;
        Ok(Ready(CommitmentReminderWordingSource {
            request: CommitmentReminderWordingRequest {
                content_ref: payload.content_ref.clone(),
                reader: record.obligor.kind,
                phase: reminder.phase,
                promise: quoted_promise(&record),
                due: civil_time(reminder.due_at, offset),
                fixed_text: reminder_text(&record, &reminder, offset),
                persona_ref: payload.voice.persona_ref.clone(),
            },
            head,
            revision,
            receipt,
        }))
    }
}
