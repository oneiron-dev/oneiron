//! A retire line for a world or a mask lands as a person's delete of it: a
//! user delete under the owner's gate, never an erase. The tombstone keeps a
//! world's keys, pads and sealed copies, so old bundles still restore it;
//! only an erase destroys them, and no seed line asks for one.
//!
//! A retire line for a channel identity releases it through its lifecycle
//! gate. A release the gate holds for the owner's approve-once press waits
//! (FIX 2577), and the owner's next apply asks again as exactly that request.
use super::apply::{LiveByTarget, ShapeItemState};
use super::invalid;
use super::plan::ShapePlanItem;
use crate::channel_identity::{decode_channel_identity_body, resolve_quarantine_floor_in_txn};
use crate::channel_identity_lifecycle::{
    ChannelIdentityLifecycleActor, ChannelIdentityLifecycleGate, ChannelIdentityLifecycleIntent,
    ChannelIdentityLifecycleRequest, ReleaseIntent,
};
use crate::consent::AuthenticatedOwner;
use crate::deletion::{DeleteReason, DeletionGateContext, GatedDeletion};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// What a held release asked with, read back from where its item rests.
struct HeldRelease {
    request_ref: EntityId,
    quarantine_until: u64,
    requested_at: u64,
}

impl HeldRelease {
    /// The request a [`ShapeItemState::Held`] item keeps; none for any
    /// other state, whose release is a request of its own.
    fn of(resting: &ShapeItemState) -> Result<Option<Self>> {
        let ShapeItemState::Held {
            request_ref,
            quarantine_until,
            requested_at,
            ..
        } = resting
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            request_ref: EntityId::from_hex(request_ref)
                .map_err(|_| invalid("a held release names its request by entity id hex"))?,
            quarantine_until: *quarantine_until,
            requested_at: *requested_at,
        }))
    }
}

impl Vault {
    /// Deletes `id` as `owner`. The gate records the policy frontier the
    /// owner acts at, and every destructive writer re-proves the owner
    /// binding against its own view. Returns the delete's receipt, else the
    /// entity it deleted.
    pub(super) fn delete_shape_entity(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
    ) -> Result<String> {
        let actor = owner.revalidate(self)?;
        let context = {
            let txn = self.store.env.read_txn()?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            DeletionGateContext::new(
                actor,
                EdgeActorClass::Human,
                crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
                policy.read_frontier_hash()?,
            )
        };
        let reverify = |txn: &heed::RoTxn<'_>| owner.revalidate_in_txn(self, txn).map(|_| ());
        let outcome = self.delete_entity_with_reason_gated(
            &id,
            DeleteReason::UserDelete,
            GatedDeletion::new(context, &reverify),
        )?;
        Ok(outcome.receipt_id.unwrap_or(id).to_hex())
    }

    /// Retires the channel identity `item` names, as `owner`, after checking
    /// the structure is still as the plan read it. It releases through the
    /// identity's lifecycle gate: outbound closes, and a self-held address
    /// goes into its never-recycle quarantine for the policy's shortest
    /// hold. A release the gate holds for the owner's approve-once press
    /// rests [`ShapeItemState::Held`]; from there (`resting`) it asks again
    /// under the same request ref, with the quarantine bound and the clock it
    /// first asked with, so the gate reads the same request. A door's
    /// refusal is the item's state.
    pub(super) fn retire_shape_channel(
        &self,
        owner: &AuthenticatedOwner,
        item: &ShapePlanItem,
        live: &LiveByTarget,
        resting: &ShapeItemState,
        now: u64,
    ) -> ShapeItemState {
        self.release_shape_channel(owner, item, live, resting, now)
            .unwrap_or_else(|error| ShapeItemState::Refused {
                reason: error.to_string(),
            })
    }

    fn release_shape_channel(
        &self,
        owner: &AuthenticatedOwner,
        item: &ShapePlanItem,
        live: &LiveByTarget,
        resting: &ShapeItemState,
        now: u64,
    ) -> Result<ShapeItemState> {
        let stale = || invalid("the structure changed since the plan read it");
        let id = match live.get(&item.target) {
            None => {
                return Ok(ShapeItemState::Landed {
                    at: now,
                    receipt: "already gone".to_owned(),
                });
            }
            Some((row, entity)) if item.before.as_ref() == Some(row) => entity.ok_or_else(stale)?,
            Some(_) => return Err(stale()),
        };
        let actor = owner.revalidate(self)?;
        let held = HeldRelease::of(resting)?;
        let (quarantine_until, requested_at) = match &held {
            Some(held) => (held.quarantine_until, held.requested_at),
            None => {
                let txn = self.store.env.read_txn()?;
                let LiveEntityRow::Live { body, .. } =
                    live_entity_row_in_txn(&self.store, &txn, &id)?
                else {
                    return Err(stale());
                };
                let identity = decode_channel_identity_body(&body)?;
                let until = if identity.is_delegated() {
                    now
                } else {
                    now.saturating_add(resolve_quarantine_floor_in_txn(
                        &self.store,
                        &txn,
                        &identity,
                    )?)
                };
                (until, now)
            }
        };
        let request = ChannelIdentityLifecycleRequest {
            actor: ChannelIdentityLifecycleActor {
                actor_class: "human".to_owned(),
                actor_ref: Some(actor.to_hex()),
                actor_entity_ref: Some(actor),
            },
            gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
            requested_at,
            intent: ChannelIdentityLifecycleIntent::Release(ReleaseIntent {
                identity_id: id,
                quarantine_until,
            }),
        };
        let released = match &held {
            Some(held) => self.apply_channel_identity_lifecycle_request(request, held.request_ref)?,
            None => self.apply_channel_identity_lifecycle_intent(request)?,
        };
        if released.identity_retiring {
            return Ok(ShapeItemState::Landed {
                at: now,
                receipt: released.receipt_id,
            });
        }
        // Only a hold names an approve-once digest: the release waits for
        // the owner's press on it, keeping what a retry asks with.
        if let (Some(request_ref), Some(approval_digest)) =
            (released.request_ref, released.approval_digest.clone())
        {
            return Ok(ShapeItemState::Held {
                request_ref: request_ref.to_hex(),
                approval_digest,
                quarantine_until,
                requested_at,
            });
        }
        // FIX 6424 part 3: a hold names its approve-once press.
        Err(invalid(format!(
            "the release did not take: {}{}",
            released.owner_visible_state,
            released.held_approval_note()
        )))
    }
}
