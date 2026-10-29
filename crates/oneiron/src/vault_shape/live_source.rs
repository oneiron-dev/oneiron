//! What the live read says about how a skill and a channel identity were
//! made (FIX 2668), so that adopting the live shape into a seed keeps it: a
//! skill row's hub source comes from its hub provenance, and a channel row's
//! provision comes from its identity body.
use super::ShapeRow;
use super::channel::{
    ShapeChannelBinding, ShapeChannelCustody, ShapeChannelProvision, ShapeSelfHeld,
};
use super::live::ShapeSources;
use super::reach::ReachActor;
use super::skill::ShapeSkillSource;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
};
use crate::claim::ClaimLifecycleStatus;
use crate::consent::{BoundClass, BoundEnvelope, BoundSubject, GrantBound};
use crate::error::Result;
use crate::skill_hub::{HubPin, HubRef, PREDICATE_SKILL_HUB_PROVENANCE, default_skill_hub_id};
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

/// The actor class a hub publisher's admission grant names, as
/// `skill_hub::publisher` binds it.
const SKILL_PUBLISHER_ACTOR_CLASS: &str = "foreign-publisher";

/// The verb class a hub publisher's admission grant names.
const SKILL_OFFER_CLASS: &str = "skill.offer";

/// Most lifecycle receipts, newest first, the live read scans for the lane
/// an active channel identity was fulfilled on. An identity whose last lane
/// lies past them projects no provision.
const SHAPE_LANE_RECEIPT_READ_MAX: usize = 4096;

/// A live skill row, by its place in the read's rows, and its entity.
pub(super) type LiveSkill = (usize, EntityId);

/// A live channel row whose body states no fulfillment lane, by its place
/// in the read's rows: its identity, and the custody and binding it holds.
pub(super) type UnlanedChannel = (usize, EntityId, ShapeChannelCustody, ShapeChannelBinding);

/// The one publisher the owner admitted for `hub` among `grants`, as their
/// identity; none when no admission names the hub, or more than one
/// identity does.
fn hub_publisher(grants: &[GrantBound], hub: EntityId) -> Option<String> {
    let selector = format!("hub:{}", hub.to_hex());
    let mut admitted = grants.iter().filter_map(|grant| {
        match (grant.subject(), grant.class(), grant.envelope()) {
            (
                BoundSubject::Actor(actor),
                BoundClass::Action(class),
                BoundEnvelope::Action(envelope),
            ) if actor.actor_class() == Some(SKILL_PUBLISHER_ACTOR_CLASS)
                && class.as_str() == SKILL_OFFER_CLASS
                && envelope.selectors().iter().any(|named| *named == selector) =>
            {
                Some(actor.actor_ref().to_owned())
            }
            _ => None,
        }
    });
    let first = admitted.next()?;
    admitted.all(|other| other == first).then_some(first)
}

/// `hub_ref` as a seed row's source: the first-party library by subtree,
/// else the hub with its folder, pin and admitted publisher.
fn skill_source(
    hub_ref: HubRef,
    library: EntityId,
    grants: &[GrantBound],
) -> Option<ShapeSkillSource> {
    if hub_ref.hub_id == library {
        return Some(ShapeSkillSource::Library {
            subtree: hub_ref.ref_string,
        });
    }
    let pin_value = match &hub_ref.pin {
        HubPin::Semver(value)
        | HubPin::Tag(value)
        | HubPin::Commit(value)
        | HubPin::ContentHash(value) => value.clone(),
        HubPin::None => return None,
    };
    Some(ShapeSkillSource::Hub {
        hub: hub_ref.hub_id.to_hex(),
        pin_type: hub_ref.pin.pin_type().to_owned(),
        pin_value,
        publisher: hub_publisher(grants, hub_ref.hub_id)?,
        folder: hub_ref.ref_string,
    })
}

/// The custody and binding `identity` holds, as a provision row states
/// them; none when its binding names an actor that is not on `roster`.
pub(super) fn channel_holding(
    identity: &ChannelIdentity,
    roster: &[ReachActor],
) -> Option<(ShapeChannelCustody, ShapeChannelBinding)> {
    let custody = match identity.grant() {
        Some(grant) => ShapeChannelCustody::Delegated {
            custody_record_ref: grant.custody_record_ref.clone(),
            scopes: grant.scopes.iter().map(|scope| (*scope).into()).collect(),
        },
        None => ShapeChannelCustody::SelfHeld {
            shape: match identity.shape() {
                ChannelIdentityShape::DedicatedAddress => ShapeSelfHeld::DedicatedAddress,
                ChannelIdentityShape::DedicatedHandle => ShapeSelfHeld::DedicatedHandle,
                ChannelIdentityShape::SharedPresence => ShapeSelfHeld::SharedPresence,
                ChannelIdentityShape::DelegatedGrant => return None,
            },
        },
    };
    let binding = match identity.binding() {
        ChannelIdentityBinding::Actor {
            actor_ref,
            facet_ref,
        } => ShapeChannelBinding::Actor {
            agent_id: roster
                .iter()
                .find(|actor| actor.entity == actor_ref)?
                .agent_id
                .clone(),
            facet: facet_ref.map(|facet| facet.to_hex()),
        },
        ChannelIdentityBinding::Vault { vault_id } => ShapeChannelBinding::Vault { vault_id },
    };
    Some((custody, binding))
}

impl Vault {
    /// Gives each of `skills` among `rows` the hub source its first active
    /// hub provenance claim names, on the caller's snapshot, listing each
    /// claim read in `sources`. A skill stays sourceless when no claim names
    /// a pinned hub, or its hub's publisher is not one admitted identity
    /// among `grants`.
    ///
    /// # Errors
    ///
    /// A read failure or an undecodable provenance claim.
    pub(super) fn source_live_skills_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        rows: &mut [(ShapeRow, Option<EntityId>)],
        skills: &[LiveSkill],
        grants: &[GrantBound],
        sources: &mut ShapeSources,
    ) -> Result<()> {
        let library = default_skill_hub_id()?;
        for (at, id) in skills {
            let mut found = None;
            for claim in self.claims_for_subject_in_txn(txn, id)? {
                let Some(body) = self.get_claim_in_txn(txn, &claim)? else {
                    continue;
                };
                if body.predicate != PREDICATE_SKILL_HUB_PROVENANCE
                    || body.lifecycle != ClaimLifecycleStatus::Active
                {
                    continue;
                }
                let Some(hub_ref) = body.value.as_map().and_then(|entries| {
                    entries
                        .iter()
                        .find_map(|(key, value)| (key.as_str() == Some("hubRef")).then_some(value))
                }) else {
                    continue;
                };
                sources.list(claim);
                found = skill_source(HubRef::from_value(hub_ref)?, library, grants);
                break;
            }
            if let Some((ShapeRow::Skill { source, .. }, _)) = rows.get_mut(*at) {
                *source = found;
            }
        }
        Ok(())
    }

    /// Gives each of `unlaned` among `rows` its provision, with the lane
    /// the newest lifecycle receipt naming the identity's fulfillment lane
    /// records; an active body holds none. The receipts are the vault's
    /// lifecycle ledger, read after the live snapshot closes.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub(super) fn lane_live_channels(
        &self,
        rows: &mut [(ShapeRow, Option<EntityId>)],
        unlaned: Vec<UnlanedChannel>,
    ) -> Result<()> {
        if unlaned.is_empty() {
            return Ok(());
        }
        let mut lanes: BTreeMap<[u8; 16], ChannelIdentityFulfillment> = BTreeMap::new();
        for receipt in self
            .store
            .channel_identity_lifecycle_receipts(SHAPE_LANE_RECEIPT_READ_MAX)?
        {
            if let Some(lane) = receipt
                .fulfillment_mode
                .as_deref()
                .and_then(ChannelIdentityFulfillment::parse)
            {
                lanes.entry(receipt.identity_id).or_insert(lane);
            }
        }
        for (at, id, custody, binding) in unlaned {
            if let (Some(lane), Some((ShapeRow::Channel { provision, .. }, _))) =
                (lanes.get(id.as_bytes()), rows.get_mut(at))
            {
                *provision = Some(ShapeChannelProvision {
                    custody,
                    binding,
                    fulfillment: (*lane).into(),
                });
            }
        }
        Ok(())
    }
}
