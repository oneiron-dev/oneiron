//! The publisher ACTOR a report's signature channel runs to (FIX 7829).
//! ARCH-0056: "the publisher is an ACTOR entity, and publisher ↔ user is a
//! normal comm channel with that actor as counterparty". The actor is read
//! off the same canonical import receipts and installed packs the metadata
//! resolver reads the artifact from: the one hub the issue's publisher
//! shipped that artifact through, and the actor it publishes there as, a
//! configured hub's foreign publisher or the engine for its seeded packs. No
//! hub, or more than one, names no actor.

use std::collections::BTreeSet;

use super::join::ReportImportJoin;
use crate::edit_distance::publisher::PublisherActor;
use crate::{EntityId, Result, Vault};

impl Vault {
    /// Every hub through which `publisher_ref` shipped `artifact`, read for
    /// routing from the canonical receipts and installed packs.
    fn report_publisher_hubs(
        &self,
        publisher_ref: &str,
        artifact: EntityId,
    ) -> Result<BTreeSet<EntityId>> {
        let artifact = artifact.to_hex();
        let mut hubs = BTreeSet::new();
        let txn = self.store.env.read_txn()?;
        for row in IMPORTS.iter_from(&self.store, &txn, &[])? {
            let (_, receipt) = row?;
            if receipt.publisher.as_deref() == Some(publisher_ref) && receipt.entity == artifact {
                hubs.extend(EntityId::from_hex(&receipt.hub_id).ok());
            }
        }
        drop(txn);
        for pack in self.installed_packs()? {
            if pack.publisher == publisher_ref && pack.skills.contains(&artifact) {
                hubs.extend(EntityId::from_hex(&pack.hub_id).ok());
            }
        }
        Ok(hubs)
    }

    /// The same hub set, read on the delivery run's import join.
    fn report_publisher_hubs_in(
        &self,
        join: &ReportImportJoin,
        publisher_ref: &str,
        artifact: EntityId,
    ) -> BTreeSet<EntityId> {
        let artifact = artifact.to_hex();
        let mut hubs = BTreeSet::new();
        for receipt in &join.receipts {
            if receipt.publisher.as_deref() == Some(publisher_ref) && receipt.entity == artifact {
                hubs.extend(EntityId::from_hex(&receipt.hub_id).ok());
            }
        }
        for pack in &join.packs {
            if pack.publisher == publisher_ref && pack.skills.contains(&artifact) {
                hubs.extend(EntityId::from_hex(&pack.hub_id).ok());
            }
        }
        hubs
    }

    /// Whether any hub names `publisher_ref` as this artifact's publisher.
    /// Routing keeps a multi-hub artifact with its real publisher even when
    /// its comm counterparty is ambiguous; an owner pack has no such actor.
    pub(in super::super) fn report_has_publisher_actor(
        &self,
        publisher_ref: &str,
        artifact: EntityId,
    ) -> Result<bool> {
        let hubs = self.report_publisher_hubs(publisher_ref, artifact)?;
        let txn = self.store.env.read_txn()?;
        for hub in hubs {
            if self
                .skill_publisher_actor_in_txn(&txn, hub, publisher_ref)?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The ACTOR `publisher_ref` published `artifact` as, read on the
    /// delivery run's import join. `None` for an artifact with no publisher
    /// actor (the owner's own or local packs) and for one shipped through
    /// more than one hub: its delivery names no comm counterparty.
    pub(super) fn report_publisher_actor_in(
        &self,
        join: &ReportImportJoin,
        publisher_ref: &str,
        artifact: EntityId,
    ) -> Result<Option<PublisherActor>> {
        let mut hubs = self
            .report_publisher_hubs_in(join, publisher_ref, artifact)
            .into_iter();
        let (Some(hub), None) = (hubs.next(), hubs.next()) else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        Ok(self
            .skill_publisher_actor_in_txn(&txn, hub, publisher_ref)?
            .map(|actor| PublisherActor {
                actor,
                identity: publisher_ref.to_owned(),
            }))
    }
}
