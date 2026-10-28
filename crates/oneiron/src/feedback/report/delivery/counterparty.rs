//! The publisher ACTOR a report's signature channel runs to (FIX 7829).
//! ARCH-0056: "the publisher is an ACTOR entity, and publisher ↔ user is a
//! normal comm channel with that actor as counterparty". The actor is read
//! off the same canonical import receipts and installed packs the metadata
//! resolver reads the artifact from: the one hub the issue's publisher
//! shipped that artifact through, and the foreign-publisher actor that hub
//! admits it as. No hub, or more than one, names no actor.

use std::collections::BTreeSet;

use super::super::routing::IMPORTS;
use crate::edit_distance::publisher::PublisherActor;
use crate::{EntityId, Result, Vault};

impl Vault {
    /// The ACTOR `publisher_ref` published `artifact` as. `None` for an
    /// artifact with no foreign publisher (owner-authored, local or
    /// engine-seeded) and for one shipped through more than one hub: such a
    /// signature has no outward channel.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn report_publisher_actor(
        &self,
        publisher_ref: &str,
        artifact: EntityId,
    ) -> Result<Option<PublisherActor>> {
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
        let mut hubs = hubs.into_iter();
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
