//! A world facet (ARCH-0070 setup plane, ARCH-0022): a named facet that
//! organizes scope inside one world, beside the masks a person wears. Canon
//! names no record of its own for it, so it is the smallest one the store
//! already holds: a FACET entity with the body every mask carries, joined to
//! its world by one `in_world` edge, and worn by no one. A person's mask
//! stays as it is (a `has_facet` edge from its wearer), and so does identity
//! topology's facet op, which partitions a person. A world facet grants
//! nothing, as no mask does.
use super::live::{facet_name, world_name};
use super::{SHAPE_NAME_MAX_BYTES, invalid};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::ports::EdgeDirection;
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_WORLD};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, TimeRange, Vault};
use std::collections::BTreeMap;

impl Vault {
    /// Every live local world on the caller's snapshot, by the name its
    /// shape row reads: its label, else its name, else its id. Base reality
    /// and received worlds are not this vault's arrangement.
    pub(super) fn local_worlds_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<BTreeMap<EntityId, String>> {
        let base = crate::claim::base_world_id();
        let mut worlds = BTreeMap::new();
        for (id, body) in self.shape_bodies_in_txn(txn, ENTITY_TYPE_WORLD)? {
            if id == base || crate::entity_id::is_foreign_world_id_range(id) {
                continue;
            }
            worlds.insert(id, world_name(&body).unwrap_or_else(|| id.to_hex()));
        }
        Ok(worlds)
    }

    /// The name of the one world in `worlds` that the facet `facet` is
    /// joined to by its `in_world` edge; none when it is joined to no live
    /// local world, or to more than one world.
    pub(super) fn facet_world_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        facet: &EntityId,
        worlds: &BTreeMap<EntityId, String>,
    ) -> Result<Option<String>> {
        let homes = self.filtered_edge_peers(
            txn,
            EdgeDirection::Out,
            facet,
            EdgeKind::InWorld,
            Some(ENTITY_TYPE_WORLD),
        )?;
        Ok(match homes.as_slice() {
            [home] => worlds.get(home).cloned(),
            _ => None,
        })
    }

    /// Creates a facet named `name` inside the world its shape row names
    /// `world`, as `owner`: a FACET with the body every mask carries, joined
    /// to the world by its `in_world` edge in the same writer, and worn by
    /// no one. An ordinary setup write that widens nothing. A world name no
    /// live local world carries, or more than one does, refuses; so does a
    /// live facet of that world already carrying the name.
    ///
    /// # Errors
    ///
    /// A blank or taken name, a world that does not resolve to one live
    /// local world, an owner proof that no longer holds, or a store failure.
    pub fn create_world_facet(
        &self,
        owner: &AuthenticatedOwner,
        world: &str,
        name: &str,
        now: u64,
    ) -> Result<EntityId> {
        if name.trim().is_empty() || name.len() > SHAPE_NAME_MAX_BYTES {
            return Err(invalid("a facet's name is 1 to 256 bytes and not blank"));
        }
        let body = rmpv::Value::Map(vec![
            ("label".into(), name.into()),
            ("sensitivity".into(), "sensitive".into()),
        ]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &body)
            .map_err(|_| invalid("facet encoding failed"))?;
        let weight = EdgeKind::InWorld
            .default_weight()
            .ok_or_else(|| invalid("in_world carries no default weight"))?;
        let id = EntityId::now();
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut named = self
                .local_worlds_in_txn(txn)?
                .into_iter()
                .filter(|(_, live)| live == world)
                .map(|(home, _)| home);
            let (Some(home), None) = (named.next(), named.next()) else {
                return Err(invalid(
                    "a world facet's world is one live world of this vault, by its name",
                ));
            };
            for facet in self.filtered_edge_peers(
                txn,
                EdgeDirection::In,
                &home,
                EdgeKind::InWorld,
                Some(ENTITY_TYPE_FACET),
            )? {
                if let LiveEntityRow::Live { body, .. } =
                    live_entity_row_in_txn(&self.store, txn, &facet)?
                    && facet_name(&body).as_deref() == Some(name)
                {
                    return Err(invalid(
                        "a live facet of that world already carries that name",
                    ));
                }
            }
            self.batch_in()
                .put(
                    &id,
                    ENTITY_TYPE_FACET,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &data,
                )
                .edge_with_created_at(&id, EdgeKind::InWorld, &home, weight, now)
                .apply(txn)?;
            Ok(id)
        })
    }
}
