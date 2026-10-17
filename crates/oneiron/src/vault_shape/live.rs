//! The live arrangement read as a shape: every setup-plane row the vault
//! holds now, under the names a seed declares. Entity-backed rows and the
//! policy frontier come from one snapshot; the pack catalog verifies its own.
use super::{ShapeGrantBound, ShapeRow, invalid};
use crate::agent_def::decode_agent_definition;
use crate::channel_identity::decode_channel_identity_body;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_SKILL, ENTITY_TYPE_WORLD,
};
use crate::skill::{SkillLifecycle, decode_skill_record};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// The setup plane as it stands.
pub(super) struct LiveShape {
    /// Each row with the entity it was read from, when it is one.
    pub(super) rows: Vec<(ShapeRow, Option<EntityId>)>,
    /// The resolved policy frontier the same snapshot read (ARCH-0040).
    pub(super) policy_frontier: [u8; 32],
}

/// A WORLD body's name: its `label` leaf, else its `name` leaf.
pub(super) fn world_name(body: &[u8]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &body[..]).ok()?;
    if crate::batch::secret_scan::release_body_reads_whole_as_stored(&value, body) {
        return None;
    }
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    ["label", "name"].into_iter().find_map(|key| {
        entries.iter().find_map(|(k, v)| {
            (k.as_str() == Some(key))
                .then(|| v.as_str().map(str::to_owned))
                .flatten()
                .filter(|name| !name.trim().is_empty())
        })
    })
}

impl Vault {
    /// Live bodies of one entity type, off-record overlays left out.
    pub(super) fn shape_bodies_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity_type: u8,
    ) -> Result<Vec<(EntityId, Vec<u8>)>> {
        let mut rows = Vec::new();
        for id in self.store.port_entity_ids_by_type(txn, entity_type, None)? {
            let id = id?;
            if self.store.off_record_sessions.contains_entity(&id)? {
                continue;
            }
            if let LiveEntityRow::Live { body, .. } = live_entity_row_in_txn(&self.store, txn, &id)? {
                rows.push((id, body));
            }
        }
        Ok(rows)
    }

    /// The live setup plane, keeping an entity-backed row only when
    /// `visible` admits its entity. Base reality and received worlds are not
    /// this vault's arrangement, so they are not rows. A world with no name
    /// is named by its id.
    pub(super) fn read_live_shape(
        &self,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<LiveShape> {
        let mut rows = Vec::new();
        let policy_frontier = {
            let txn = self.store.env.read_txn()?;
            let policy_frontier =
                crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()?;
            let base = crate::claim::base_world_id();
            for (id, body) in self.shape_bodies_in_txn(&txn, ENTITY_TYPE_WORLD)? {
                if id == base || crate::entity_id::is_foreign_world_id_range(id) {
                    continue;
                }
                let name = world_name(&body).unwrap_or_else(|| id.to_hex());
                rows.push((ShapeRow::World { name }, Some(id)));
            }
            for (id, body) in self.shape_bodies_in_txn(&txn, ENTITY_TYPE_AGENT_DEF)? {
                let def = decode_agent_definition(&body)?;
                rows.push((
                    ShapeRow::Actor {
                        agent_id: def.agent_id,
                        ceiling: def.ceiling.into(),
                        enabled: def.enabled,
                    },
                    Some(id),
                ));
            }
            for (id, body) in self.shape_bodies_in_txn(&txn, ENTITY_TYPE_SKILL)? {
                let record = decode_skill_record(&body)?;
                if record.lifecycle_status == SkillLifecycle::Superseded {
                    continue;
                }
                rows.push((
                    ShapeRow::Skill {
                        skill_id: record.skill_id,
                        version: Some(record.version),
                    },
                    Some(id),
                ));
            }
            for (id, body) in self.shape_bodies_in_txn(&txn, ENTITY_TYPE_CHANNEL_IDENTITY)? {
                let identity = decode_channel_identity_body(&body)?;
                rows.push((
                    ShapeRow::Channel {
                        channel: identity.channel().to_owned(),
                        address: identity.address_or_handle().to_owned(),
                    },
                    Some(id),
                ));
            }
            for grant in self.active_standing_consent_grants_in_txn(&txn)? {
                rows.push((
                    ShapeRow::Grant {
                        grant_ref: grant.bound().digest().to_hex(),
                        bound: ShapeGrantBound::of(grant.bound()),
                    },
                    None,
                ));
            }
            policy_frontier
        };
        // The pack catalog checks each install against its live source in a
        // snapshot of its own, so it reads after this one has closed.
        for receipt in self.installed_packs()? {
            let source = EntityId::from_hex(&receipt.source_id)
                .map_err(|_| invalid("installed pack source id"))?;
            let version = self
                .get_pack_source(&source)?
                .map(|source| source.manifest().version.clone());
            rows.push((
                ShapeRow::Pack {
                    name: receipt.pack_name,
                    version,
                },
                None,
            ));
        }
        let mut kept = Vec::with_capacity(rows.len());
        for (row, entity) in rows {
            if entity.map_or(Ok(true), |id| visible(&id))? {
                kept.push((row, entity));
            }
        }
        // One row per name, in a stable order: the first entity by id wins.
        kept.sort_by(|(a, x), (b, y)| a.target().cmp(&b.target()).then(x.cmp(y)));
        kept.dedup_by(|(a, _), (b, _)| a.target() == b.target());
        Ok(LiveShape {
            rows: kept,
            policy_frontier,
        })
    }
}
