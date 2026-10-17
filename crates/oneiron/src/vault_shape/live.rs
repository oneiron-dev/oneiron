//! The live arrangement read as a shape: every setup-plane row the vault
//! holds now, under the names a seed declares. Entity-backed rows and the
//! policy frontier come from one snapshot; the pack catalog verifies its own.
use super::reach::{ReachActor, ReachRows, ReachSender};
use super::seed::hex;
use super::{ShapeGrantBound, ShapeMemberRole, ShapeRow, invalid};
use crate::agent_def::decode_agent_definition;
use crate::channel_identity::{
    ChannelIdentityState, channel_identity_send_holder_in_txn, decode_channel_identity_body,
};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::gate::manifest_authenticity::manifest_is_quarantined;
use crate::ports::{EdgeDirection, EntityStoreRead};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SKILL, ENTITY_TYPE_WORLD,
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
    /// The rows the reach line joins, read on the same snapshot and before
    /// any visibility filter: the join runs over the whole set.
    pub(super) reach: ReachRows,
}

/// A WORLD body's name: its `label` leaf, else its `name` leaf.
pub(super) fn world_name(body: &[u8]) -> Option<String> {
    text_leaf(body, &["label", "name"])
}

/// A FACET body's name: its `label` leaf. A person's substrate and a
/// persona scenario carry none, so they are not named masks.
pub(super) fn facet_name(body: &[u8]) -> Option<String> {
    text_leaf(body, &["label"])
}

/// The first of `keys` a map body carries as non-blank text.
fn text_leaf(body: &[u8], keys: &[&str]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &body[..]).ok()?;
    if crate::batch::secret_scan::release_body_reads_whole_as_stored(&value, body) {
        return None;
    }
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    keys.iter().find_map(|key| {
        entries.iter().find_map(|(k, v)| {
            (k.as_str() == Some(*key))
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
            if let LiveEntityRow::Live { body, .. } = live_entity_row_in_txn(&self.store, txn, &id)?
            {
                rows.push((id, body));
            }
        }
        Ok(rows)
    }

    /// The one live local world `name` names (its label, else its name, as
    /// written), on the caller's snapshot: `None` when no world or more than
    /// one carries it. Base reality and received worlds are not this vault's
    /// to bind.
    pub(crate) fn local_world_named_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        name: &str,
    ) -> Result<Option<EntityId>> {
        let base = crate::claim::base_world_id();
        let mut found = None;
        for (id, body) in self.shape_bodies_in_txn(txn, ENTITY_TYPE_WORLD)? {
            if id == base
                || crate::entity_id::is_foreign_world_id_range(id)
                || world_name(&body).as_deref() != Some(name)
            {
                continue;
            }
            if found.replace(id).is_some() {
                return Ok(None);
            }
        }
        Ok(found)
    }

    /// The live setup plane, keeping an entity-backed row only when
    /// `visible` admits its entity. Base reality and received worlds are not
    /// this vault's arrangement, so they are not rows, and neither is a
    /// retired skill or channel identity, an unnamed mask, or a quarantined
    /// manifest. A world with no name is named by its id.
    pub(super) fn read_live_shape(
        &self,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<LiveShape> {
        let mut rows = Vec::new();
        let mut reach = ReachRows::default();
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
            for (id, body) in self.shape_bodies_in_txn(&txn, ENTITY_TYPE_FACET)? {
                let Some(name) = facet_name(&body) else {
                    continue;
                };
                // A mask is its wearer's: the one person whose has_facet
                // edge reaches it.
                let wearers = self.filtered_edge_peers(
                    &txn,
                    EdgeDirection::In,
                    &id,
                    EdgeKind::HasFacet,
                    Some(ENTITY_TYPE_PERSON),
                )?;
                if let [person] = wearers.as_slice() {
                    rows.push((
                        ShapeRow::Facet {
                            person: person.to_hex(),
                            name,
                        },
                        Some(id),
                    ));
                }
            }
            if let Some(shared) = self.shared_vault_creation_in_txn(&txn)? {
                rows.push((
                    ShapeRow::Shared {
                        vault_id: shared.vault_id,
                        preset: shared.preset.map(Into::into),
                    },
                    None,
                ));
                for (member, role) in self.shared_members_in_txn(&txn, shared.vault_id)? {
                    if let Some(role) = ShapeMemberRole::of(role) {
                        rows.push((
                            ShapeRow::Member {
                                member: member.to_hex(),
                                role,
                            },
                            Some(member),
                        ));
                    }
                }
            }
            for (id, body) in self.shape_bodies_in_txn(&txn, ENTITY_TYPE_AGENT_DEF)? {
                let def = decode_agent_definition(&body)?;
                reach.actors.push(ReachActor {
                    entity: id,
                    agent_id: def.agent_id.clone(),
                    enabled: def.enabled,
                });
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
                if matches!(
                    record.lifecycle_status,
                    SkillLifecycle::Superseded | SkillLifecycle::Quarantined
                ) {
                    continue;
                }
                rows.push((
                    ShapeRow::Skill {
                        skill_id: record.skill_id,
                        version: Some(record.version),
                        source: None,
                    },
                    Some(id),
                ));
            }
            for (id, body) in self.shape_bodies_in_txn(&txn, ENTITY_TYPE_CHANNEL_IDENTITY)? {
                let identity = decode_channel_identity_body(&body)?;
                if matches!(
                    identity.state(),
                    ChannelIdentityState::Released
                        | ChannelIdentityState::Quarantine
                        | ChannelIdentityState::Tombstone
                ) {
                    continue;
                }
                if let Some((actor, may_send)) =
                    channel_identity_send_holder_in_txn(&self.store, &txn, &id)?
                {
                    reach.senders.push(ReachSender {
                        entity: id,
                        actor,
                        channel: identity.channel().to_owned(),
                        address: identity.address_or_handle().to_owned(),
                        may_send,
                    });
                }
                rows.push((
                    ShapeRow::Channel {
                        channel: identity.channel().to_owned(),
                        address: identity.address_or_handle().to_owned(),
                        provision: None,
                    },
                    Some(id),
                ));
            }
            // A quarantined manifest no longer counts, so it is not a row.
            for (id, body) in self.shape_bodies_in_txn(&txn, ENTITY_TYPE_POLICY_MANIFEST)? {
                if manifest_is_quarantined(&self.store, &txn, &id, &body)? {
                    continue;
                }
                rows.push((
                    ShapeRow::Manifest {
                        manifest_ref: id.to_hex(),
                        body: hex(&body),
                    },
                    Some(id),
                ));
            }
            for grant in self.active_standing_consent_grants_in_txn(&txn)? {
                reach.grants.push(grant.bound().clone());
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
            reach,
        })
    }
}
