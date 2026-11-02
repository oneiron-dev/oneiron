//! Who a pack hook's outcomes run as: the owner, a resident agent, or a
//! foreign skill publisher.
//! Entry: `HookAuthor` and `Vault::hook_author_in_txn`.
//! Defines its own items.

use super::*;

/// The foreign-actor kind a hub pack's publisher is (ARCH-0072).
pub const FOREIGN_SKILL_PUBLISHER: &str = "skill_publisher";

/// Who a hook runs as (ARCH-0080 §6, §7, §9): the owner who bound it, a
/// resident agent that wrote it into the `local` pack, or a hub pack's
/// publisher as a foreign actor. The foreign fields name ARCH-0072's
/// foreign-actor admission: the actor's kind, its identity record, the hub
/// it offers from and the one Grant that admits it, plus the vault-resident
/// actor its outcomes stamp. Hub trust never chains to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HookAuthor {
    Owner,
    /// A resident agent's own hook: its outcomes run as the agent, and it
    /// reads at the agent's ceiling unless the owner grants it otherwise.
    Agent {
        #[serde(with = "crate::serialize::entity_ref")]
        #[schemars(with = "String")]
        agent: EntityId,
    },
    ForeignActor {
        actor_kind: String,
        identity: String,
        #[serde(with = "crate::serialize::entity_ref")]
        #[schemars(with = "String")]
        hub: EntityId,
        /// The digest of the publisher's standing Grant.
        grant: String,
        #[serde(with = "crate::serialize::entity_ref")]
        #[schemars(with = "String")]
        actor: EntityId,
    },
}

/// The vault-resident actor a hub's publisher runs hooks as.
fn foreign_publisher_actor(hub: EntityId, identity: &str) -> Result<EntityId> {
    Ok(EntityId::derive(
        b"oneiron.pack-hook.foreign-publisher.v1",
        &[hub.as_bytes(), identity.as_bytes()],
    )?)
}

impl Vault {
    /// Who the hooks `receipt` installed run as: a pack fetched from a
    /// configured hub runs as its publisher, a foreign actor (ARCH-0080 §9);
    /// the owner's own pack runs as the owner.
    pub(crate) fn hook_author_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        receipt: &super::super::PackInstallReceipt,
    ) -> Result<HookAuthor> {
        let hub = EntityId::from_hex(&receipt.hub_id)?;
        let configured =
            match crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &hub)? {
                Some(raw) => {
                    EntityMetadataHeader::parse(&raw)
                        .ok_or(Error::CorruptedIndex("entity header"))?
                        .entity_type
                        == crate::registry::ENTITY_TYPE_SKILL_HUB
                }
                None => false,
            };
        if !configured {
            return Ok(HookAuthor::Owner);
        }
        let identity = receipt.publisher.clone();
        Ok(HookAuthor::ForeignActor {
            actor_kind: FOREIGN_SKILL_PUBLISHER.to_owned(),
            grant: crate::skill_hub::publisher::skill_publisher_grant(&identity, hub)?
                .digest()
                .to_hex(),
            actor: foreign_publisher_actor(hub, &identity)?,
            identity,
            hub,
        })
    }

    /// The vault-resident ACTOR `identity` publishes from `hub` as: a
    /// configured SKILL_HUB's publisher, the one its pack hooks run as, or the
    /// engine publishing its seeded packs from its own derived hub. `None`
    /// for any other pair, such as the owner's own and local packs, which
    /// have no publisher actor. An issue signature about its artifact rides a
    /// comm channel with this actor as counterparty (ARCH-0056, FIX 7829).
    pub(crate) fn skill_publisher_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        hub: EntityId,
        identity: &str,
    ) -> Result<Option<EntityId>> {
        if identity == super::super::builtin::ENGINE_PUBLISHER
            && hub == super::super::builtin::engine_hub_id()?
        {
            return Ok(Some(foreign_publisher_actor(hub, identity)?));
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &hub)?
        else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL_HUB {
            return Ok(None);
        }
        Ok(Some(foreign_publisher_actor(hub, identity)?))
    }
}
