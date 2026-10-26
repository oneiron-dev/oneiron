//! Who a pack hook's outcomes run as: the owner, or a foreign skill publisher.
//! Entry: `HookAuthor` and `Vault::hook_author_in_txn`.
//! Defines its own items.

use super::*;

/// The foreign-actor kind a hub pack's publisher is (ARCH-0072).
pub const FOREIGN_SKILL_PUBLISHER: &str = "skill_publisher";

/// Who a hook runs as (ARCH-0080 §6, §9): the owner who bound it, or a hub
/// pack's publisher as a foreign actor. The foreign fields name ARCH-0072's
/// foreign-actor admission: the actor's kind, its identity record, the hub
/// it offers from and the one Grant that admits it, plus the vault-resident
/// actor its outcomes stamp. Hub trust never chains to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HookAuthor {
    Owner,
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
}
