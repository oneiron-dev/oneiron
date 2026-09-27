//! Owner-bound exact-effect origin: same-transaction location, never caller scope text.
use super::input::ExternalEffectGateInput;
use super::policy_values::{PolicyEvaluationScope, PolicyRowScope};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{base_world_id, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"policy:effect-origin:v1:";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EffectOriginStamp {
    version: u8,
    digest: [u8; 32],
    origin: EntityId,
    origin_hash: [u8; 32],
}
fn invalid() -> Error {
    Error::InvalidConfig("unverified policy effect origin".into())
}

fn effect_digest(effect: &ExternalEffectGateInput) -> Option<[u8; 32]> {
    let send = effect
        .send_ref
        .as_deref()
        .filter(|value| !value.is_empty())?;
    if effect.scoped_mcp_call.is_some() {
        return None;
    }
    let fields = serde_json::json!([
        effect.actor.actor_class,
        effect.actor.actor_ref,
        effect.provenance.actor_entity_ref.map(|id| id.to_hex()),
        effect.verb,
        effect.channel,
        effect.channel_identity_ref.map(|id| id.to_hex()),
        effect.counterparty,
        effect.brief_ref,
        send,
        effect.policy_risk.as_str(),
    ]);
    let bytes = serde_json::to_vec(&fields).ok()?;
    Some(
        *blake3::hash(&[b"oneiron.policy-effect-origin.v1".as_slice(), &bytes].concat()).as_bytes(),
    )
}
fn key(digest: &[u8; 32]) -> Vec<u8> {
    [PREFIX, digest.as_slice()].concat()
}

fn origin_scope(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    origin: EntityId,
) -> Result<PolicyEvaluationScope> {
    let raw = store
        .entities
        .get(txn, origin.as_bytes())?
        .ok_or_else(invalid)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type == ENTITY_TYPE_CLAIM {
        let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let world = body.world.unwrap_or_else(base_world_id);
        return Ok(PolicyEvaluationScope {
            world: Some(world),
            project: Some(body.scope_project),
            hidden_world: world != base_world_id(),
            ..Default::default()
        });
    }
    if let Some(location) =
        crate::workspace_roster::effect_project_origin_in_txn(store, txn, origin)?
    {
        return Ok(PolicyEvaluationScope {
            project: Some(location.project),
            subproject: location.subproject,
            thread: location.thread,
            unknown_world: true,
            ..Default::default()
        });
    }
    Err(invalid())
}

impl Vault {
    /// Binds a durable, exact effect identity to a stored claim or project
    /// room. The issuer must hold vault policy power: no scoped grant can
    /// assert a convenient origin for an unrelated send.
    pub(crate) fn bind_policy_effect_origin_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        effect: &ExternalEffectGateInput,
        origin: EntityId,
        now: u64,
    ) -> Result<()> {
        let digest = effect_digest(effect).ok_or_else(invalid)?;
        if !self.policy_power_in_txn(txn, actor, PolicyRowScope::Vault, now)? {
            return Err(invalid());
        }
        origin_scope(&self.store, txn, origin)?;
        let raw = self
            .store
            .entities
            .get(txn, origin.as_bytes())?
            .ok_or_else(invalid)?;
        let stamp = EffectOriginStamp {
            version: 1,
            digest,
            origin,
            origin_hash: *blake3::hash(&raw).as_bytes(),
        };
        let encoded = rmp_serde::to_vec_named(&stamp).map_err(|_| invalid())?;
        let key = key(&digest);
        if let Some(previous) = self.store.vault_meta.get(txn, &key)? {
            if previous != encoded {
                return Err(invalid());
            }
            return Ok(());
        }
        self.store.vault_meta.put(txn, &key, &encoded)?;
        Ok(())
    }
}

pub(super) fn scope_for_effect(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<PolicyEvaluationScope> {
    let Some(digest) = effect_digest(effect) else {
        return Ok(PolicyEvaluationScope {
            unknown_location: true,
            ..Default::default()
        });
    };
    let Some(bytes) = store.vault_meta.get(txn, &key(&digest))? else {
        return Ok(PolicyEvaluationScope {
            unknown_location: true,
            ..Default::default()
        });
    };
    let stamp: EffectOriginStamp = rmp_serde::from_slice(&bytes).map_err(|_| invalid())?;
    if stamp.version != 1 || stamp.digest != digest {
        return Err(invalid());
    }
    let raw = store
        .entities
        .get(txn, stamp.origin.as_bytes())?
        .ok_or_else(invalid)?;
    if *blake3::hash(&raw).as_bytes() != stamp.origin_hash {
        return Err(invalid());
    }
    origin_scope(store, txn, stamp.origin)
}
