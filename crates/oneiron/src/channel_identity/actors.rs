//! Channels are credential-bearing scoped actors, not identities borrowed from an agent.
use super::*;
use crate::authority::{CapabilitySlip, HostSlipIssuer, SlipClaims};
use crate::batch::{BatchOp, EntityMetadataHeader, apply_ops};
use crate::connector_key::ConnectorKeyRecord;
use crate::error::{Error, RecordError, Result};
use crate::federation::{Scope, ScopeAxis};
use crate::{EntityId, TimeRange, Vault};
use rmpv::Value;
use std::collections::BTreeSet;

/// Host-controlled channel registration. Authentication secrets are deliberately absent.
#[derive(Debug, Clone)]
pub struct ChannelActorRegistration {
    pub identity: ChannelIdentity,
    pub provider_key: String,
    pub scope: Scope,
    /// Public half of a throwaway holder key; the private half never enters the vault.
    pub binding_key: [u8; 32],
    pub lifetime_secs: u64,
    pub confidence_prior: f32,
    pub prior_evidence: String,
}
/// The credential is returned to the host, never written into an identity or prior claim.
#[derive(Debug, Clone)]
pub struct RegisteredChannelActor {
    pub actor_ref: EntityId,
    pub identity_ref: EntityId,
    pub connector_key_ref: EntityId,
    pub prior_claim_ref: EntityId,
    pub slip: CapabilitySlip,
}

impl Vault {
    /// Resolves the channel's own actor, not the identity's routing target.
    pub fn channel_actor(&self, identity_ref: &EntityId) -> Result<Option<EntityId>> {
        let Some(identity) = self.get_channel_identity(identity_ref)? else {
            return Ok(None);
        };
        let Some(actor) = identity.reputation_ref else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&txn, actor.as_bytes())? else {
            return Ok(None);
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("channel actor header"));
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_PERSON {
            return Ok(None);
        }
        let Value::Map(entries) =
            rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| Error::CorruptedIndex("channel actor body"))?
        else {
            return Ok(None);
        };
        Ok(entries
            .iter()
            .any(|(key, value)| {
                key.as_str() == Some("channel_identity_ref")
                    && value.as_str() == Some(identity_ref.to_hex().as_str())
            })
            .then_some(actor))
    }

    /// Atomically registers one channel actor, its identity route, budget key,
    /// confidence prior and actual log-backed Scope credential. Sends still
    /// pass the existing effector gate; this is not a dispatch permit.
    pub fn register_channel_actor(
        &self,
        issuer: &HostSlipIssuer,
        registration: ChannelActorRegistration,
    ) -> Result<RegisteredChannelActor> {
        registration.identity.validate()?;
        if registration.lifetime_secs == 0
            || registration.lifetime_secs > 365 * 24 * 60 * 60
            || !registration.confidence_prior.is_finite()
            || !(0.0..=1.0).contains(&registration.confidence_prior)
            || registration.prior_evidence.is_empty()
        {
            return Err(Error::InvalidClaimBody("invalid channel registration"));
        }
        // Explicit root provisioning happens before registration, never by
        // interpreting a missing/conflicted root as an enrollment invitation.
        self.verified_host_root_slip(issuer)?;
        let mut txn = self.store.env.write_txn()?;
        validate_axes(self, &txn, &registration.scope)?;
        // A provider name identifies one channel actor. A second claimant may
        // not steal the existing actor's reputation or key lineage.
        for kind in [crate::registry::ENTITY_TYPE_PERSON] {
            for row in self.store.type_index.prefix_iter(&txn, &[kind])? {
                let (key, _) = row?;
                let id = crate::vault::entity_id_from_type_index_key(&key)?;
                let Some(raw) = self.store.entities.get(&txn, id.as_bytes())? else {
                    return Err(Error::CorruptedIndex("channel actor index"));
                };
                if let Ok(Value::Map(entries)) =
                    rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                    && entries.iter().any(|(key, value)| {
                        key.as_str() == Some("provider_key")
                            && value.as_str() == Some(registration.provider_key.as_str())
                    })
                {
                    return Err(Error::Record(RecordError::ChannelIdentityAlreadyExists));
                }
            }
        }
        let actor_ref = EntityId::now();
        let identity_ref = EntityId::now();
        let connector_key_ref = EntityId::now();
        let now = self.instant_in_txn(&txn)?.secs();
        let mut identity = registration.identity;
        let route_target = identity.binding.actor_ref();
        identity.binding = ChannelIdentityBinding::Actor {
            actor_ref,
            facet_ref: identity.binding.facet_ref(),
        };
        identity.reputation_ref = Some(actor_ref);
        let actor_body = Value::Map(vec![
            (
                Value::from("provider_key"),
                Value::from(registration.provider_key.clone()),
            ),
            (
                Value::from("channel_identity_ref"),
                Value::from(identity_ref.to_hex()),
            ),
            (
                Value::from("channel"),
                Value::from(identity.channel.clone()),
            ),
            (Value::from("actor_class"), Value::from("system")),
            (
                Value::from("route_target_ref"),
                route_target.map_or(Value::Nil, |id| Value::from(id.to_hex())),
            ),
        ]);
        let mut actor_bytes = Vec::new();
        rmpv::encode::write_value(&mut actor_bytes, &actor_body)
            .map_err(|_| Error::InvariantViolation("channel actor encode"))?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut txn,
            vec![BatchOp::Put {
                id: actor_ref,
                entity_type: crate::registry::ENTITY_TYPE_PERSON,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: actor_bytes,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        admit_channel_identity_transition_in_txn(
            &self.store,
            &txn,
            &identity_ref,
            IdentityTransition::Birth { next: &identity },
        )?;
        self.apply_channel_identity_body(
            &mut txn,
            &identity_ref,
            now,
            encode_channel_identity_body(&identity)?,
        )?;
        let connector =
            ConnectorKeyRecord::active(identity.channel, Some(actor_ref), Vec::new(), now);
        self.register_connector_key_in_txn(&mut txn, &connector_key_ref, &connector)?;
        let prior_claim_ref = crate::provider_confidence::write_provider_prior_in_txn(
            self,
            &mut txn,
            &registration.provider_key,
            registration.confidence_prior,
            &registration.prior_evidence,
        )?;
        let mut slip_id = [0; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut slip_id);
        let vault_id = self
            .authority_fold_readonly_in_txn(&txn)?
            .vault_id
            .ok_or(Error::InvalidClaimBody("channel has no authority root"))?;
        let expires_at = now
            .checked_add(registration.lifetime_secs)
            .ok_or(Error::ArithmeticOverflow("channel slip expiry"))?;
        let slip = self.mint_slip_in_txn(
            &mut txn,
            issuer,
            SlipClaims {
                slip_id,
                vault_id,
                pact: None,
                parent_id: None,
                holder_ref: actor_ref.to_hex(),
                binding_key: registration.binding_key,
                scope: registration.scope,
                issued_at: now,
                expires_at,
                ttl_secs: registration.lifetime_secs,
                single_use: false,
                records: BTreeSet::new(),
                channels: BTreeSet::new(),
                actor_class: Some("system".to_owned()),
                org_ref: None,
            },
        )?;
        txn.commit()?;
        Ok(RegisteredChannelActor {
            actor_ref,
            identity_ref,
            connector_key_ref,
            prior_claim_ref,
            slip,
        })
    }
}
fn validate_axes(vault: &Vault, txn: &heed::RoTxn<'_>, scope: &Scope) -> Result<()> {
    for (axis, kind) in [
        (&scope.worlds, crate::registry::ENTITY_TYPE_WORLD),
        (&scope.facets, crate::registry::ENTITY_TYPE_FACET),
    ] {
        match axis {
            ScopeAxis::Bottom => {
                return Err(Error::InvalidClaimBody("channel scope cannot be bottom"));
            }
            ScopeAxis::All => {}
            ScopeAxis::Some(ids) => {
                if ids.is_empty() {
                    return Err(Error::InvalidClaimBody("channel scope cannot be empty"));
                }
                for id in ids {
                    if kind == crate::registry::ENTITY_TYPE_WORLD
                        && id.0 == crate::claim::base_world_id()
                    {
                        continue;
                    }
                    let found = vault
                        .store
                        .entities
                        .get(txn, id.0.as_bytes())?
                        .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|h| h.entity_type));
                    if found != Some(kind) {
                        return Err(Error::InvalidClaimBody(
                            "channel scope reference has wrong type",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
