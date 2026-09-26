//! Channel actor, scoped key and provider prior compose in one registration.
use super::*;
use crate::authority::HostSlipIssuer;
use crate::claim::ClaimSource;
use crate::federation::{Scope, ScopeAxis, ScopeId};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;

#[test]
fn mail_and_enrichment_are_distinct_scoped_actors_with_own_keys_and_priors() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(&owner, crate::registry::ENTITY_TYPE_PERSON, at, 1, b"owner")?;
    let facet = crate::claim::substrate_facet_id(owner)?;
    let issuer = HostSlipIssuer::from_secret(b"channel registration retained root")?;
    let mut actors = Vec::new();
    for (channel, address, seed) in [
        ("mail", "owner@example.test", 81),
        ("enrichment", "lookup-provider", 82),
    ] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut scope = Scope::top();
        scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(crate::claim::base_world_id())]));
        scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(facet)]));
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "effect".to_owned()]));
        let registration = ChannelActorRegistration {
            identity: ChannelIdentity::requested(
                channel,
                address,
                SelfHeldShape::DedicatedAddress,
                ChannelIdentityBinding::actor(owner),
                1,
            ),
            provider_key: format!("test.{channel}"),
            scope: scope.clone(),
            binding_key: key.verifying_key().to_bytes(),
            lifetime_secs: 600,
            confidence_prior: 0.75,
            prior_evidence: "owner configured provider prior".to_owned(),
        };
        let registered = vault.register_channel_actor(&issuer, registration.clone())?;
        assert_eq!(
            vault.channel_actor(&registered.identity_ref)?,
            Some(registered.actor_ref)
        );
        assert_eq!(
            vault
                .get_channel_identity(&registered.identity_ref)?
                .unwrap()
                .binding
                .actor_ref(),
            Some(registered.actor_ref)
        );
        assert_ne!(registered.actor_ref, owner);
        assert_eq!(registered.slip.claims.scope, scope);
        let signature = key
            .sign(&registered.slip.binding_transcript(b"channel read")?)
            .to_bytes();
        assert_eq!(
            vault
                .verify_capability_slip(&issuer, &registered.slip, b"channel read", &signature)?
                .scope(),
            &scope
        );
        let prior = vault
            .get_claim(&registered.prior_claim_ref)?
            .expect("stored prior");
        assert_eq!(prior.subject, ClaimSubject::Entity(registered.actor_ref));
        let id = EntityId::now();
        let mut enrichment = ClaimBody::new(
            crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT,
            ClaimSubject::Entity(registered.actor_ref),
            Value::Map(vec![(
                Value::from("provider"),
                Value::from(registration.provider_key),
            )]),
            0.8,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        enrichment.source = Some(ClaimSource::Observed);
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                1,
                &crate::claim::encode_claim_body(&enrichment)?,
            )
            .commit()?;
        let effective = crate::provider_confidence::effective_confidence(&vault, &id)?;
        assert!((effective - 0.6).abs() < 0.0001);
        assert_eq!(
            vault
                .get_connector_key(&registered.connector_key_ref)?
                .expect("key")
                .actor_entity_ref,
            Some(registered.actor_ref)
        );
        actors.push(registered.actor_ref);
    }
    assert_ne!(actors[0], actors[1]);
    Ok(())
}
