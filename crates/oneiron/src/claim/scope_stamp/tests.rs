//! Observable Scope identity, codec, selector and replay acceptance.
use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, decode_claim_body, encode_claim_body,
};
use crate::federation::record_scope::ScopeView;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use crate::test_util::entity;
use crate::{TimeRange, Vault};
fn vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    Ok((dir, vault))
}
fn body() -> ClaimBody {
    ClaimBody::new(
        "test.scope",
        ClaimSubject::Entity(entity(31)),
        Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("test encode"))?;
    Ok(bytes)
}
const AT: TimeRange = TimeRange { start: 10, end: 10 };

#[test]
fn four_scope_keys_are_required_at_raw_and_replay_write_doors() -> Result<()> {
    let (_dir, vault) = vault()?;
    let id = entity(32);
    let bytes = encode_claim_body(&body())?;
    let Value::Map(entries) = rmpv::decode::read_value(&mut bytes.as_slice()).expect("fixture")
    else {
        panic!("map")
    };
    for field in [
        "worldId",
        "scopeFacetId",
        "scopeRelationshipId",
        "scopeProjectId",
        "scopeVersion",
    ] {
        for nil in [false, true] {
            let malformed = Value::Map(
                entries
                    .iter()
                    .filter_map(|(k, v)| {
                        if k.as_str() == Some(field) {
                            nil.then(|| (k.clone(), Value::Nil))
                        } else {
                            Some((k.clone(), v.clone()))
                        }
                    })
                    .collect(),
            );
            let malformed = encode(&malformed)?;
            assert!(matches!(
                vault.put_entity(&id, ENTITY_TYPE_CLAIM, AT, 10, &malformed),
                Err(Error::InvalidClaimBody(_))
            ));
            assert!(matches!(
                vault
                    .batch()
                    .put_replicated(&id, ENTITY_TYPE_CLAIM, AT, 10, &malformed)
                    .commit(),
                Err(Error::InvalidClaimBody(_))
            ));
            #[cfg(feature = "sync")]
            assert!(
                vault
                    .with_write_txn(|txn| vault
                        .batch_in()
                        .put_replicated(&id, ENTITY_TYPE_CLAIM, AT, 10, &malformed)
                        .apply(txn))
                    .is_err()
            );
            assert!(vault.get(&id)?.is_none());
        }
    }
    vault
        .batch()
        .put_replicated(&id, ENTITY_TYPE_CLAIM, AT, 10, &bytes)
        .commit()?;
    assert_eq!(vault.get_claim(&id)?, Some(body()));
    assert!(
        vault
            .record_scope(&id)?
            .expect("fixture")
            .worlds
            .contains(&ScopeId(base_world_id()))
    );
    assert!(
        vault
            .put_entity(
                &base_world_id(),
                crate::registry::ENTITY_TYPE_WORLD,
                AT,
                10,
                b""
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn person_mints_one_substrate_facet_with_sensitivity_and_replay_is_idempotent() -> Result<()> {
    let (_dir, vault) = vault()?;
    let person = entity(33);
    let facet = substrate_facet_id(person);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, AT, 10, b"person")?;
    vault
        .batch()
        .put_replicated(&person, ENTITY_TYPE_PERSON, AT, 10, b"person")
        .commit()?;
    let raw = vault.get(&facet)?.expect("fixture");
    assert_eq!(vault.get_entity_type(&facet)?, Some(ENTITY_TYPE_FACET));
    let Value::Map(entries) = rmpv::decode::read_value(&mut &raw[..]).expect("fixture") else {
        panic!("map")
    };
    assert!(
        entries
            .iter()
            .any(|(k, v)| k.as_str() == Some("sensitivity") && v.as_str() == Some("sensitive"))
    );
    let edges = vault.edges_out(&person)?;
    assert_eq!(
        edges
            .iter()
            .filter(|e| e.kind == crate::EdgeKind::HasFacet && e.target == facet)
            .count(),
        1
    );
    assert!(
        vault
            .put_entity(&facet, ENTITY_TYPE_FACET, AT, 10, b"replacement")
            .is_err()
    );
    Ok(())
}
#[test]
fn legacy_claim_scope_sweep_stamps_explicit_base_once() -> Result<()> {
    let (_dir, vault) = vault()?;
    let id = entity(34);
    let bytes = encode_claim_body(&body())?;
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut bytes.as_slice()).expect("fixture")
    else {
        panic!("map")
    };
    entries.retain(|(k, _)| {
        ![
            "worldId",
            "scopeFacetId",
            "scopeRelationshipId",
            "scopeProjectId",
            "scopeVersion",
        ]
        .contains(&k.as_str().expect("fixture"))
    });
    let legacy = encode(&Value::Map(entries))?;
    let mut raw = vec![ENTITY_TYPE_CLAIM];
    raw.extend_from_slice(&10u64.to_be_bytes());
    raw.extend_from_slice(&10u64.to_be_bytes());
    raw.extend_from_slice(&10u64.to_be_bytes());
    raw.extend_from_slice(&legacy);
    vault.with_write_txn(|txn| {
        vault.store.entities.put(txn, id.as_bytes(), &raw)?;
        vault
            .store
            .vault_meta
            .delete(txn, b"scope:claim-codec:v2")?;
        Ok(())
    })?;
    crate::batch::sweep_scope_stamps(&vault.store)?;
    let first = vault.get(&id)?.expect("fixture");
    assert!(decode_claim_body(&first[..], true).is_ok());
    crate::batch::sweep_scope_stamps(&vault.store)?;
    assert_eq!(vault.get(&id)?.expect("fixture"), first);
    Ok(())
}
#[test]
fn unstamped_records_are_excluded_from_read_export_delete_and_debug_is_explicit() -> Result<()> {
    let (_dir, vault) = vault()?;
    let local = entity(35);
    let remote = entity(36);
    vault.put_entity(&local, ENTITY_TYPE_PERSON, AT, 10, b"local")?;
    vault
        .batch()
        .put_replicated(&remote, ENTITY_TYPE_PERSON, AT, 10, b"remote")
        .commit()?;
    let mut selector = Scope::top();
    selector.bands = ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_PERSON]));
    let top = Scope::top();
    let normal = vault.records_in_scope(&selector, &top, &top, ScopeView::Normal)?;
    assert!(normal.iter().any(|r| r.id == local));
    assert!(!normal.iter().any(|r| r.id == remote));
    let exported = vault.export_records_in_scope(&selector, &top, &top)?;
    assert!(exported.iter().any(|r| r.id == local));
    assert!(!exported.iter().any(|r| r.id == remote));
    let debug = vault.records_in_scope(&selector, &top, &top, ScopeView::Debug)?;
    assert!(
        debug
            .iter()
            .any(|r| r.id == remote && r.suppressed && r.scope.is_none())
    );
    let mut reader = top.clone();
    reader.verbs = ScopeAxis::Some(BTreeSet::from(["read".into()]));
    assert!(
        vault
            .records_in_scope(&selector, &reader, &top, ScopeView::Debug)
            .is_err()
    );
    selector.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(substrate_facet_id(local))]));
    let deleted = vault.delete_records_in_scope(&selector, &top, &top)?;
    assert!(deleted.contains(&local));
    assert!(!deleted.contains(&remote));
    assert!(vault.get(&remote)?.is_some());
    Ok(())
}
#[test]
fn stored_grant_scope_roundtrip_and_bottom_deny_at_existing_doors() -> Result<()> {
    let mut access = crate::access_grant::AccessGrant::companion_profile_read(
        entity(40),
        entity(41),
        entity(42),
        1,
    );
    access.authority_scope = Scope::default();
    let bytes = crate::access_grant::encode_access_grant_body(&access)?;
    let decoded = crate::access_grant::decode_access_grant_body(&bytes)?;
    assert_eq!(decoded.authority_scope, Scope::default());
    assert!(!decoded.allows_companion_profile_read(&entity(40), &entity(41), &entity(42)));
    let mut federation = crate::federation::FederationGrant::new(
        crate::federation::FederationGrantScope::vault(7),
        entity(40),
        crate::federation::FederationGrantRole::Viewer,
        crate::federation::FederationGrantPreset::ReadOnly,
    );
    federation.authority_scope = Scope::default();
    let decoded = crate::federation::decode_federation_grant_body(
        &crate::federation::encode_federation_grant_body(&federation)?,
    )?;
    assert!(!decoded.confers_at(1));
    Ok(())
}
#[test]
fn identity_facet_replay_and_export_use_content_sensitivity_not_export_classification() -> Result<()>
{
    let (_dir, vault) = vault()?;
    let person = entity(43);
    let facet = entity(44);
    let record = crate::companion::CompanionRecord::persona(
        crate::companion::CompanionScope::neutral(),
        person,
        Value::from("persona"),
        crate::companion::CompanionProvenance::new(
            person,
            crate::EdgeActorClass::Human,
            crate::ClaimSource::UserStated,
            crate::ClaimApprovalStatus::Approved,
            Value::from("owner"),
        ),
        Sensitivity::Private,
    );
    vault.create_companion_record(&facet, &record, 10)?;
    assert_eq!(vault.get_entity_type(&facet)?, Some(ENTITY_TYPE_FACET));
    assert_eq!(vault.get_entity_type(&person)?, Some(ENTITY_TYPE_PERSON));
    let raw = vault.get(&facet)?.expect("fixture");
    let (_dir2, replayed) = self::vault()?;
    replayed
        .batch()
        .put_replicated(&facet, ENTITY_TYPE_FACET, AT, 10, &raw[..])
        .commit()?;
    assert_eq!(
        replayed.get_companion_record(&facet)?,
        vault.get_companion_record(&facet)?
    );
    assert_eq!(replayed.get_entity_type(&person)?, Some(ENTITY_TYPE_PERSON));
    let register = vault.companion_register()?;
    let expressions = crate::companion::CompanionExpressionRegister::new();
    let mut channel = Scope::top();
    channel.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Public);
    assert!(
        crate::batch::export::companion_export_layer(&register, &expressions, &channel).is_empty()
    );
    channel.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Private);
    assert_eq!(
        crate::batch::export::companion_export_layer(&register, &expressions, &channel).len(),
        1
    );
    Ok(())
}

fn owner_actor(vault: &Vault) -> crate::WriteActor {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    crate::WriteActor::new(owner, crate::EdgeActorClass::Human)
}

fn put_facet(vault: &Vault, facet: EntityId) -> Result<()> {
    vault.put_entity(&facet, ENTITY_TYPE_FACET, AT, 10, b"facet")
}

#[test]
fn default_facet_is_the_owner_substrate_facet_until_set() -> Result<()> {
    let (_dir, vault) = vault()?;
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");

    assert_eq!(vault.default_facet()?, substrate_facet_id(owner));
    Ok(())
}

#[test]
fn set_default_facet_moves_the_default() -> Result<()> {
    let (_dir, vault) = vault()?;
    let facet = entity(41);
    put_facet(&vault, facet)?;
    vault
        .set_default_facet(facet, owner_actor(&vault))
        .expect("the owner sets the default");

    assert_eq!(vault.default_facet()?, facet);
    Ok(())
}

#[test]
fn set_default_facet_refuses_an_id_that_is_not_a_facet() -> Result<()> {
    let (_dir, vault) = vault()?;
    let person = entity(42);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, AT, 10, b"person")?;

    assert!(
        vault
            .set_default_facet(person, owner_actor(&vault))
            .is_err()
    );
    Ok(())
}

#[test]
fn set_default_facet_refuses_a_caller_that_is_not_the_owner() -> Result<()> {
    let (_dir, vault) = vault()?;
    let facet = entity(43);
    put_facet(&vault, facet)?;
    let agent = entity(44);
    vault.put_entity(&agent, ENTITY_TYPE_PERSON, AT, 10, b"agent")?;

    assert!(
        vault
            .set_default_facet(
                facet,
                crate::WriteActor::new(agent, crate::EdgeActorClass::Agent)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn fork_to_facet_births_a_claim_under_the_new_facet() -> Result<()> {
    let (_dir, vault) = vault()?;
    let owner = owner_actor(&vault);
    let facet = entity(45);
    put_facet(&vault, facet)?;
    let claim = entity(46);
    let mut origin = ClaimBody::new(
        "test.fork",
        ClaimSubject::Entity(owner.entity_ref()),
        Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    origin.scope_facet = vault.default_facet()?;
    vault.put_claim(&claim, &origin, AT, 10)?;
    let fork = vault
        .fork_to_facet(claim, facet, true, owner)
        .expect("the owner forks the claim");

    assert_eq!(vault.get_claim(&fork)?.expect("fork").scope_facet, facet);
    Ok(())
}
