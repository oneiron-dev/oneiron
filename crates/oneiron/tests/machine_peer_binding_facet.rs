//! A MACHINE's actor bookkeeping lands in the vault default facet (FIX 23050,
//! PRIVACY-02's Dreamer summary landing). #7017 gave the actor-stamp token
//! that facet; the `actor.peer_binding` claim still took `ClaimBody::new`'s
//! subject-substrate facet, which no row holds for a MACHINE, so the Dreamer's
//! first authored document write was refused with "invalid active facet ...
//! resolved type None, expected FACET (13)".
#![cfg(feature = "test-support")]

use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_doc::{DocAuthorization, TextField};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_MACHINE};
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::typed_body::TypedBodyWriter;
use oneiron::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};
use oneiron::{
    ClaimBody, ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    (directory, vault)
}

fn authenticated_owner(vault: &Vault) -> (WriteActor, AuthenticatedOwner) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (WriteActor::new(owner, EdgeActorClass::Human), proof)
}

fn text_asset(vault: &Vault) -> EntityId {
    let entity = EntityId::now();
    vault
        .put_entity(
            &entity,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 7, end: 7 },
            9,
            b"actor bookkeeping fixture",
        )
        .expect("text asset");
    entity
}

fn actor_claims(vault: &Vault, actor: WriteActor, predicate: &str) -> Vec<ClaimBody> {
    vault
        .claims_for_subject(&actor.entity_ref())
        .expect("actor claim ids")
        .into_iter()
        .map(|id| {
            vault
                .get_claim(&id)
                .expect("claim read")
                .expect("stored claim")
        })
        .filter(|body| body.predicate == predicate)
        .collect()
}

/// Exactly one `predicate` claim on `actor`, in `facet`.
fn assert_claim_facet(vault: &Vault, actor: WriteActor, predicate: &str, facet: EntityId) {
    let claims = actor_claims(vault, actor, predicate);
    assert_eq!(claims.len(), 1, "one {predicate} claim");
    assert_eq!(claims[0].subject, ClaimSubject::Entity(actor.entity_ref()));
    assert_eq!(claims[0].scope_facet, facet, "{predicate} claim facet");
}

/// At least one `predicate` claim on `actor`, every one in `facet`.
fn assert_claims_in_facet(vault: &Vault, actor: WriteActor, predicate: &str, facet: EntityId) {
    let claims = actor_claims(vault, actor, predicate);
    assert!(!claims.is_empty(), "at least one {predicate} claim");
    for claim in &claims {
        assert_eq!(claim.subject, ClaimSubject::Entity(actor.entity_ref()));
        assert_eq!(claim.scope_facet, facet, "{predicate} claim facet");
    }
}

#[test]
fn dreamer_migration_lands_stamp_and_peer_binding_in_default_facet() {
    let (_directory, vault) = fresh_vault();
    let dreamer = vault.dreamer_authority().expect("Dreamer authority");
    assert_eq!(
        vault
            .get_entity_type(&dreamer.entity_ref())
            .expect("actor type"),
        Some(ENTITY_TYPE_MACHINE)
    );
    let (_, owner) = authenticated_owner(&vault);
    let default_facet = vault.default_facet().expect("vault default facet");
    let entity = text_asset(&vault);

    // Migration attributes the birth to the Dreamer, with owner authorization.
    // It mints the Dreamer's stamp token, then binds the document peer.
    vault
        .migrate_entity_text(
            &entity,
            &TextField::Utf8Body,
            dreamer,
            &DocAuthorization::Owner(&owner),
        )
        .expect("Dreamer MACHINE migration must land");

    assert_claim_facet(&vault, dreamer, "actor.stamp_token", default_facet);
    assert_claims_in_facet(&vault, dreamer, "actor.peer_binding", default_facet);
}

#[test]
fn dreamer_machine_peer_binding_uses_vault_default_facet() {
    let (_directory, vault) = fresh_vault();
    let dreamer = vault.dreamer_authority().expect("Dreamer authority");
    let default_facet = vault.default_facet().expect("vault default facet");
    let entity = text_asset(&vault);
    let made_by = MadeBy {
        inputs: Vec::new(),
        process: MadeByProcess {
            actor: dreamer.entity_ref(),
            class: MadeByClass::Concluded,
            identity: "machine-peer-binding-facet-fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "fixture".to_owned(),
        },
        at: 7,
        trigger: None,
    };

    // Typed-body birth binds its peer without first minting a stamp token.
    vault
        .birth_typed_body(
            &entity,
            TypedBodyWriter {
                schema: "machine-peer-binding-facet.fixture.v1",
                actor: dreamer,
                made_by: &made_by,
            },
            |document| {
                document
                    .get_map("body")
                    .insert("text", "fixture")
                    .expect("body edit");
                Ok(())
            },
        )
        .expect("Dreamer MACHINE peer binding must land");

    assert_claim_facet(&vault, dreamer, "actor.peer_binding", default_facet);
    assert!(actor_claims(&vault, dreamer, "actor.stamp_token").is_empty());
}

/// Control, green before and after: a PERSON's bookkeeping keeps its own
/// substrate facet, which on a fresh vault is the owner's default facet.
#[test]
fn owner_person_stamp_still_uses_vault_default_facet() {
    let (_directory, vault) = fresh_vault();
    let (actor, owner) = authenticated_owner(&vault);
    let default_facet = vault.default_facet().expect("vault default facet");
    let entity = text_asset(&vault);

    vault
        .migrate_entity_text(
            &entity,
            &TextField::Utf8Body,
            actor,
            &DocAuthorization::Owner(&owner),
        )
        .expect("owner PERSON stamp must still land");

    assert_claim_facet(&vault, actor, "actor.stamp_token", default_facet);
}
