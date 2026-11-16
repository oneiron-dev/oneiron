//! The owner's agent Grants confer only on their counted mint (pass 28 R3).
//!
//! A FEDERATION_GRANT row gives nothing by itself: a row no counted mint gives names no
//! `ai.*` operation, deletes nothing and shows in the owner's consent registry as revoked,
//! and a minted row widened in place stands for nothing until the owner mints the wider
//! terms. The honest mint keeps its standing and its delete, and a revoked Grant's row put
//! back stays revoked.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test agent_grant_standing`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::{
    AuthenticatedOwner, ConsentGrantStatus, ConsentRegistryQuery, ConsentRegistryRow,
};
use oneiron::federation::{FederationGrant, Scope, ScopeAxis, decode_federation_grant_body};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// A device vault whose live install profile carries the owner's acts.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let keystore = Arc::new(MemoryKeystore::default());
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
    }
}

fn ai_scope(verbs: &[&str]) -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    scope
}

/// The owner mints `agent` an agent Grant over `verbs`; its id.
fn mint(fixture: &Fixture, agent: EntityId, verbs: &[&str]) -> EntityId {
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: ai_scope(verbs),
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner mints the agent Grant");
    EntityId::from_hex(&minted.grant.grant_ref).expect("Grant id hex")
}

/// The Grant row `id` as it is stored now.
fn row(vault: &Vault, id: EntityId) -> FederationGrant {
    let body = vault
        .get(&id)
        .expect("grant read")
        .expect("a live Grant row");
    decode_federation_grant_body(&body).expect("the Grant row decodes")
}

fn ai_operations(vault: &Vault, agent: EntityId) -> BTreeSet<String> {
    vault
        .agent_ai_operations(agent)
        .expect("the agent's ai operations")
}

fn registry_rows(vault: &Vault, agent: EntityId, include_revoked: bool) -> Vec<ConsentRegistryRow> {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, include_revoked))
        .expect("the owner's consent registry")
        .rows
        .into_iter()
        .filter(|row| {
            row.agent_grant
                .as_ref()
                .is_some_and(|grant| grant.agent == agent)
        })
        .collect()
}

fn named_agent(vault: &Vault, name: &str) -> EntityId {
    vault
        .ensure_agent_principal(name)
        .expect("a named agent principal")
}

/// An enabled, active agent definition the owner creates: an agent that calls verbs.
fn defined_agent(fixture: &Fixture, agent_id: &str) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Agent Grant standing test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("the owner creates an enabled, active agent definition");
    agent
}

/// A NOTE the owner writes about a fresh person, by its full hex ref.
fn owner_note(fixture: &Fixture) -> String {
    let subject = EntityId::now();
    fixture
        .vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .author_take(TakeTarget::Subject(subject), "a take about the subject")
        .expect("the owner authors a NOTE")
        .id_hex
}

/// `agent` calls the `vault.delete` verb on `note`.
fn agent_deletes(
    vault: &Vault,
    agent: EntityId,
    note: &str,
) -> Result<serde_json::Value, MemoryError> {
    invoke(
        &vault.memory(agent, EdgeActorClass::Agent),
        "vault.delete",
        json!({ "entity_ref": note, "reason": "user_delete" }),
    )
}

fn deleted(vault: &Vault, note: &str) -> bool {
    vault
        .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
        .expect("shell read")
}

/// Puts the honest Grant `template`'s terms for `holder` at a fresh id, with no act: a
/// forged row that passes every check of the row alone.
fn put_bare_copy(vault: &Vault, template: &FederationGrant, holder: EntityId) -> EntityId {
    let mut forged = template.clone();
    forged.member_ref = holder;
    let id = EntityId::now();
    put_unkeyed_member_grant(vault, id, &forged).expect("the bare row lands");
    id
}

#[test]
fn a_bare_agent_grant_row_names_no_ai_operation() {
    let fixture = fixture();
    let yuki = named_agent(&fixture.vault, "yuki");
    let mika = named_agent(&fixture.vault, "mika");
    let honest = mint(&fixture, yuki, &["ai.text"]);
    let template = row(&fixture.vault, honest);
    let forged = put_bare_copy(&fixture.vault, &template, mika);

    let operations = ai_operations(&fixture.vault, mika);
    assert!(
        operations.is_empty(),
        "agent={mika:?} grant={forged:?}; expected a row no counted mint gives to name no ai \
         operation; seen operations={operations:?}"
    );
}

/// Catches a bare agent Grant row conferring delete: the delete authority's agent arm read
/// every live Delegate row naming the agent alone (review of R3a's fix, P2-1).
#[test]
fn a_bare_agent_grant_row_deletes_nothing() {
    let fixture = fixture();
    let yuki = defined_agent(&fixture, "standing_delete_agent");
    let mika = defined_agent(&fixture, "standing_read_agent");
    let honest = mint(&fixture, yuki, &["read", "delete"]);
    mint(&fixture, mika, &["read"]);
    let template = row(&fixture.vault, honest);
    let forged = put_bare_copy(&fixture.vault, &template, mika);
    let note = owner_note(&fixture);

    let refused = agent_deletes(&fixture.vault, mika, &note);
    assert!(
        refused
            .as_ref()
            .is_err_and(|error| error.code == MEMORY_CODE_FORBIDDEN
                && error.message.starts_with("no_delete_grant:")),
        "agent={mika:?} grant={forged:?}; expected a row no counted mint gives to confer no \
         delete; seen {refused:?}"
    );
    assert!(
        !deleted(&fixture.vault, &note),
        "note={note}; expected the refused NOTE untouched"
    );
}

/// Guard: the owner's minted delete Grant still deletes through `vault.delete`.
#[test]
fn a_minted_agent_grant_deletes() {
    let fixture = fixture();
    let yuki = defined_agent(&fixture, "standing_delete_agent");
    let id = mint(&fixture, yuki, &["read", "delete"]);
    let note = owner_note(&fixture);

    let receipt = agent_deletes(&fixture.vault, yuki, &note);
    assert!(
        receipt
            .as_ref()
            .is_ok_and(|receipt| receipt["existed"] == true),
        "agent={yuki:?} grant={id:?}; expected the minted delete Grant to delete; seen \
         {receipt:?}"
    );
    assert!(
        deleted(&fixture.vault, &note),
        "note={note}; expected the NOTE a deleted shell"
    );
}

#[test]
fn a_bare_agent_grant_row_shows_revoked_in_the_registry() {
    let fixture = fixture();
    let yuki = named_agent(&fixture.vault, "yuki");
    let mika = named_agent(&fixture.vault, "mika");
    let honest = mint(&fixture, yuki, &["ai.text"]);
    let template = row(&fixture.vault, honest);
    let forged = put_bare_copy(&fixture.vault, &template, mika);

    let standing = registry_rows(&fixture.vault, mika, false);
    assert!(
        standing.is_empty(),
        "agent={mika:?} grant={forged:?}; expected the standing registry to list no Grant no \
         counted mint gives; seen rows={standing:?}"
    );
    let reviewed = registry_rows(&fixture.vault, mika, true);
    assert!(
        reviewed.len() == 1
            && reviewed[0].status == ConsentGrantStatus::Revoked
            && reviewed[0]
                .agent_grant
                .as_ref()
                .is_some_and(|grant| !grant.confers),
        "agent={mika:?} grant={forged:?}; expected the review to show the bare row once, \
         revoked and conferring nothing, so the owner finds it; seen rows={reviewed:?}"
    );
}

#[test]
fn an_agent_grant_widened_in_place_stands_for_nothing() {
    let fixture = fixture();
    let yuki = named_agent(&fixture.vault, "yuki");
    let id = mint(&fixture, yuki, &["ai.text"]);
    let mut widened = row(&fixture.vault, id);
    widened.authority_scope = ai_scope(&["ai.text", "ai.image"]);
    put_unkeyed_member_grant(&fixture.vault, id, &widened).expect("the widened row lands");

    let operations = ai_operations(&fixture.vault, yuki);
    assert!(
        operations.is_empty(),
        "agent={yuki:?} grant={id:?}; expected a row whose terms are not its mint's to name no \
         ai operation; seen operations={operations:?}"
    );
}

#[test]
fn a_minted_agent_grant_names_its_ai_operation() {
    let fixture = fixture();
    let yuki = named_agent(&fixture.vault, "yuki");
    let id = mint(&fixture, yuki, &["ai.text"]);

    let operations = ai_operations(&fixture.vault, yuki);
    assert_eq!(
        operations,
        BTreeSet::from(["text".to_owned()]),
        "agent={yuki:?} grant={id:?}; expected the honest mint to name ai.text"
    );
    let standing = registry_rows(&fixture.vault, yuki, false);
    assert!(
        standing.len() == 1 && standing[0].status == ConsentGrantStatus::Active,
        "agent={yuki:?} grant={id:?}; expected the registry to list the minted Grant as \
         active; seen rows={standing:?}"
    );
}

#[test]
fn a_revoked_agent_grant_put_back_stays_revoked() {
    let fixture = fixture();
    let yuki = named_agent(&fixture.vault, "yuki");
    let id = mint(&fixture, yuki, &["ai.text"]);
    let saved = row(&fixture.vault, id);
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: id,
            seen: None,
        },
    )
    .expect("the owner revokes the Grant");
    assert!(
        revoked.changed,
        "grant={id:?}; expected the revoke to sign an act"
    );
    put_unkeyed_member_grant(&fixture.vault, id, &saved).expect("the saved row lands again");

    let operations = ai_operations(&fixture.vault, yuki);
    assert!(
        operations.is_empty(),
        "agent={yuki:?} grant={id:?}; expected a row put back after its revoke to name no ai \
         operation; seen operations={operations:?}"
    );
}
