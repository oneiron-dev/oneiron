//! A named agent's PERSON (the principal `Vault::ensure_agent_principal`
//! derives from its name: `oneiron token agent`, an OAuth client's sign-in)
//! stands as an agent principal under a live owner Grant listing the work's
//! verb, as the Grant mint already admits it as a holder (Engine RULING
//! LEARN-NAMED-AGENT = A, 12 Nov 06:15; FIX 20232). The Grant checks are
//! unchanged: the same PERSON with no Grant, or with a Grant that lists
//! another verb, is refused, and an ordinary PERSON acting as an agent is
//! never an agent principal.
//!
//! The public verb is `vault.free_time.policy.set_as`, whose door asks
//! `principal_standing_or_lapse_in_txn` for the caller and then the engine
//! writer checks the Grant again. The request clears a policy never set on
//! a fresh agent id: the smallest call that crosses both checks.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const VERB: &str = "vault.free_time.policy.set_as";
/// The verb the agent's Grant lists to name the free-time policy act.
const GRANT_VERB: &str = "free_time_policy_set";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (_, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    Fixture {
        vault,
        _dir: dir,
        owner_proof,
    }
}

/// The owner's Grant naming `agent` and listing `verb`. A Grant confers
/// only with `read` among its verbs (`AgentGrantMintRequest`).
fn grant_request(agent: EntityId, verb: &str) -> AgentGrantMintRequest {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), verb.to_owned()]));
    AgentGrantMintRequest {
        agent,
        authority_scope,
        expires_at: None,
        repo_bounds: None,
        verb_classes: BTreeSet::new(),
        wallet_ref: None,
        working_view_bounds: None,
        check_in_ref: None,
    }
}

fn mint(fixture: &Fixture, agent: EntityId, verb: &str) {
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        grant_request(agent, verb),
    )
    .expect("owner mints the named agent a Grant");
    assert!(
        minted.grant.confers,
        "agent={agent:?} verb={verb}; expected the owner's Grant to confer; seen {minted:?}"
    );
}

/// Clears the free-time policy of a fresh agent id, one never set: the
/// door's standing check and the writer's Grant check run, nothing moves.
fn clear_as(fixture: &Fixture, actor: EntityId) -> MemoryResult<Value> {
    invoke(
        &fixture.vault.memory(actor, EdgeActorClass::Agent),
        VERB,
        json!({"agent": EntityId::now().to_hex(), "expected_revision": 0}),
    )
}

fn assert_forbidden(seen: MemoryResult<Value>, why: &str) {
    match seen {
        Err(error) => assert_eq!(
            error.code, MEMORY_CODE_FORBIDDEN,
            "{why}; expected FORBIDDEN; seen {error:?}"
        ),
        Ok(view) => panic!("{why}; expected FORBIDDEN; seen admitted {view}"),
    }
}

/// A named agent's PERSON with no Grant is refused; once the owner grants it
/// the verb, the same PERSON stands and the act runs. Main refuses it here
/// even with the Grant: its agent rule knows agent definitions and base
/// agent machines only.
#[test]
fn named_agent_person_stands_under_its_owner_grant() {
    let fixture = fixture();
    let named = fixture
        .vault
        .ensure_agent_principal("standing-granted-agent")
        .expect("named agent principal");
    assert_forbidden(
        clear_as(&fixture, named),
        &format!("actor=named agent {named:?} with no Grant"),
    );

    mint(&fixture, named, GRANT_VERB);
    let view = clear_as(&fixture, named).unwrap_or_else(|error| {
        panic!(
            "actor=named agent {named:?} with a live owner Grant listing {GRANT_VERB}; expected the act to run; seen {error:?}"
        )
    });
    assert_eq!(
        (view["state"].clone(), view["revision"].clone()),
        (json!("disabled"), json!(0)),
        "actor=named agent {named:?}; expected the clear of an unset policy to answer disabled at revision 0; seen {view}"
    );
}

/// The Grant checks stay: a named agent's Grant that lists another verb
/// gives it no standing for this one.
#[test]
fn named_agent_person_with_a_grant_for_another_verb_is_refused() {
    let fixture = fixture();
    let named = fixture
        .vault
        .ensure_agent_principal("standing-other-verb-agent")
        .expect("named agent principal");
    mint(&fixture, named, "drafter_read");
    assert_forbidden(
        clear_as(&fixture, named),
        &format!("actor=named agent {named:?} with a Grant listing drafter_read only"),
    );
}

/// An ordinary PERSON with a `name` acting as an agent is no named agent: it
/// gets no Grant and no standing.
#[test]
fn ordinary_person_acting_as_agent_is_refused() {
    let fixture = fixture();
    let ordinary = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({"name": "standing-ordinary-person"}))
        .expect("ordinary PERSON body");
    fixture
        .vault
        .put_entity(
            &ordinary,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .expect("an ordinary PERSON whose id is not derived from its name");
    assert!(
        mint_agent_grant_as(
            &fixture.vault,
            &fixture.owner_proof,
            ActSurface::ThisInstall,
            grant_request(ordinary, GRANT_VERB),
        )
        .is_err(),
        "actor=ordinary PERSON {ordinary:?}; expected the owner's Grant mint to refuse a person that is no agent"
    );
    assert_forbidden(
        clear_as(&fixture, ordinary),
        &format!("actor=ordinary PERSON {ordinary:?} acting as an agent"),
    );
}
