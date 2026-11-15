//! The topology-judgment branches `derive_links` leaves unrun (FIX-LIST 23228):
//! an applied judgment, an unread participant, a revoked, expired or another
//! agent's Grant, and a judgment the ledger's transition table refuses. Each
//! test commits a distinct assertion on the parked-proposal fixture's shape.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_topology_branches`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::authority::ActSurface;
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::identity_topology::{StoredIdentityOpAction, distinct_pair_key};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Derived, Distinct, commit, define_auto_agent, expire_agent_grant, grant_derive_rows,
    grant_topology_seal, source_version,
};
use oneiron::test_doors::steward::{dreamer, owner};
use oneiron::verbs::{AgentGrantRevokeRequest, revoke_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault};

const READER: &str = "reader";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    dreamer: EntityId,
    person: EntityId,
}

/// A vault with the Dreamer and one person.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
    }
}

/// An agent with landing and read rows and its own live `topology_seal`
/// Grant; the agent and the Grant.
fn agent_with_grant(fixture: &Fixture) -> (EntityId, EntityId) {
    let agent = define_auto_agent(&fixture.vault).expect("an agent");
    grant_derive_rows(&fixture.vault, &[agent]).expect("the agent's landing and read rows");
    let grant = grant_topology_seal(&fixture.vault, agent).expect("the agent's topology grant");
    (agent, grant)
}

fn distinct(a: EntityId, b: EntityId, grant: EntityId, apply: bool) -> Derived {
    Derived::Distinct(Distinct {
        local: "distinct",
        a,
        b,
        grant,
        apply,
    })
}

fn commit_one(
    fixture: &Fixture,
    agent: EntityId,
    item: Derived,
) -> (bool, Vec<EntityId>, Vec<String>) {
    let committed = commit(
        &fixture.vault,
        agent,
        EdgeActorClass::Agent,
        "run-topology",
        &[item],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    (item.landed, item.rows.clone(), item.reasons.clone())
}

#[test]
fn an_agent_with_its_own_topology_grant_applies_a_judgment() {
    let fixture = fixture();
    let other = put(&fixture.vault, ENTITY_TYPE_PERSON, b"someone else");
    let (agent, grant) = agent_with_grant(&fixture);
    let committed = commit(
        &fixture.vault,
        agent,
        EdgeActorClass::Agent,
        "run-topology-apply",
        &[distinct(fixture.person, other, grant, true)],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the judgment applies: {:?}", item.reasons);
    assert_eq!(item.approval.as_deref(), Some("auto"));
    let [event] = item.rows.as_slice() else {
        panic!("one applied event: {:?}", item.rows);
    };
    let stored = fixture
        .vault
        .identity_topology_event(event)
        .expect("read the event")
        .expect("the applied event");
    assert_eq!(stored.source, ClaimSource::Generated);
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    let StoredIdentityOpAction::AssertDistinct { a, b, .. } = stored.action else {
        panic!("a distinct assertion: {:?}", stored.action);
    };
    assert_eq!((a, b), distinct_pair_key(fixture.person, other));
}

#[test]
fn an_agent_lands_no_judgment_over_a_participant_it_does_not_read() {
    let fixture = fixture();
    let (agent, grant) = agent_with_grant(&fixture);
    let mut body = ClaimBody::new(
        "preference.coffee",
        ClaimSubject::Entity(fixture.person),
        rmpv::Value::from("a black filter coffee"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::Observed);
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("principal"),
        rmpv::Value::Binary(fixture.dreamer.as_bytes().to_vec()),
    )]));
    let unread = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_claim(&unread, &body, TimeRange { start: at, end: at }, at)
        .expect("a claim for the Dreamer alone");
    assert!(
        source_version(&fixture.vault, agent, EdgeActorClass::Agent, unread)
            .expect("the agent's read")
            .is_none()
    );
    let missing = EntityId::now();
    let committed = commit(
        &fixture.vault,
        agent,
        EdgeActorClass::Agent,
        "run-topology-unread",
        &[
            Derived::Distinct(Distinct {
                local: "unread_pair",
                a: unread,
                b: fixture.person,
                grant,
                apply: false,
            }),
            Derived::Distinct(Distinct {
                local: "missing_pair",
                a: fixture.person,
                b: missing,
                grant,
                apply: false,
            }),
        ],
    )
    .expect("commit");
    let [unread_pair, missing_pair] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    for item in [unread_pair, missing_pair] {
        assert!(!item.landed);
        assert!(item.rows.is_empty());
        assert_eq!(
            item.reasons,
            vec!["gate.deny.derive.topology_unread".to_owned()]
        );
    }
}

#[test]
fn an_agent_lands_no_judgment_on_another_agents_grant() {
    let fixture = fixture();
    let other = put(&fixture.vault, ENTITY_TYPE_PERSON, b"someone else");
    let holder = define_auto_agent(&fixture.vault).expect("the holding agent");
    let actor = define_auto_agent(&fixture.vault).expect("the acting agent");
    grant_derive_rows(&fixture.vault, &[holder, actor]).expect("the agents' landing and read rows");
    let grant = grant_topology_seal(&fixture.vault, holder).expect("the holder's topology grant");
    let (landed, rows, reasons) = commit_one(
        &fixture,
        actor,
        distinct(fixture.person, other, grant, false),
    );
    assert!(!landed);
    assert!(rows.is_empty());
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.topology_needs_grant".to_owned()]
    );
}

#[test]
fn an_agent_lands_no_judgment_on_a_revoked_grant() {
    let fixture = fixture();
    let other = put(&fixture.vault, ENTITY_TYPE_PERSON, b"someone else");
    let (agent, grant) = agent_with_grant(&fixture);
    let owner_proof = owner(&fixture.vault).expect("the embedded owner");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: grant,
            seen: None,
        },
    )
    .expect("the owner's revoke");
    assert!(revoked.changed, "the revoke lands: {revoked:?}");
    let (landed, rows, reasons) = commit_one(
        &fixture,
        agent,
        distinct(fixture.person, other, grant, false),
    );
    assert!(!landed);
    assert!(rows.is_empty());
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.topology_needs_grant".to_owned()]
    );
}

#[test]
fn an_agent_lands_no_judgment_on_an_expired_grant() {
    let fixture = fixture();
    let other = put(&fixture.vault, ENTITY_TYPE_PERSON, b"someone else");
    let (agent, grant) = agent_with_grant(&fixture);
    expire_agent_grant(&fixture.vault, grant).expect("the grant expires");
    let (landed, rows, reasons) = commit_one(
        &fixture,
        agent,
        distinct(fixture.person, other, grant, false),
    );
    assert!(!landed);
    assert!(rows.is_empty());
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.topology_needs_grant".to_owned()]
    );
}

#[test]
fn an_agent_lands_no_judgment_the_transition_table_refuses() {
    let fixture = fixture();
    let (agent, grant) = agent_with_grant(&fixture);
    let (landed, rows, reasons) = commit_one(
        &fixture,
        agent,
        distinct(fixture.person, fixture.person, grant, false),
    );
    assert!(!landed);
    assert!(rows.is_empty());
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.topology_rejected".to_owned()]
    );
}
