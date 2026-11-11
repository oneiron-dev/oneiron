//! Identity-link items of a derivation batch (untangle 6.7b, decision C-4):
//! a SameAs lands as its proposed coreference status claim, and its edge is
//! applied only under the owner's standing nightly-link grant; a topology
//! judgment needs the agent's own `topology_seal` Grant.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_links`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    default_project_id,
};
use oneiron::identity_topology::{StoredIdentityOpAction, distinct_pair_key};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Distinct, Named, SameAs, claim_lifecycle, commit, commit_claims,
    define_auto_agent, grant_derive_rows, grant_topology_seal, mint_nightly_links,
    narrow_steward_grant_to_project, same_as_edge, source_version,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

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
    first: EntityId,
    second: EntityId,
}

/// A vault whose Dreamer landed two claims about one person, each citing a
/// TURN.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    let turn = put(&vault, ENTITY_TYPE_TURN, &body);
    let claim = |local, value| Claim {
        local,
        predicate: "preference.coffee",
        subject: Named::Stored(person),
        value: json!(value),
        evidence: vec![Named::Stored(turn)],
    };
    let committed = commit_claims(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-claims",
        &[
            claim("first", "an oat milk flat white"),
            claim("second", "a flat white with oat milk"),
        ],
    )
    .expect("the claims commit");
    let [first, second] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    assert!(first.landed && second.landed, "{:?}", committed.items);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        first: first.rows[0],
        second: second.rows[0],
    }
}

fn commit_one(fixture: &Fixture, item: Derived) -> (bool, Vec<EntityId>, Vec<String>) {
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-links",
        &[item],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    (item.landed, item.rows.clone(), item.reasons.clone())
}

fn same_as(source: EntityId, target: EntityId) -> Derived {
    Derived::SameAs(SameAs {
        local: "same_as",
        source: Named::Stored(source),
        target: Named::Stored(target),
    })
}

#[test]
fn the_dreamers_same_as_lands_as_a_proposal() {
    let fixture = fixture();
    let (landed, rows, reasons) = commit_one(&fixture, same_as(fixture.first, fixture.second));
    assert!(landed, "the proposal lands: {reasons:?}");
    let [status] = rows.as_slice() else {
        panic!("one status claim: {rows:?}");
    };
    assert_eq!(
        claim_lifecycle(&fixture.vault, *status).expect("read"),
        Some("active".to_owned())
    );
    assert!(
        !same_as_edge(&fixture.vault, fixture.first, fixture.second).expect("read"),
        "no grant applies the edge"
    );
}

#[test]
fn the_owners_nightly_link_grant_applies_the_dreamers_same_as() {
    let fixture = fixture();
    mint_nightly_links(&fixture.vault).expect("the owner's grant");
    let (landed, _, reasons) = commit_one(&fixture, same_as(fixture.first, fixture.second));
    assert!(landed, "the proposal lands: {reasons:?}");
    assert!(
        same_as_edge(&fixture.vault, fixture.first, fixture.second).expect("read"),
        "the owner's grant applies the edge"
    );
}

#[test]
fn a_same_as_joins_two_claims() {
    let fixture = fixture();
    let (landed, _, reasons) = commit_one(&fixture, same_as(fixture.first, fixture.person));
    assert!(!landed);
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.same_as_not_claims".to_owned()]
    );
}

#[test]
fn an_agent_that_reads_both_claims_lands_a_same_as_proposal() {
    let fixture = fixture();
    mint_nightly_links(&fixture.vault).expect("the owner's grant");
    let agent = define_auto_agent(&fixture.vault).expect("an agent");
    grant_derive_rows(&fixture.vault, &[agent]).expect("the agent's landing and read rows");
    let committed = commit(
        &fixture.vault,
        agent,
        EdgeActorClass::Agent,
        "run-agent-link",
        &[same_as(fixture.first, fixture.second)],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the proposal lands: {:?}", item.reasons);
    assert!(item.reasons.is_empty());
    let [status] = item.rows.as_slice() else {
        panic!("one status claim: {:?}", item.rows);
    };
    assert_eq!(
        claim_lifecycle(&fixture.vault, *status).expect("read"),
        Some("active".to_owned())
    );
    assert!(
        !same_as_edge(&fixture.vault, fixture.first, fixture.second).expect("read"),
        "the owner's grant names the Dreamer, not this agent"
    );
}

#[test]
fn an_agent_lands_no_same_as_to_a_claim_it_does_not_read() {
    let fixture = fixture();
    let agent = define_auto_agent(&fixture.vault).expect("an agent");
    grant_derive_rows(&fixture.vault, &[agent]).expect("the agent's landing and read rows");
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
    assert_eq!(
        claim_lifecycle(&fixture.vault, unread).expect("read"),
        Some("active".to_owned())
    );
    assert!(
        source_version(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            unread
        )
        .expect("the Dreamer's read")
        .is_some()
    );
    assert!(
        source_version(&fixture.vault, agent, EdgeActorClass::Agent, fixture.first)
            .expect("the agent's read")
            .is_some()
    );
    assert!(
        source_version(&fixture.vault, agent, EdgeActorClass::Agent, unread)
            .expect("the agent's read")
            .is_none()
    );
    let committed = commit(
        &fixture.vault,
        agent,
        EdgeActorClass::Agent,
        "run-agent-unread-link",
        &[
            Derived::SameAs(SameAs {
                local: "unread_target",
                source: Named::Stored(fixture.first),
                target: Named::Stored(unread),
            }),
            Derived::SameAs(SameAs {
                local: "unread_source",
                source: Named::Stored(unread),
                target: Named::Stored(fixture.first),
            }),
        ],
    )
    .expect("commit");
    let [unread_target, unread_source] = committed.items.as_slice() else {
        panic!("two items: {:?}", committed.items);
    };
    for item in [unread_target, unread_source] {
        assert!(!item.landed);
        assert!(item.rows.is_empty());
        assert_eq!(
            item.reasons,
            vec!["gate.deny.derive.same_as_not_claims".to_owned()]
        );
    }
    assert!(!same_as_edge(&fixture.vault, fixture.first, unread).expect("read"));
    assert!(!same_as_edge(&fixture.vault, unread, fixture.first).expect("read"));
}

#[test]
fn the_dreamer_lands_no_same_as_to_a_claim_outside_its_narrowed_grant() {
    let fixture = fixture();
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
    body.scope_project = EntityId::now();
    let outside = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_claim(&outside, &body, TimeRange { start: at, end: at }, at)
        .expect("a live claim in another project");
    assert!(
        source_version(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            outside
        )
        .expect("the Dreamer's full read")
        .is_some()
    );
    let grant = stand_steward_grant(&fixture.vault, fixture.dreamer, &STEWARD_VERBS)
        .expect("the Dreamer's Steward grant");
    narrow_steward_grant_to_project(&fixture.vault, grant, default_project_id())
        .expect("the grant held to the fixture's project");
    assert!(
        source_version(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            fixture.first
        )
        .expect("the Dreamer's narrowed read")
        .is_some()
    );
    assert!(
        source_version(
            &fixture.vault,
            fixture.dreamer,
            EdgeActorClass::System,
            outside
        )
        .expect("the Dreamer's narrowed read")
        .is_none()
    );
    let (landed, rows, reasons) = commit_one(&fixture, same_as(fixture.first, outside));
    assert!(!landed);
    assert!(rows.is_empty());
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.same_as_not_claims".to_owned()]
    );
    assert!(!same_as_edge(&fixture.vault, fixture.first, outside).expect("read"));
}

#[test]
fn a_topology_judgment_needs_the_agents_own_grant() {
    let fixture = fixture();
    let other = put(&fixture.vault, ENTITY_TYPE_PERSON, b"someone else");
    let (landed, _, reasons) = commit_one(
        &fixture,
        Derived::Distinct(Distinct {
            local: "distinct",
            a: fixture.person,
            b: other,
            grant: EntityId::now(),
            apply: false,
        }),
    );
    assert!(!landed);
    assert_eq!(
        reasons,
        vec!["gate.deny.derive.topology_needs_grant".to_owned()]
    );
}

#[test]
fn an_agent_with_its_own_topology_grant_lands_a_judgment_as_a_proposal() {
    let fixture = fixture();
    let other = put(&fixture.vault, ENTITY_TYPE_PERSON, b"someone else");
    let agent = define_auto_agent(&fixture.vault).expect("an agent");
    grant_derive_rows(&fixture.vault, &[agent]).expect("the agent's landing and read rows");
    let grant = grant_topology_seal(&fixture.vault, agent).expect("the agent's topology grant");
    let committed = commit(
        &fixture.vault,
        agent,
        EdgeActorClass::Agent,
        "run-topology",
        &[Derived::Distinct(Distinct {
            local: "distinct",
            a: fixture.person,
            b: other,
            grant,
            apply: false,
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the proposal lands: {:?}", item.reasons);
    assert!(item.reasons.is_empty());
    let [proposal] = item.rows.as_slice() else {
        panic!("one proposal event: {:?}", item.rows);
    };
    let event = fixture
        .vault
        .identity_topology_event(proposal)
        .expect("read the proposal")
        .expect("the proposal event");
    assert_eq!(event.source, ClaimSource::Generated);
    assert_eq!(event.approval, ClaimApprovalStatus::Proposed);
    let StoredIdentityOpAction::AssertDistinct { a, b, .. } = event.action else {
        panic!("a distinct assertion: {:?}", event.action);
    };
    assert_eq!((a, b), distinct_pair_key(fixture.person, other));
}

#[test]
fn an_agent_with_no_topology_grant_lands_no_judgment() {
    let fixture = fixture();
    let other = put(&fixture.vault, ENTITY_TYPE_PERSON, b"someone else");
    let agent = define_auto_agent(&fixture.vault).expect("an agent");
    grant_derive_rows(&fixture.vault, &[agent]).expect("the agent's landing and read rows");
    let committed = commit(
        &fixture.vault,
        agent,
        EdgeActorClass::Agent,
        "run-topology",
        &[Derived::Distinct(Distinct {
            local: "distinct",
            a: fixture.person,
            b: other,
            grant: EntityId::now(),
            apply: false,
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(!item.landed);
    assert_eq!(
        item.reasons,
        vec!["gate.deny.derive.topology_needs_grant".to_owned()]
    );
}
