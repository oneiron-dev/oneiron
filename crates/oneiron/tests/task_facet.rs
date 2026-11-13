//! ARCH-0022 #facets (the owner, 2026-09-23): "A record carries its facet as
//! its one outgoing `facet_of` edge, written in the same write as the record
//! ... With no active mask, the vault's default facet stamps it". A TASK held
//! its facet only in its birth stamp (canon #task-facet-not-built, UNBUILT
//! item 10). Now every TASK born here carries the edge, and its stamp names
//! the same facet:
//!
//! - a narrowed writer's TASK is born under the writer's facet, and the
//!   authority facts about it under the same facet;
//! - a vault-wide writer's TASK is born under the vault default (D1 = A), and
//!   after the owner sets another default, the next one under that;
//! - a TASK keeps its birth facet: the edge it carries is admitted again,
//!   while a second facet and a delete of its edge are refused.
//!
//! Every read goes through a public door main already has, so this file
//! builds on main and fails there at the first edge read.
//!
//! `cargo test --locked -p oneiron --all-features --test task_facet`.

use std::collections::BTreeSet;

use oneiron::federation::record_scope::BirthPosition;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_TASK};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const LEARNED_AT: u64 = 1_780_000_000;

/// A default vault this process owns and its embedded owner. The vault
/// closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("an owned vault");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    Fixture {
        vault,
        owner,
        _dir: dir,
    }
}

/// A stored FACET named `name`.
fn put_facet(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name })).expect("a facet body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_FACET,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            &body,
        )
        .expect("a stored FACET");
    id
}

/// A TASK the owner creates through the task door, born at `position`.
fn owner_task(fixture: &Fixture, position: BirthPosition, label: &str) -> EntityId {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_birth_position(position)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some(label.into()),
            Some(fixture.owner),
            Some(fixture.vault.now_recorded_at()),
        ))
        .expect("the task door")
        .task_ref
        .expect("the TASK creation took effect")
}

/// The facets `record`'s outgoing `facet_of` edges name.
fn facets_of(vault: &Vault, record: EntityId) -> Vec<EntityId> {
    vault
        .edges_out(&record)
        .expect("the record's edges")
        .iter()
        .filter(|edge| edge.kind == EdgeKind::FacetOf)
        .map(|edge| edge.target)
        .collect()
}

/// The facets the stored stamp of `record` names.
fn stamp_facets(vault: &Vault, record: EntityId) -> ScopeAxis<ScopeId> {
    vault
        .record_scope(&record)
        .expect("the record's stamp")
        .expect("a stamped record")
        .facets
}

fn only(facet: EntityId) -> ScopeAxis<ScopeId> {
    ScopeAxis::Some(BTreeSet::from([ScopeId(facet)]))
}

/// The TASK rows scoped to `task`: the authority facts about it.
fn authority_facts(vault: &Vault, task: EntityId) -> Vec<EntityId> {
    let tasks = vault
        .entities_by_type(ENTITY_TYPE_TASK)
        .expect("the stored TASKs");
    vault
        .edges_in(&task)
        .expect("the TASK's inbound edges")
        .iter()
        .filter(|edge| edge.kind == EdgeKind::ScopedTo && tasks.contains(&edge.target))
        .map(|edge| edge.target)
        .collect()
}

/// A writer narrowed to a work facet: its TASK is born under that facet, as
/// its edge and its stamp both say, and so is the Owner fact the task door
/// writes beside it.
#[test]
fn a_narrowed_writers_task_and_its_authority_facts_are_born_under_its_facet() {
    let fixture = open();
    let work = put_facet(&fixture.vault, "work");
    let task = owner_task(
        &fixture,
        BirthPosition {
            world: None,
            facet: Some(work),
        },
        "narrowed",
    );

    // On main the stamp alone names the facet: the test fails here.
    assert_eq!(
        facets_of(&fixture.vault, task),
        vec![work],
        "the TASK's one facet_of edge names its writer's facet"
    );
    assert_eq!(stamp_facets(&fixture.vault, task), only(work));

    let facts = authority_facts(&fixture.vault, task);
    assert!(!facts.is_empty(), "the task door writes the Owner fact");
    for fact in facts {
        assert_eq!(
            facets_of(&fixture.vault, fact),
            vec![work],
            "an authority fact is born under its TASK's facet"
        );
        assert_eq!(stamp_facets(&fixture.vault, fact), only(work));
    }
}

/// A vault-wide writer's TASK is born under the vault default (D1 = A). Once
/// the owner sets another default, the next TASK is born under it and the
/// earlier one keeps its facet.
#[test]
fn a_vault_wide_writers_task_is_born_under_the_vault_default() {
    let fixture = open();
    let first = fixture.vault.default_facet().expect("the first default");
    let before = owner_task(&fixture, BirthPosition::default(), "before");

    // On main the TASK carries no edge: the test fails here.
    assert_eq!(
        facets_of(&fixture.vault, before),
        vec![first],
        "a vault-wide writer's TASK is born under the vault default"
    );
    assert_eq!(stamp_facets(&fixture.vault, before), only(first));

    let work = put_facet(&fixture.vault, "work");
    fixture
        .vault
        .set_default_facet(work, WriteActor::new(fixture.owner, EdgeActorClass::Human))
        .expect("the owner sets the default");
    let after = owner_task(&fixture, BirthPosition::default(), "after");
    assert_eq!(facets_of(&fixture.vault, after), vec![work]);
    assert_eq!(stamp_facets(&fixture.vault, after), only(work));
    assert_eq!(
        facets_of(&fixture.vault, before),
        vec![first],
        "a TASK born earlier keeps its facet"
    );
    assert_eq!(stamp_facets(&fixture.vault, before), only(first));
}

/// The `facet_of` table admits a TASK source, so the edge a TASK was born
/// with is admitted again. Its facet never moves: a second facet and a delete
/// of its edge are refused, and the TASK keeps its one edge.
#[test]
fn a_task_keeps_its_birth_facet() {
    let fixture = open();
    let work = put_facet(&fixture.vault, "work");
    let other = put_facet(&fixture.vault, "other");
    let task = owner_task(
        &fixture,
        BirthPosition {
            world: None,
            facet: Some(work),
        },
        "kept",
    );

    // On main the table refuses a TASK source: InvalidFacetOfEdge.
    fixture
        .vault
        .put_edge(&task, EdgeKind::FacetOf, &work, 1.0)
        .expect("the TASK's own birth edge is admitted");

    let moved = fixture
        .vault
        .put_edge(&task, EdgeKind::FacetOf, &other, 1.0)
        .expect_err("a second facet is refused");
    assert!(
        format!("{moved:?}").contains("FacetStampImmutable"),
        "{moved:?}"
    );
    let deleted = fixture
        .vault
        .delete_edge(&task, EdgeKind::FacetOf, &work)
        .expect_err("a delete of the TASK's edge is refused");
    assert!(
        format!("{deleted:?}").contains("FacetStampImmutable"),
        "{deleted:?}"
    );
    assert_eq!(facets_of(&fixture.vault, task), vec![work]);
    assert_eq!(stamp_facets(&fixture.vault, task), only(work));
}
