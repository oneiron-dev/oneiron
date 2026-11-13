//! ARCH-0022 #facets (the owner, 2026-09-23): "Every vault has one default
//! facet ... the owner may set another", and "With no active mask, the
//! vault's default facet stamps it" (UNBUILT item 10). The owner sets the
//! default through `vault.settings.default_facet.set` and reads it back
//! through `vault.settings.default_facet`; the next NOTE written with no
//! mask is born under it (its one `facet_of` edge), and a NOTE born earlier
//! keeps its facet. An id that is not a stored FACET, and a caller other
//! than the owner, are refused with nothing written. A change records the
//! owner's act, and a set that changes nothing records none. The default
//! survives a reopen, and the owner can set the first default back. An
//! agent reads it only while it holds an `engine.controls` class, and never
//! sets it.
//!
//! Every door is reached by its verb name and every read through a public
//! door that main already has, so this file builds on a tree without the
//! doors and fails there at the first verb call.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test default_facet_owner_door`.
#![cfg(oneiron_test_support)]

use std::path::Path;

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, coach, define_agent};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, open_owner_carrier_vault, stand_steward_grant,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

const READ: &str = "vault.settings.default_facet";
const SET: &str = "vault.settings.default_facet.set";
/// The owner act's setting name (`PolicySetting::as_str`).
const SETTING: &str = "settings.default_facet";
const LEARNED_AT: u64 = 1_780_000_000;

/// Opens the vault this process owns (the writer lease), as an embedded
/// host does at each start, so the owner's handle carries the owner's proof.
fn open_owned(path: &Path) -> (Vault, EntityId) {
    let vault = Vault::open_owned(path, VaultConfig::device()).expect("an owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    (vault, owner)
}

fn call(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    input: Value,
) -> MemoryResult<Value> {
    invoke(&vault.memory(actor, class), verb, input)
}

/// The verb's answer naming `facet`.
fn answer(facet: EntityId) -> Value {
    json!({ "facet": facet.to_hex() })
}

/// The owner's acts on this setting, as this install recorded them.
fn default_facet_acts(vault: &Vault) -> usize {
    vault
        .policy_setting_acts()
        .expect("the owner's setting acts")
        .iter()
        .filter(|receipt| receipt.setting.as_str() == SETTING)
        .count()
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

/// A NOTE the owner writes with no mask.
fn owner_note(vault: &Vault, owner: EntityId, text: &str) -> EntityId {
    vault
        .create_note(
            "research",
            text,
            WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the owner's NOTE")
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

/// The owner reads the first default, sets a work facet, and the next NOTE
/// is born under it while an earlier NOTE keeps its facet; refused sets
/// write and record nothing; the default and the owner's act survive a
/// reopen; the owner sets the first default back.
#[test]
fn the_owner_sets_the_default_facet_and_the_next_note_is_born_under_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = open_owned(dir.path());
    let human = EdgeActorClass::Human;
    let first = vault.default_facet().expect("the first default facet");

    // Unset: the owner's substrate facet. On a tree without the door, the
    // test fails here.
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads the default");
    assert_eq!(read, answer(first), "unset reads as the owner's substrate");
    let before = owner_note(&vault, owner, "a note before the set");
    assert_eq!(facets_of(&vault, before), [first]);
    assert_eq!(default_facet_acts(&vault), 0);

    // The owner makes a work facet the default: the next NOTE is born under
    // it, and the earlier NOTE keeps its facet.
    let work = put_facet(&vault, "work");
    let set = call(&vault, owner, human, SET, answer(work)).expect("the owner sets work");
    assert_eq!(set, answer(work));
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads it back");
    assert_eq!(read, answer(work));
    assert_eq!(vault.default_facet().expect("the default"), work);
    let after = owner_note(&vault, owner, "a note after the set");
    assert_eq!(
        facets_of(&vault, after),
        [work],
        "the next NOTE with no mask is born under the owner's default"
    );
    assert_eq!(
        facets_of(&vault, before),
        [first],
        "an earlier NOTE keeps its facet"
    );
    assert_eq!(
        default_facet_acts(&vault),
        1,
        "the change records the owner's act"
    );

    // Refused: an id that is not a FACET, an id with no row, an id that is
    // not hex, and a caller that is not the owner. Nothing is written or
    // recorded.
    let refused = call(&vault, owner, human, SET, answer(owner))
        .expect_err("the owner's PERSON is not a FACET");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    assert!(refused.message.contains("expected FACET"), "{refused:?}");
    let refused =
        call(&vault, owner, human, SET, answer(EntityId::now())).expect_err("an id with no row");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    call(&vault, owner, human, SET, json!({ "facet": "work" })).expect_err("an id that is not hex");
    let agent = define_agent(&vault).expect("an agent");
    let refused = call(&vault, agent, EdgeActorClass::Agent, SET, answer(first))
        .expect_err("an agent never sets the owner's default facet");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    let refused = call(&vault, agent, EdgeActorClass::Agent, READ, json!({}))
        .expect_err("an agent with no engine.controls class reads nothing");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads");
    assert_eq!(read, answer(work), "a refused set changes nothing");
    assert_eq!(
        default_facet_acts(&vault),
        1,
        "a refused set records nothing"
    );

    // The same facet again changes nothing and records nothing.
    let set = call(&vault, owner, human, SET, answer(work)).expect("the same facet");
    assert_eq!(set, answer(work));
    assert_eq!(
        default_facet_acts(&vault),
        1,
        "an unchanged default records no act"
    );

    // A reopen reads the owner's default and keeps the act.
    drop(vault);
    let (vault, owner) = open_owned(dir.path());
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads after a reopen");
    assert_eq!(read, answer(work), "the default survives a reopen");
    assert_eq!(default_facet_acts(&vault), 1, "the act survives a reopen");

    // The owner sets the first default back: the next NOTE is born under it.
    let set = call(&vault, owner, human, SET, answer(first)).expect("the owner sets it back");
    assert_eq!(set, answer(first));
    let read = call(&vault, owner, human, READ, json!({})).expect("the owner reads");
    assert_eq!(read, answer(first));
    let back = owner_note(&vault, owner, "a note after the set back");
    assert_eq!(facets_of(&vault, back), [first]);
    assert_eq!(default_facet_acts(&vault), 2);
}

/// A holder of any `engine.controls` class reads the default facet, as
/// every dial read is (S66F-READ = C), and is refused once the class is
/// gone. No holder ever sets it: the set is the owner's alone.
#[test]
fn a_holder_of_an_engine_controls_class_reads_the_default_facet_and_never_sets_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let agent = define_agent(&vault).expect("an agent");
    let class = EdgeActorClass::Agent;
    let first = vault.default_facet().expect("the default facet");

    // No grant: refused.
    let refused = call(&vault, agent, class, READ, json!({})).expect_err("no grant");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");

    // One engine.controls class reads the default in force.
    stand_steward_grant(&vault, agent, &[ENGINE_CONTROLS_VERBS[0]]).expect("a class grant");
    let read = call(&vault, agent, class, READ, json!({})).expect("a class holder reads");
    assert_eq!(read, answer(first));

    // The holder never sets it.
    let work = put_facet(&vault, "work");
    let refused =
        call(&vault, agent, class, SET, answer(work)).expect_err("the set is the owner's");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(vault.default_facet().expect("the default"), first);
    assert_eq!(
        default_facet_acts(&vault),
        0,
        "a refused set records nothing"
    );

    // The grant that replaces it names `read` alone: refused at the next read.
    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB]).expect("a read grant");
    let refused = call(&vault, agent, class, READ, json!({}))
        .expect_err("`read` is not an engine.controls class");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
}
