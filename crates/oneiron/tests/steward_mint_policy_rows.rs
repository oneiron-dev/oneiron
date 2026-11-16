//! Every Steward row of a base agent holds the scope the vault's
//! grant-policy rows resolve for it (RULING REMINT-POLICY-ROWS = A, Engine
//! 13 Nov; FIX row DREAMER-GRANT-REMINT-IGNORES-DATA-AXES, second half).
//!
//! A Steward holder row naming the Dreamer narrows the worlds its first
//! mint and the owner's grant back hold, and a second grant back mints
//! nothing. A holder row that leaves out `delete` holds the grant back to
//! the other three verbs. The Coach keeps its `engine.controls` classes,
//! which no role default names, under a holder row that narrows its worlds
//! and under one that leaves it no `read` (RULING REMINT-POLICY-VERBS = A,
//! Engine 13 Nov 16:22). With no holder row the scope is the Steward
//! default, as before. A row list that resolves no Steward scope stands no
//! default and refuses the grant back.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_mint_policy_rows`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, coach, read_and_engine_controls};
use oneiron::test_doors::steward::{
    GrantMark, STEWARD_VERBS, dreamer, empty_grant_policy_rows, grant_mark,
    open_owner_carrier_vault, owner, steward_reach_scope, write_steward_holder_row,
};

fn verb_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn worlds_of(world: EntityId) -> ScopeAxis<ScopeId> {
    [ScopeId(world)].into_iter().collect()
}

fn minted_verbs(vault: &oneiron::Vault, agent: EntityId) -> BTreeSet<String> {
    match grant_mark(vault, agent).expect("mark") {
        Some(GrantMark::Minted { verbs, .. }) => verbs,
        other => panic!("a grant with verbs stands: {other:?}"),
    }
}

fn reach_scope(vault: &oneiron::Vault, agent: EntityId) -> Scope {
    steward_reach_scope(vault, agent)
        .expect("reach")
        .expect("a Steward row stands")
}

#[test]
fn the_first_mint_holds_the_holder_rows_worlds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let world = EntityId::now();
    write_steward_holder_row(&vault, dreamer, Some(&[world][..]), None).expect("holder row");

    vault.provision_system_agent_grants().expect("first mint");
    assert_eq!(
        minted_verbs(&vault, dreamer),
        verb_set(&STEWARD_VERBS),
        "the shipped rows give the whole default"
    );
    assert_eq!(
        reach_scope(&vault, dreamer).worlds,
        worlds_of(world),
        "the engine's default holds the worlds the owner's holder row gives the Dreamer"
    );
}

#[test]
fn the_grant_back_holds_the_holder_rows_worlds_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let owner = owner(&vault).expect("owner proof");
    vault.provision_system_agent_grants().expect("first mint");
    assert_eq!(
        reach_scope(&vault, dreamer).worlds,
        ScopeAxis::All,
        "no holder row: every world"
    );

    let world = EntityId::now();
    write_steward_holder_row(&vault, dreamer, Some(&[world][..]), None).expect("holder row");
    assert!(
        vault
            .grant_dreamer_weave(&owner, 1)
            .expect("the owner's grant"),
        "the grant back mints at the worlds the holder row gives"
    );
    assert_eq!(
        reach_scope(&vault, dreamer).worlds,
        worlds_of(world),
        "the grant back holds the holder row's worlds"
    );
    assert_eq!(
        minted_verbs(&vault, dreamer),
        verb_set(&STEWARD_VERBS),
        "the whole default's verbs"
    );
    assert!(
        !vault
            .grant_dreamer_weave(&owner, 1)
            .expect("the owner's second grant"),
        "a second grant back mints nothing: no re-mint loop"
    );
}

#[test]
fn with_no_holder_row_the_scope_is_the_steward_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let owner = owner(&vault).expect("owner proof");
    vault.provision_system_agent_grants().expect("first mint");

    let mut default = Scope::top();
    default.verbs = STEWARD_VERBS
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    assert_eq!(
        reach_scope(&vault, dreamer),
        default,
        "every data axis whole, the four Steward verbs"
    );
    assert!(
        !vault
            .grant_dreamer_weave(&owner, 1)
            .expect("the owner's grant"),
        "the grant back over the default mints nothing"
    );
    assert_eq!(reach_scope(&vault, dreamer), default, "unchanged");
}

#[test]
fn a_holder_row_without_delete_holds_the_grant_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let owner = owner(&vault).expect("owner proof");
    vault.provision_system_agent_grants().expect("first mint");
    assert_eq!(minted_verbs(&vault, dreamer), verb_set(&STEWARD_VERBS));

    let three: Vec<&str> = STEWARD_VERBS
        .iter()
        .copied()
        .filter(|verb| *verb != "delete")
        .collect();
    assert_eq!(three.len(), 3, "the Steward verbs name delete");
    write_steward_holder_row(&vault, dreamer, None, Some(three.as_slice())).expect("holder row");
    assert!(
        vault
            .grant_dreamer_weave(&owner, 1)
            .expect("the owner's grant"),
        "the grant back mints at the holder row's verbs"
    );
    assert_eq!(
        minted_verbs(&vault, dreamer),
        verb_set(&three),
        "no delete: the owner's holder row leaves it out"
    );
    assert!(
        !vault
            .grant_dreamer_weave(&owner, 1)
            .expect("the owner's second grant"),
        "a second grant back mints nothing"
    );
}

#[test]
fn the_coach_keeps_its_engine_controls_under_a_holder_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let coach = coach(&vault).expect("the Coach");
    let owner = owner(&vault).expect("owner proof");
    vault.provision_system_agent_grants().expect("first mint");
    assert_eq!(
        minted_verbs(&vault, coach),
        verb_set(&read_and_engine_controls()),
        "the shipped rows: read and the four engine.controls classes"
    );

    let world = EntityId::now();
    write_steward_holder_row(&vault, coach, Some(&[world][..]), None).expect("holder row");
    assert!(
        vault
            .grant_coach_steward(&owner)
            .expect("the owner's grant"),
        "the Coach's grant back mints at the worlds the holder row gives"
    );
    assert_eq!(
        reach_scope(&vault, coach).worlds,
        worlds_of(world),
        "the holder row's worlds"
    );
    assert_eq!(
        minted_verbs(&vault, coach),
        verb_set(&read_and_engine_controls()),
        "the engine.controls classes stay: no role default names them"
    );
    assert!(
        !vault
            .grant_coach_steward(&owner)
            .expect("the owner's second grant"),
        "a second grant back mints nothing"
    );
}

#[test]
fn the_coach_keeps_its_engine_controls_under_a_narrowed_steward_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let coach = coach(&vault).expect("the Coach");
    let owner = owner(&vault).expect("owner proof");
    vault.provision_system_agent_grants().expect("first mint");

    // The owner's row gives the Coach `derive` alone of the four Steward
    // verbs: no `read`.
    write_steward_holder_row(&vault, coach, None, Some(&["derive"][..])).expect("holder row");
    assert!(
        vault
            .grant_coach_steward(&owner)
            .expect("the owner's grant"),
        "the Coach's grant back mints at the holder row's verbs"
    );
    assert_eq!(
        minted_verbs(&vault, coach),
        verb_set(&ENGINE_CONTROLS_VERBS),
        "read goes with the holder row; the four engine.controls classes stay"
    );
    assert!(
        !vault
            .grant_coach_steward(&owner)
            .expect("the owner's second grant"),
        "a second grant back mints nothing"
    );
}

#[test]
fn rows_that_resolve_no_steward_scope_stand_no_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let coach = coach(&vault).expect("the Coach");
    empty_grant_policy_rows(&vault).expect("no grant-policy rows");

    vault
        .provision_system_agent_grants()
        .expect("a refused default never stops the open");
    assert_eq!(
        grant_mark(&vault, dreamer).expect("mark"),
        None,
        "no Dreamer default stands"
    );
    assert_eq!(
        grant_mark(&vault, coach).expect("mark"),
        None,
        "no Coach default stands"
    );
}

#[test]
fn rows_that_resolve_no_steward_scope_refuse_the_grant_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let owner = owner(&vault).expect("owner proof");
    vault.provision_system_agent_grants().expect("first mint");
    let before = grant_mark(&vault, dreamer).expect("mark");
    assert!(
        matches!(before, Some(GrantMark::Minted { .. })),
        "{before:?}"
    );

    empty_grant_policy_rows(&vault).expect("no grant-policy rows");
    let refused = vault.grant_dreamer_weave(&owner, 1);
    assert!(
        refused.is_err(),
        "the grant back refuses while no Steward scope resolves: {refused:?}"
    );
    assert_eq!(
        grant_mark(&vault, dreamer).expect("mark"),
        before,
        "the standing grant is left as it was"
    );
}
