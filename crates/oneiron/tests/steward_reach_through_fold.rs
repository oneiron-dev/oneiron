//! A Steward row gives an actor that is no base agent only what the fold's counted acts give
//! it (pass 28 R4b, FIX [STEWARD-REACH-ROW-ALONE-FOR-NON-BASE-ACTOR]).
//!
//! The Steward reach (`federation::steward_reach_in`) is what the derive gate, its receipts'
//! grant field and the strength-observation reader ask for any actor. A Steward row naming a
//! person, or an agent that is no base agent, that no counted act gives (one another device
//! sent alone) reaches nothing and lets the agent derive over no stored record. The owner's
//! counted Steward mint still gives an agent its reach, a shared vault's Steward member given
//! by the membership door keeps theirs, and a base agent's engine-default row is unchanged.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test steward_reach_through_fold`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::federation::{FederationGrantRole, decode_federation_grant_body};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::coach::{coach, define_agent, read_and_engine_controls};
use oneiron::test_doors::derive::{define_auto_agent, derive_verdict, grant_derive_rows};
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, open_owner_carrier_vault, receive_steward_grant_row, stand_steward_grant,
    steward_reach_scope,
};
use oneiron::test_support::provision_act_carrier;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

/// The derive verb a Steward row names.
const DERIVE_VERB: &str = "derive";
/// The derive gate's refusal for an actor whose reach holds no stored record.
const OUTSIDE_GRANT: &str = "gate.deny.derive.outside_grant";
/// The shared vault's id.
const SHARED: u64 = 42;

/// A PERSON row; its id.
fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"someone",
        )
        .expect("a person row");
    id
}

/// A shared vault whose install carries acts, created by its embedded owner.
fn shared_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config).expect("vault");
    provision_act_carrier(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault
        .initialize_shared_vault(&proof, SHARED, None, &[], 1)
        .expect("the shared vault");
    (dir, vault)
}

#[test]
fn a_bare_steward_row_gives_an_agent_no_steward_reach() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let agent = define_agent(&vault).expect("an agent");
    let id = receive_steward_grant_row(&vault, agent, &[STEWARD_READ_VERB, DERIVE_VERB])
        .expect("the bare row lands");

    let reach = steward_reach_scope(&vault, agent).expect("the reach read");
    assert!(
        reach.is_none(),
        "agent={agent:?} row={id:?}; expected a Steward row no counted act gives to give an \
         agent that is no base agent no Steward reach; seen {reach:?}"
    );
}

#[test]
fn a_bare_steward_row_gives_a_person_no_steward_reach() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let someone = person(&vault);
    let id = receive_steward_grant_row(&vault, someone, &[STEWARD_READ_VERB, DERIVE_VERB])
        .expect("the bare row lands");

    let reach = steward_reach_scope(&vault, someone).expect("the reach read");
    assert!(
        reach.is_none(),
        "person={someone:?} row={id:?}; expected a Steward row no counted act gives to give a \
         person no Steward reach; seen {reach:?}"
    );
}

#[test]
fn a_bare_steward_row_lets_an_agent_derive_over_no_stored_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let agent = define_auto_agent(&vault).expect("an agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's derive rows");
    let target = person(&vault);
    let id = receive_steward_grant_row(&vault, agent, &[STEWARD_READ_VERB, DERIVE_VERB])
        .expect("the bare row lands");

    let verdict = derive_verdict(&vault, agent, EdgeActorClass::Agent, false, Some(target))
        .expect("the derive verdict");
    assert_eq!(
        verdict,
        Err(OUTSIDE_GRANT),
        "agent={agent:?} row={id:?}; expected a Steward row no counted act gives to reach no \
         stored record at the derive gate"
    );
}

/// Guard: the owner's counted Steward mint gives the agent its reach and its derive grant.
#[test]
fn the_owners_steward_mint_lets_an_agent_derive_over_a_stored_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let agent = define_auto_agent(&vault).expect("an agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's derive rows");
    let target = person(&vault);
    let id = stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB, DERIVE_VERB])
        .expect("the owner's mint");

    assert!(
        steward_reach_scope(&vault, agent)
            .expect("the reach read")
            .is_some(),
        "agent={agent:?} grant={id:?}; expected the owner's counted mint to give its reach"
    );
    let verdict = derive_verdict(&vault, agent, EdgeActorClass::Agent, false, Some(target))
        .expect("the derive verdict");
    assert_eq!(
        verdict,
        Ok(id.to_hex()),
        "agent={agent:?}; expected the owner's counted mint to let the agent derive over a \
         stored record, judged by that grant"
    );
}

/// Guard: a shared vault's Steward member given by the membership door keeps their reach.
#[test]
fn a_steward_member_given_by_the_membership_door_keeps_their_steward_reach() {
    let (_dir, vault) = shared_vault();
    let steward = person(&vault);
    let id = stand_member_grant(&vault, steward, SHARED, FederationGrantRole::Steward)
        .expect("the Steward giving");

    let reach = steward_reach_scope(&vault, steward).expect("the reach read");
    assert!(
        reach.is_some(),
        "member={steward:?} grant={id:?}; expected a counted SharedMember giving at Steward \
         role to give its Steward reach; seen none"
    );
}

#[test]
fn a_copied_steward_member_row_over_a_shared_vault_gives_no_steward_reach() {
    let (_dir, vault) = shared_vault();
    let steward = person(&vault);
    let given = stand_member_grant(&vault, steward, SHARED, FederationGrantRole::Steward)
        .expect("the Steward giving");
    let mut copied = decode_federation_grant_body(
        &vault
            .get(&given)
            .expect("grant read")
            .expect("a live Grant row"),
    )
    .expect("the Grant row decodes");
    let other = person(&vault);
    copied.member_ref = other;
    let id = EntityId::now();
    put_unkeyed_member_grant(&vault, id, &copied).expect("the copied row lands");

    let reach = steward_reach_scope(&vault, other).expect("the reach read");
    assert!(
        reach.is_none(),
        "person={other:?} row={id:?}; expected a Steward member row no counted giving gives \
         to give no Steward reach; seen {reach:?}"
    );
}

/// Guard: a base agent's engine-default Steward row, which no act gives, keeps its reach.
#[test]
fn the_coachs_default_steward_row_keeps_its_steward_reach() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let coach = coach(&vault).expect("the Coach");
    let id = receive_steward_grant_row(&vault, coach, &read_and_engine_controls())
        .expect("the row lands");

    assert!(
        steward_reach_scope(&vault, coach)
            .expect("the reach read")
            .is_some(),
        "coach={coach:?} row={id:?}; expected the Coach's default Steward row to give its reach"
    );
}
