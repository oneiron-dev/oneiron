//! The owner's three grant verbs (Engine RULING ROW3-GRANT-VERBS = A; FIX
//! FABLE-6917-1 and ENGINE-CONTROLS-GRANT-DOORS-NO-VERB), called by name
//! through the generated verb dispatch (`oneiron::task_verb::sdk::invoke`)
//! as the vault's embedded owner, as a client calls them:
//! - `vault.agents.grants.restore` gives a narrowed base agent its default
//!   grant back: the Coach reads the project goal again, the Dreamer lands
//!   again, and a second call changes nothing. For the Dreamer the answer
//!   also carries its live reach, read after the grant (Engine RULING
//!   ROW4-WEAVE-GRANT-REACH = A), so a grant the owner's policy rows still
//!   hold back says so;
//! - `vault.engine.controls.grant` and `vault.engine.controls.revoke` give
//!   an agent that is no base agent a class of the engine's knobs and take
//!   it back.
//!
//! On main none of the three names is a verb: each call answers BAD_REQUEST
//! "unknown SDK agent verb", so every test here fails there.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test grant_restore_and_engine_controls_verbs`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::authority::coach_reader;
use oneiron::federation::{EngineControlActor, EngineControlClass, SystemAgentGrantNarrowing};
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, coach, write_root_goal};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, WeaveReach, dreamer, owner, steward_grant_rows, weave_reach,
    write_generated_false_without_ceilings,
};
use oneiron::test_support::provision_engine_machines;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const RESTORE_VERB: &str = "vault.agents.grants.restore";
const CONTROLS_GRANT_VERB: &str = "vault.engine.controls.grant";
const CONTROLS_REVOKE_VERB: &str = "vault.engine.controls.revoke";

/// An owned vault whose install carries the embedded owner's signed acts:
/// its writer lease is what the owner's verb doors ask for
/// (`Memory::embedded_owner`), and, as `open_owner_carrier_vault` sets it
/// up, the engine's machine writers, the embedded owner, an in-memory
/// device keystore and this install's machine profile. The host's first
/// mint gives the Dreamer and the Coach their default grants.
fn open_owned_carrier_vault(dir: &tempfile::TempDir) -> Vault {
    let vault = open_owned_carrier_vault_before_first_mint(dir);
    vault.provision_system_agent_grants().expect("first mint");
    vault
}

/// [`open_owned_carrier_vault`] before the host's first mint.
fn open_owned_carrier_vault_before_first_mint(dir: &tempfile::TempDir) -> Vault {
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("owned vault");
    let issuer = provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    vault
}

/// `verb` as the vault's embedded owner, by name.
fn call_as_owner(vault: &Vault, verb: &str, input: Value) -> Value {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    invoke(&vault.memory(owner, EdgeActorClass::Human), verb, input)
        .unwrap_or_else(|error| panic!("{verb} as the owner: {error:?}"))
}

/// A grant back's answer: restored, on the owner's own proof (ROLES-CHECKIN
/// 2k7).
fn assert_restored(answer: Value) {
    assert_eq!(
        answer,
        json!({
            "restored": true,
            "check_in": {
                "act_class": "grant_widen",
                "role": "owner",
                "mode": null,
                "basis": "own_proof",
                "check_in": null,
            },
        })
    );
}

/// A Dreamer grant back's answer: [`assert_restored`]'s, plus the
/// Dreamer's live reach read after the grant (Engine RULING
/// ROW4-WEAVE-GRANT-REACH = A).
fn assert_dreamer_restored(answer: Value, lands_auto: bool, message: &str) {
    assert_eq!(
        answer,
        json!({
            "restored": true,
            "check_in": {
                "act_class": "grant_widen",
                "role": "owner",
                "mode": null,
                "basis": "own_proof",
                "check_in": null,
            },
            "reach": { "reads": true, "lands_auto": lands_auto },
        }),
        "{message}"
    );
}

/// The owner narrows `agent`'s grant to `keep`, confirming what breaks.
fn narrow(vault: &Vault, owner: &AuthenticatedOwner, agent: EntityId, keep: &[&str]) {
    let keep: BTreeSet<String> = keep.iter().map(|verb| (*verb).to_owned()).collect();
    let mut narrowing = vault
        .narrow_system_agent_grant(owner, agent, &keep, None)
        .expect("narrowing");
    if let SystemAgentGrantNarrowing::ConfirmRequired { confirm, .. } = narrowing {
        narrowing = vault
            .narrow_system_agent_grant(owner, agent, &keep, Some(confirm))
            .expect("confirmed narrowing");
    }
    assert!(
        matches!(narrowing, SystemAgentGrantNarrowing::Narrowed { .. }),
        "the owner's narrowing applies: {narrowing:?}"
    );
}

/// The Coach's read of the root project's goal.
fn coach_goal_read(vault: &Vault, project: EntityId) -> bool {
    vault
        .project_intake_goal_as(coach_reader().expect("the Coach as a reader"), project)
        .expect("the Coach's goal read")
        .is_some()
}

#[test]
fn the_restore_verb_gives_a_narrowed_coach_its_goal_read_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned_carrier_vault(&dir);
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    let project = write_root_goal(&vault, &owner).expect("goal");
    assert!(
        coach_goal_read(&vault, project),
        "the first mint's grant reads the goal"
    );

    narrow(&vault, &owner, coach, &ENGINE_CONTROLS_VERBS);
    assert!(
        !coach_goal_read(&vault, project),
        "a Coach narrowed off read reads no goal"
    );

    assert_restored(call_as_owner(
        &vault,
        RESTORE_VERB,
        json!({ "agent": coach.to_hex() }),
    ));
    assert!(
        coach_goal_read(&vault, project),
        "the grant back gives the Coach its goal read again"
    );
    assert!(
        vault
            .engine_control_allowed(
                EngineControlActor::Holder(coach),
                EngineControlClass::WorkBudget
            )
            .expect("check"),
        "the grant back keeps the Coach's engine.controls classes"
    );
}

#[test]
fn a_second_restore_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned_carrier_vault(&dir);
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    narrow(&vault, &owner, coach, &ENGINE_CONTROLS_VERBS);

    let input = json!({ "agent": coach.to_hex() });
    assert_restored(call_as_owner(&vault, RESTORE_VERB, input.clone()));
    let rows = steward_grant_rows(&vault, coach).expect("rows");
    assert_eq!(
        call_as_owner(&vault, RESTORE_VERB, input),
        json!({ "restored": false }),
        "the whole default already stands"
    );
    assert_eq!(
        steward_grant_rows(&vault, coach).expect("rows"),
        rows,
        "the row the first grant back minted still stands, and no other"
    );
}

#[test]
fn the_restore_verb_gives_a_narrowed_dreamer_its_landing_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned_carrier_vault(&dir);
    let owner = owner(&vault).expect("owner proof");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    narrow(&vault, &owner, dreamer, &[STEWARD_READ_VERB]);
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        WeaveReach {
            reads: true,
            lands_auto: false,
        },
        "a Dreamer narrowed to read lands nothing Auto"
    );

    assert_dreamer_restored(
        call_as_owner(&vault, RESTORE_VERB, json!({ "agent": dreamer.to_hex() })),
        true,
        "the answer carries the Dreamer's live reach",
    );
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        WeaveReach {
            reads: true,
            lands_auto: true,
        },
        "the grant back lets the Dreamer land again"
    );
}

/// GENERATED-SHORTHAND-UNDER-STEWARD-DERIVE (Engine RULING
/// ROW4-WEAVE-GRANT-REACH = A): the owner's grant back can stand whole
/// while the owner's own policy rows keep the Dreamer from landing
/// (`generated: false` and no actor ceiling). The first mint over that pack
/// copies `read` alone; the grant back mints the whole Steward default, and
/// its answer says the Dreamer still lands nothing.
#[test]
fn the_restore_verb_answers_a_dreamer_reach_the_policy_still_holds_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned_carrier_vault_before_first_mint(&dir);
    write_generated_false_without_ceilings(&vault).expect("Generated: false, no ceiling");
    vault.provision_system_agent_grants().expect("first mint");
    let dreamer = dreamer(&vault).expect("the Dreamer");

    assert_dreamer_restored(
        call_as_owner(&vault, RESTORE_VERB, json!({ "agent": dreamer.to_hex() })),
        false,
        "the whole default stands, and the answer says the Dreamer still lands nothing",
    );
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        WeaveReach {
            reads: true,
            lands_auto: false,
        },
        "the answer's reach is the live one"
    );
}

#[test]
fn the_restore_verb_refuses_a_principal_that_is_no_base_agent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned_carrier_vault(&dir);
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let error = invoke(
        &vault.memory(owner_id, EdgeActorClass::Human),
        RESTORE_VERB,
        json!({ "agent": person.to_hex() }),
    )
    .expect_err("a person has no default grant to give back");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        error.message.contains("vault.agents.base"),
        "the refusal names where the base agents are listed: {}",
        error.message
    );
}

#[test]
fn the_engine_controls_grant_and_revoke_verbs_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned_carrier_vault(&dir);
    let holder = EntityId::now();
    vault
        .put_entity(
            &holder,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let allowed = |class| {
        vault
            .engine_control_allowed(EngineControlActor::Holder(holder), class)
            .expect("check")
    };
    assert!(!allowed(EngineControlClass::WorkBudget));

    let granted = call_as_owner(
        &vault,
        CONTROLS_GRANT_VERB,
        json!({ "agent": holder.to_hex(), "classes": ["work_budget"] }),
    );
    let grant = granted["grant"]
        .as_str()
        .unwrap_or_else(|| panic!("the answer names the grant: {granted}"))
        .to_owned();
    assert!(allowed(EngineControlClass::WorkBudget), "the class granted");
    assert!(
        !allowed(EngineControlClass::WakeCadence),
        "a class not granted"
    );

    assert_eq!(
        call_as_owner(
            &vault,
            CONTROLS_REVOKE_VERB,
            json!({ "agent": holder.to_hex() })
        ),
        json!({ "revoked": [grant] }),
        "the revoke names the grant the grant verb minted"
    );
    assert!(
        !allowed(EngineControlClass::WorkBudget),
        "the holder tunes nothing after the revoke"
    );
    assert_eq!(
        call_as_owner(
            &vault,
            CONTROLS_REVOKE_VERB,
            json!({ "agent": holder.to_hex() })
        ),
        json!({ "revoked": [] }),
        "nothing is left to revoke"
    );
}
