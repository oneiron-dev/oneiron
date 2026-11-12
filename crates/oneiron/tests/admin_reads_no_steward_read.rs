//! Steward is a named grant preset, never a rank, and never reachable
//! through Admin (lead 10 Nov 06:5x; ARCH-0043's Admin row: "Cannot read
//! private member vaults. Cannot self-grant blanket access"; federation:27).
//! A shared vault's Admin, whose grant names `read` among its powers, is
//! refused every Steward-only read and every engine.controls class, while
//! the vault's Steward, whom the owner made one, reads.
//!
//! A guard: it passes on the base too, since no check orders roles.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test admin_reads_no_steward_read`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    EngineControlActor, EngineControlClass, FederationGrantRole as Role, InitialSharedMember,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const SHARED: u64 = 42;

const CLASSES: [EngineControlClass; 4] = [
    EngineControlClass::MaintenanceCadence,
    EngineControlClass::WorkBudget,
    EngineControlClass::WakeCadence,
    EngineControlClass::KnowledgeRecipe,
];

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `member` accepts its founding invitation to the shared vault at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

fn read(vault: &Vault, actor: EntityId, verb: &str, input: Value) -> MemoryResult<Value> {
    invoke(&vault.memory(actor, EdgeActorClass::Human), verb, input)
}

#[test]
fn an_admin_is_refused_every_steward_only_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let (admin, steward) = (EntityId::now(), EntityId::now());
    person(&vault, admin);
    person(&vault, steward);
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: admin,
                    role: Some(Role::Admin),
                },
                InitialSharedMember {
                    member_ref: steward,
                    role: Some(Role::Steward),
                },
            ],
            1,
        )
        .expect("a shared vault with an Admin and a Steward");
    accept(&vault, admin, Role::Admin);
    accept(&vault, steward, Role::Steward);

    let cards = || json!({ "from": 0, "to": u64::MAX });
    // The Steward the owner made reads the engine's evidence about agents.
    read(&vault, steward, "vault.agent_health.cards", cards())
        .expect("the Steward reads agent health");

    // The Admin, whose powers include `read`, is no Steward: every
    // Steward-only read refuses it.
    for (verb, input) in [
        ("vault.agent_health.cards", cards()),
        ("vault.settings.learning", json!({})),
    ] {
        let error = read(&vault, admin, verb, input)
            .expect_err(&format!("{verb}: an Admin is refused a Steward-only read"));
        assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{verb}: {error:?}");
    }
    for class in CLASSES {
        assert!(
            !vault
                .engine_control_allowed(EngineControlActor::Holder(admin), class)
                .expect("check"),
            "{class:?}: an Admin holds no engine.controls class"
        );
    }
}
