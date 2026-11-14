//! L9-52 (b), the Engine's ruling L9-52-ACTOR-BINDING-DELETED = A (14 Nov):
//! a soft-deleted actor's Active binding authorizes nothing. A soft delete
//! keeps the row's header (ARCH-0038) and no delete revokes a binding, so
//! the doors that read the authority fold alone let a deleted owner or agent
//! act. Main already holds the rule on its other paths: H149 refuses a
//! deleted owner on an unrooted vault, and a host never acts as a deleted
//! owner ("A deleted owner is not brought back").
//!
//! A deleted actor that still holds its binding is made here as a delete
//! that landed before the binding leaves it: the person is deleted while the
//! host key binds a stand-in, then the host key binds the deleted person.
//!
//! The lead's ruling L9-52-OWNER-SELF-DELETE = B (14 Nov) rides on top: no
//! delete door deletes the PERSON that holds the vault's last Active owner
//! binding, and the refusal names both ways out (another owner first, or
//! erasing the vault). A person no live binding names is deleted as before.
//!
//! Red on main: a deleted bound owner still classes VaultOwner in a room and
//! still holds owner verbs and task verbs, a deleted agent-bound person still
//! classes VaultAgent, and the last bound owner's PERSON is deleted. Guards
//! (pass on main too): the same doors serve the live bound owner and the live
//! agent-bound person, and an unbound person's delete passes.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test actor_binding_liveness`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, actor_binding_is_active};
use oneiron::disclosure::RoomParty;
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_OWNER_BINDING_REQUIRED, Memory,
    SafeDeleteReason,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::{TaskCreateSpec, TaskHandle, TaskStatusQuery};
use oneiron::temporal::TimeRange;
use oneiron::test_support::{bind_host_actor, bind_host_owner, provision_engine_machines};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

/// A rooted vault whose host key binds its embedded owner. The vault closes
/// before its directory.
struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    // A delete signs its receipt with this install's key.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    Fixture {
        vault,
        issuer,
        owner,
        _dir: dir,
    }
}

fn live_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    id
}

impl Fixture {
    fn memory(&self, actor: EntityId) -> Memory<'_> {
        self.vault.memory(actor, EdgeActorClass::Human)
    }

    /// `person` deleted while the host key binds a stand-in, then bound at
    /// `class`: a deleted actor that holds an Active binding.
    fn deleted_then_bound(&self, person: EntityId, class: &str) {
        let stand_in = live_person(&self.vault);
        bind_host_actor(&self.vault, &self.issuer, stand_in, "human")
            .expect("FIXTURE: the host key binds a stand-in");
        assert!(
            self.vault
                .delete_entity(&person)
                .expect("FIXTURE: the host deletes the person"),
            "FIXTURE: the person existed"
        );
        assert!(
            self.vault.is_deleted_shell(&person).expect("shell read"),
            "FIXTURE: the person is a deleted shell"
        );
        bind_host_actor(&self.vault, &self.issuer, person, class)
            .expect("FIXTURE: the host key binds the deleted person");
        assert!(
            actor_binding_is_active(
                &self.vault.authority_fold().expect("authority fold"),
                &person,
                class
            ),
            "FIXTURE: the deleted person holds an Active {class} binding"
        );
    }
}

#[test]
fn a_deleted_owner_holding_its_binding_is_no_vault_owner_in_a_room() {
    let f = fixture();
    assert_eq!(
        f.vault.room_parties(&[f.owner]).expect("parties"),
        vec![RoomParty::VaultOwner],
        "the live bound owner is the vault owner"
    );
    f.deleted_then_bound(f.owner, "human");
    assert_eq!(
        f.vault.room_parties(&[f.owner]).expect("parties"),
        vec![RoomParty::Unknown],
        "a deleted owner adds the bottom term, as any deleted member"
    );
}

#[test]
fn a_deleted_person_holding_an_agent_binding_is_no_vault_agent_in_a_room() {
    let f = fixture();
    let live = live_person(&f.vault);
    bind_host_actor(&f.vault, &f.issuer, live, "agent").expect("the live agent's binding");
    assert_eq!(
        f.vault.room_parties(&[live]).expect("parties"),
        vec![RoomParty::VaultAgent],
        "a live agent-bound person is the vault's own agent"
    );
    let gone = live_person(&f.vault);
    f.deleted_then_bound(gone, "agent");
    assert_eq!(
        f.vault.room_parties(&[gone]).expect("parties"),
        vec![RoomParty::Unknown],
        "a deleted agent is no vault agent"
    );
}

#[test]
fn a_deleted_owner_holding_its_binding_holds_no_owner_verbs() {
    let f = fixture();
    let first = live_person(&f.vault);
    let second = live_person(&f.vault);
    f.memory(f.owner)
        .safe_delete(&first.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the live bound owner deletes a person");
    f.deleted_then_bound(f.owner, "human");
    let refused = f
        .memory(f.owner)
        .safe_delete(&second.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("a deleted owner's delete");
    assert_eq!(
        refused.code, MEMORY_CODE_OWNER_BINDING_REQUIRED,
        "{refused:?}"
    );
    assert!(
        !f.vault.is_deleted_shell(&second).expect("shell read"),
        "nothing was deleted"
    );
}

#[test]
fn a_deleted_owner_holding_its_binding_takes_no_task_verb() {
    let f = fixture();
    let receipt = f
        .memory(f.owner)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("a task its owner reads"),
            None,
            Some(f.owner),
            None,
        ))
        .expect("FIXTURE: the owner's TASK");
    let task = receipt.task_ref.expect("FIXTURE: a TASK row");
    let status = || TaskStatusQuery {
        handle: TaskHandle::Task { task_ref: task },
        after: None,
    };
    f.memory(f.owner)
        .tasks_status(status())
        .expect("the live bound owner reads its TASK");
    f.deleted_then_bound(f.owner, "human");
    let refused = f
        .memory(f.owner)
        .tasks_status(status())
        .expect_err("a deleted owner's task verb");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains("deleted actor's binding"),
        "{refused:?}"
    );
}

/// The guard's refusal names both ways out of it.
fn names_both_ways_out(message: &str) -> bool {
    message.contains("add another owner first") && message.contains("erase the vault")
}

#[test]
fn the_last_bound_owners_person_is_not_deleted_and_the_refusal_names_both_ways_out() {
    let f = fixture();
    let refused = f
        .memory(f.owner)
        .safe_delete(&f.owner.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("the last bound owner deletes their own person");
    assert_eq!(refused.code, MEMORY_CODE_INVALID_STATE, "{refused:?}");
    assert!(names_both_ways_out(&refused.message), "{refused:?}");
    let host = f
        .vault
        .delete_entity(&f.owner)
        .expect_err("the host door deletes the last bound owner's person");
    assert!(names_both_ways_out(&host.to_string()), "{host:?}");
    assert!(
        !f.vault.is_deleted_shell(&f.owner).expect("shell read"),
        "the owner's person stays live"
    );
    let unbound = live_person(&f.vault);
    f.memory(f.owner)
        .safe_delete(&unbound.to_hex(), SafeDeleteReason::UserDelete)
        .expect("a person no binding names is deleted as before");
}

#[test]
fn the_guard_follows_the_live_binding_not_the_embedded_owner() {
    let f = fixture();
    let heir = live_person(&f.vault);
    bind_host_actor(&f.vault, &f.issuer, heir, "human").expect("the host key binds the heir");
    assert!(
        f.vault
            .delete_entity(&f.owner)
            .expect("the embedded owner, no longer bound, is deleted"),
        "the owner's person existed"
    );
    let refused = f
        .vault
        .delete_entity(&heir)
        .expect_err("the person holding the last binding");
    assert!(names_both_ways_out(&refused.to_string()), "{refused:?}");
    assert!(
        !f.vault.is_deleted_shell(&heir).expect("shell read"),
        "the heir's person stays live"
    );
}
