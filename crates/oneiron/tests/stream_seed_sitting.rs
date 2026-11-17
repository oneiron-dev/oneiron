//! A message stream's TURN joins the sitting its opener's handle was bound
//! to (`Memory::with_session`), at its terminal and at the terminal a
//! restart's recovery writes (FIX 1033). The stored stream seed kept no
//! sitting, so the terminal rebuilt its handle from the actor alone and the
//! witness fell back to this machine's sitting: the TURN joined the wrong
//! sitting, or none.
//!
//! Each case opens two sittings of the owner: the one on this machine, and
//! one on another machine, the way a host binds a caller's authenticated
//! sitting. The stream binds the second.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test stream_seed_sitting`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use oneiron::memory::{
    Memory, MessageWriteMode, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::session_lifecycle::SessionKey;
use oneiron::test_doors::turn_sitting::turn_sitting;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A device vault with its embedded owner bound to the test host.
fn fresh_vault() -> TestResult<(tempfile::TempDir, Vault, EntityId)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor()?;
    bind_host_owner(&vault, &test_host_issuer(), owner)?;
    Ok((directory, vault, owner))
}

/// A vault no host roots, with its embedded owner: the crate's own stream
/// crash tests reopen this shape (memory/witness/stream/tests.rs).
fn unrooted_vault() -> TestResult<(tempfile::TempDir, Vault, EntityId)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok((directory, vault, owner))
}

/// The owner's two open sittings: this machine's, and one on another
/// machine, which the stream is bound to.
struct Sittings {
    bound: SessionKey,
    bound_session: EntityId,
    local_session: EntityId,
}

/// Mints and opens `key`'s sitting; returns its SESSION.
fn open_sitting(vault: &Vault, key: SessionKey) -> TestResult<EntityId> {
    vault.mint_session(key, vault.now_recorded_at())?;
    Ok(vault
        .open_session(key)?
        .ok_or("fixture: the sitting is not open")?
        .session)
}

fn open_sittings(vault: &Vault, owner: EntityId) -> TestResult<Sittings> {
    let local = vault.local_session_key(owner)?;
    let bound = SessionKey {
        actor: owner,
        machine: EntityId::now(),
    };
    assert_ne!(bound, local, "fixture: the bound sitting is this machine's");
    Ok(Sittings {
        bound,
        local_session: open_sitting(vault, local)?,
        bound_session: open_sitting(vault, bound)?,
    })
}

fn owner_memory(vault: &Vault, owner: EntityId) -> Memory<'_> {
    vault.memory(owner, EdgeActorClass::Human)
}

/// One empty User MESSAGE in a fresh TURN of a fresh conversation, the
/// stream's birth. Returns the turn and the TURN id.
fn stream_birth(vault: &Vault) -> TestResult<(WitnessTurn, EntityId)> {
    let turn = EntityId::now();
    Ok((
        WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: String::new(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: WitnessAssertions::default(),
        },
        turn,
    ))
}

/// Red on main: the TURN joined this machine's sitting, not the bound one.
#[test]
fn a_finalized_stream_joins_the_sitting_its_opener_was_bound_to() -> TestResult {
    let (_directory, vault, owner) = fresh_vault()?;
    let sittings = open_sittings(&vault, owner)?;
    let memory = owner_memory(&vault, owner).with_session(sittings.bound);
    let (birth, turn) = stream_birth(&vault)?;
    let handle = memory.begin_message_stream(&birth, Some(MessageWriteMode::Atomic))?;
    memory.append_to_stream(handle, "owen speaks from his laptop")?;
    memory.finalize_stream(handle)?;

    let joined = turn_sitting(&vault, &turn)?;
    assert_ne!(
        joined,
        Some(sittings.local_session),
        "the TURN joined this machine's sitting, not the one its stream was bound to"
    );
    assert_eq!(joined, Some(sittings.bound_session));
    Ok(())
}

/// Red on main: the seed stored no sitting, so the TURN that recovery
/// writes at the next open joined this machine's sitting.
#[test]
fn a_recovered_stream_joins_the_sitting_its_opener_was_bound_to() -> TestResult {
    let (directory, vault, owner) = unrooted_vault()?;
    let sittings = open_sittings(&vault, owner)?;
    let (birth, turn) = stream_birth(&vault)?;
    let message = {
        let memory = owner_memory(&vault, owner).with_session(sittings.bound);
        let handle = memory.begin_message_stream(&birth, Some(MessageWriteMode::Atomic))?;
        memory.append_to_stream(handle, "owen's words, checkpointed")?;
        handle.message_id()
    };
    // The process stops with the stream open: only its seed survives.
    drop(vault);
    let reopened = Vault::open(directory.path(), VaultConfig::default())?;
    let receipt = reopened
        .message_stream_receipt(&message)?
        .ok_or("fixture: recovery wrote no terminal for the stream")?;
    assert!(receipt.recovered, "the terminal is not the recovery's");

    let joined = turn_sitting(&reopened, &turn)?;
    assert_ne!(
        joined,
        Some(sittings.local_session),
        "the recovered TURN joined this machine's sitting, not the one its stream was bound to"
    );
    assert_eq!(joined, Some(sittings.bound_session));
    Ok(())
}

/// Control: a stream bound to no sitting still joins this machine's open
/// sitting, as the witness always placed it.
#[test]
fn an_unbound_stream_joins_this_machines_open_sitting() -> TestResult {
    let (_directory, vault, owner) = fresh_vault()?;
    let sittings = open_sittings(&vault, owner)?;
    let memory = owner_memory(&vault, owner);
    let (birth, turn) = stream_birth(&vault)?;
    let handle = memory.begin_message_stream(&birth, Some(MessageWriteMode::Atomic))?;
    memory.append_to_stream(handle, "owen speaks on this machine")?;
    memory.finalize_stream(handle)?;

    assert_eq!(turn_sitting(&vault, &turn)?, Some(sittings.local_session));
    Ok(())
}
