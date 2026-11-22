//! UC-05 PR 1 guard: the owner-proof rule of an attendee answer.
//!
//! PR 1 moved five ask kinds' word admission and first-word cut onto one rule
//! (`task_verb/ask_guard.rs`: `admit_word_in`, `may_cut_in`). This file pins
//! that shared rule through the attendee ask kind: an owner's word counts
//! only as the owner's own act under the live owner proof, so a proven word
//! is admitted and cuts the ask on first word, while an unproven word is
//! refused with `GateError::ConsentOwnerNotAuthenticated` and the ask keeps
//! waiting.
//!
//! Each test passes on main and on the PR head: the move is
//! behaviour-preserving, so this is a guard, not a red proof.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test owner_ask_word_proof`.
#![allow(clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::disclosure::{AttendeeIdentityChoice, UnknownAttendeeAsk};
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{TaskAskDecision, TaskAskSettlementReason, TaskAskStatus, TaskAskWord};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;

/// The rooted vault's fixed clock: no wall time, no sleeps.
const ROOTED_T0: u64 = 1_780_000_000;

/// A vault with install signing, a host root, the engine machine identities
/// and a serving install profile, as a host that serves an agent's verb calls
/// holds it; the third value is the embedded owner.
fn rooted_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(ROOTED_T0).bundle();
    let vault = Vault::open(directory.path(), config).expect("rooted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    (directory, vault, owner)
}

/// The live owner proof, minted with no bound credential: revalidation of a
/// credential-less proof asks only live vault ownership.
fn owner_proof(vault: &Vault, owner: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

/// An ask about speaker `speaker-1` at roster revision 1 of `session_key`.
fn attendee_ask(vault: &Vault, session_key: &str) -> UnknownAttendeeAsk {
    UnknownAttendeeAsk {
        session_key: session_key.to_owned(),
        speaker_key: "speaker-1".to_owned(),
        roster_revision: 1,
        trigger_turn: None,
        candidates: Vec::new(),
        until: vault.now_recorded_at() + 86_400,
    }
}

/// The owner's word for the ask: the `unknown` option, answered on the
/// owner's own row.
fn owner_word(owner: EntityId) -> TaskAskWord {
    let mut word = TaskAskWord::new(owner);
    word.option = Some(
        AttendeeIdentityChoice::Unknown
            .option()
            .expect("the unknown option id"),
    );
    word
}

/// A proven owner word is admitted, and the ask cuts on it: the shared rule
/// admits the asked party's own word under its live proof and cuts the ask
/// on that first word.
#[test]
fn an_attendee_owner_word_under_the_owner_proof_is_admitted_and_cut() {
    let (_directory, vault, owner) = rooted_vault();
    let proof = owner_proof(&vault, owner);
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .raise_unknown_attendee_ask(&attendee_ask(&vault, "room-proof"))
        .expect("the owner raises the attendee ask");
    let handle = receipt.handle;
    let word = owner_word(owner);
    let answer = vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(&proof)
        .tasks_answer(&handle, &word)
        .expect("the owner's proven word is admitted");
    assert_eq!(
        answer.actor_ref, owner,
        "the admitted word is the owner's own"
    );
    let TaskAskStatus::Settled(result) = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask_status(handle)
        .expect("the ask's status reads")
    else {
        panic!("the proven word cuts the ask");
    };
    assert_eq!(
        result.settlement.reason,
        TaskAskSettlementReason::FirstWord,
        "the proven first word cuts the ask"
    );
    assert!(
        matches!(&result.decision, TaskAskDecision::First(first) if first.actor_ref == owner),
        "the cut decides the owner's word: {:?}",
        result.decision
    );
}

/// The same word with no proof bound is refused with the owner-proof
/// refusal, and nothing is recorded: the shared rule admits no word without
/// the asked party's live proof.
#[test]
fn an_attendee_owner_word_without_the_owner_proof_is_refused() {
    let (_directory, vault, owner) = rooted_vault();
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .raise_unknown_attendee_ask(&attendee_ask(&vault, "room-unproven"))
        .expect("the owner raises the attendee ask");
    let handle = receipt.handle;
    let word = owner_word(owner);
    let error = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_answer(&handle, &word)
        .expect_err("the unproven word is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "the refusal is the owner-proof refusal, got {}: {}",
        error.code, error.message
    );
    assert!(
        error.message.contains("consent owner not authenticated"),
        "the refusal names the missing owner proof: {}",
        error.message
    );
    let evidence = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask_evidence(handle)
        .expect("the ask's evidence reads");
    assert!(evidence.is_empty(), "the refused word records nothing");
}

/// After a refused word, the ask still waits: the refusal lands before
/// anything is recorded, so a proof-less status read stays pending.
#[test]
fn an_attendee_ask_waits_after_a_refused_word() {
    let (_directory, vault, owner) = rooted_vault();
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .raise_unknown_attendee_ask(&attendee_ask(&vault, "room-waits"))
        .expect("the owner raises the attendee ask");
    let handle = receipt.handle;
    let word = owner_word(owner);
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_answer(&handle, &word)
        .expect_err("the unproven word is refused");
    let status = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask_status(handle)
        .expect("the ask's status reads");
    assert!(
        matches!(&status, TaskAskStatus::Pending { .. }),
        "the ask still waits after the refused word: {status:?}"
    );
}
