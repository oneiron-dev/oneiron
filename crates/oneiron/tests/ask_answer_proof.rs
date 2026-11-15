//! UC-05 PR 2: a code consent or comm widen word is its asked party's
//! own act, under that party's live proof (ruling UC-05-ASK-ANSWERER = A).
//! An owner answers either ask under the owner proof; a frozen holder
//! answers a code consent ask under their person-tier proof; comm widen's
//! agent recipient answers as its verified actor. A word with no proof is
//! refused, and a first-word cut needs the same proof in the cutting
//! transaction.
//!
//! On the base (branch opus-uc05-asks/answer-person-tier, where code consent
//! and comm widen admit any asked person's Human word with no proof and cut
//! on it) the refusal and still-waiting assertions fail; on the head they
//! pass.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test ask_answer_proof`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, CommReach,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::VerifiedSlip;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    AskForwardAct, AskForwardHolderProof, AskForwardReceipt, HostBinding, TaskAskDecision,
    TaskAskOptionId, TaskAskStatus, TaskAskWord,
};
use oneiron::test_doors::ask_answer_proof::{
    admit_word_unsettled, mint_code_consent_ask, raise_comm_widen_ask,
};
use oneiron::{
    AttemptId, AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_testkit::dreamer::{attach_test_host, test_host_issuer};

/// The run every attempt of one test's tree belongs to.
const RUN: &str = "ask-answer-proof";
/// The lease owner this test claims rows as.
const WORKER: &str = "ask-answer-proof";

/// An owned vault with its embedded owner and the test host. The vault drops
/// before its directory.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("a tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("an owned vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    attach_test_host(&vault).expect("the test host");
    Fixture {
        vault,
        _dir: dir,
        owner,
    }
}

/// A live PERSON who owns nothing.
fn put_person(vault: &Vault, at: u64, body: &[u8]) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            body,
        )
        .expect("a live person");
    person
}

/// A TURN row a word stands on (tests/ask_forward_intent_secret_scan.rs).
fn put_turn(vault: &Vault, at: u64, role: &str) -> EntityId {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("role"), rmpv::Value::from(role))]),
    )
    .expect("turn bytes");
    let turn = EntityId::now();
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("a turn row");
    turn
}

/// A fresh slip id from two entity ids
/// (tests/gate_pins_authority_custody_grants.rs G184).
fn slip_id() -> [u8; 32] {
    let first = EntityId::now();
    let second = EntityId::now();
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(first.as_bytes());
    id[16..].copy_from_slice(second.as_bytes());
    id
}

/// A live person's own verified human slip, cut from the host root with a
/// fresh id and verified on its binding (G184).
fn own_verified_slip(vault: &Vault, holder: EntityId, challenge: &[u8]) -> VerifiedSlip {
    let issuer = test_host_issuer().expect("the test host issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip");
    let mut claims = root.claims;
    claims.slip_id = slip_id();
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the person's own slip");
    let binding = issuer
        .binding_proof(&slip, challenge)
        .expect("the binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &binding)
        .expect("the slip verifies")
}

/// The owner's own proof at owner tier, as tests/owner_ask_word_proof.rs
/// builds it: `authenticate_owner` with no credential, which
/// `revalidate_in_txn` holds while the actor is a live owner.
fn owner_proof(vault: &Vault, owner: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof")
}

/// A live person's own person-tier proof (G184): `authenticate_owner`, then
/// their own human slip bound as the request slip and as the person
/// credential. It carries no owner authority.
fn person_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    let verified = own_verified_slip(vault, person, b"ask-answer-proof-person");
    let proof = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("the person's proof");
    let proof = vault
        .bind_request_credential(proof, verified.clone())
        .expect("the request slip binds");
    vault
        .bind_person_credential(proof, verified)
        .expect("the person credential binds")
}

/// A root run of the seeded default agent with one level of delegation left:
/// its attempt and the actor it runs as (tests/run_wait_agents.rs).
fn root_run(vault: &Vault, run: &str, now: u64) -> (AttemptId, WriteActor) {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .expect("the seed reads")
        .expect("the default agent is seeded");
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now,
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )
        .expect("one fresh root run")
    else {
        panic!("expected one fresh root run");
    };
    let actor = agent_dispatch_actor(&status.input).expect("the run's actor");
    (status.attempt.id, actor)
}

/// A child of `parent`, as the run's dispatcher spawns one (run_wait_agents.rs
/// `spawn_child`, also answering the actor it runs as).
fn spawn_child(
    vault: &Vault,
    parent: AttemptId,
    run: &str,
    key: &str,
    now: u64,
) -> (AttemptId, WriteActor) {
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_default_base(
            Some(parent),
            Some(key.to_owned()),
            Some(run.to_owned()),
            now,
        )
        .expect("one fresh child")
    else {
        panic!("expected one fresh child");
    };
    let actor = agent_dispatch_actor(&status.input).expect("the child's actor");
    (status.attempt.id, actor)
}

/// Leases `id` to this test's worker and answers its row (run_wait_agents.rs
/// `claim`).
fn claim(vault: &Vault, id: AttemptId) -> AttemptRecord {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: WORKER.to_owned(),
                    now: u64::MAX,
                },
            )
            .expect("the claim reads")
        else {
            break;
        };
        if row.id == id {
            return queue
                .get(id)
                .expect("the claim reads back")
                .expect("a claimed row reads back");
        }
    }
    panic!("the attempt is ready to claim");
}

/// A word on `result` naming `option`.
fn word(result: EntityId, option: &str) -> TaskAskWord {
    let mut word = TaskAskWord::new(result);
    word.option = Some(TaskAskOptionId::new(option).expect("the option id"));
    word
}

/// Asserts `result` is the gate's refusal of a word that lacks its asked
/// party's live proof: `FORBIDDEN` carrying
/// `GateError::ConsentOwnerNotAuthenticated`'s words with the kind's `reason`.
fn assert_owner_proof_refusal<T: std::fmt::Debug>(result: MemoryResult<T>, reason: &str) {
    let error = result.expect_err("the word without its proof is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "the refusal code: {error:?}"
    );
    assert!(
        error.message.contains("consent owner not authenticated"),
        "the refusal is the gate's owner-proof refusal: {error:?}"
    );
    assert!(
        error.message.contains(reason),
        "the refusal names its kind: {error:?}"
    );
}

/// The owner's Human word on a code consent ask, with no proof bound, is
/// refused; the same owner with the owner proof is admitted.
///
/// Base: the word without the proof is admitted, so the refusal assertion
/// fails. Head: it is refused with `ConsentOwnerNotAuthenticated`, and the
/// word under the owner proof is admitted.
#[test]
fn a_code_consent_owner_word_without_the_owner_proof_is_refused() {
    let fx = fixture();
    let handle = mint_code_consent_ask(&fx.vault, fx.owner, &[]).expect("the code consent ask");
    let result = put_turn(&fx.vault, 11, "answer");
    let memory = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    assert_owner_proof_refusal(
        memory.tasks_answer(&handle, &word(result, "approve_once")),
        "a code consent answer needs the asked person's own authenticated word",
    );
    let proof = owner_proof(&fx.vault, fx.owner);
    memory
        .with_owner_authorship(&proof)
        .tasks_answer(&handle, &word(result, "approve_once"))
        .expect("the owner's word under the owner proof is admitted");
}

/// A non-owner holder's Human word on a code consent ask is refused without
/// a proof, and admitted under the holder's own person-tier proof.
///
/// Base: the word without the proof is admitted, so the refusal assertion
/// fails. Head: it is refused with `ConsentOwnerNotAuthenticated`, and the
/// word under the person proof is admitted (as on the base).
#[test]
fn a_code_consent_holder_word_needs_the_person_proof() {
    let fx = fixture();
    let holder = put_person(&fx.vault, 10, b"holder");
    let handle =
        mint_code_consent_ask(&fx.vault, fx.owner, &[holder]).expect("the code consent ask");
    let result = put_turn(&fx.vault, 11, "answer");
    let memory = fx.vault.memory(holder, EdgeActorClass::Human);
    assert_owner_proof_refusal(
        memory.tasks_answer(&handle, &word(result, "approve_once")),
        "a code consent answer needs the asked person's own authenticated word",
    );
    let proof = person_proof(&fx.vault, holder);
    memory
        .with_owner_authorship(&proof)
        .tasks_answer(&handle, &word(result, "approve_once"))
        .expect("the holder's word under the person proof is admitted");
}

/// The owner's Human word on a comm widen ask to the owner, with no proof
/// bound, is refused; the same owner with the owner proof is admitted.
///
/// Base: the word without the proof is admitted, so the refusal assertion
/// fails. Head: it is refused with `ConsentOwnerNotAuthenticated`, and the
/// word under the owner proof is admitted.
#[test]
fn a_comm_widen_owner_word_without_the_owner_proof_is_refused() {
    let fx = fixture();
    let (root, actor) = root_run(&fx.vault, RUN, 3);
    let leased = claim(&fx.vault, root);
    let child = fx
        .vault
        .memory(actor.entity_ref(), actor.actor_class())
        .with_task_host(HostBinding::from_leased(&leased, None).expect("the bound run"));
    let handle = raise_comm_widen_ask(&child, root, CommReach::Subtree).expect("the widen ask");
    let result = put_turn(&fx.vault, 11, "answer");
    let memory = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    assert_owner_proof_refusal(
        memory.tasks_answer(&handle, &word(result, "approve_once")),
        "a comm widen answer needs the owner's own authenticated word",
    );
    let proof = owner_proof(&fx.vault, fx.owner);
    memory
        .with_owner_authorship(&proof)
        .tasks_answer(&handle, &word(result, "approve_once"))
        .expect("the owner's word under the owner proof is admitted");
}

/// A child dispatch's widen ask to its parent agent is answered by the parent
/// agent's own word, with no proof: an agent answers as its verified actor.
///
/// Base and head alike: the parent agent's `approve` word is admitted, and
/// the ask settles on it.
#[test]
fn a_comm_widen_agent_word_is_admitted_from_its_verified_agent() {
    let fx = fixture();
    let (root, root_actor) = root_run(&fx.vault, RUN, 3);
    let (child, child_actor) = spawn_child(&fx.vault, root, RUN, "widen-child", 4);
    let leased = claim(&fx.vault, child);
    let surface = fx
        .vault
        .memory(child_actor.entity_ref(), child_actor.actor_class())
        .with_task_host(HostBinding::from_leased(&leased, None).expect("the bound run"));
    let handle = raise_comm_widen_ask(&surface, child, CommReach::Subtree).expect("the widen ask");
    let result = put_turn(&fx.vault, 11, "answer");
    let parent = fx
        .vault
        .memory(root_actor.entity_ref(), EdgeActorClass::Agent);
    parent
        .tasks_answer(&handle, &word(result, "approve"))
        .expect("the parent agent's word is admitted");
    let status = parent.tasks_ask_status(handle).expect("the ask reads");
    assert!(
        matches!(&status, TaskAskStatus::Settled(result) if matches!(result.decision, TaskAskDecision::First(_))),
        "the agent's word cuts the ask: {status:?}"
    );
}

/// A code consent holder's relayed word is admitted under the holder's own
/// person proof, which the admitting node mints from the holder's verified
/// slip (tests/ask_forward_intent_secret_scan.rs, whole fixture).
///
/// Base and head alike: the forwarded word is answered (`Answered`).
#[test]
fn a_forwarded_holder_word_carries_the_person_proof() {
    let fx = fixture();
    let holder = put_person(&fx.vault, 10, b"holder");
    let handle =
        mint_code_consent_ask(&fx.vault, fx.owner, &[holder]).expect("the code consent ask");
    let issuer = test_host_issuer().expect("the test host issuer");
    let root = fx
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip");
    let holder_key =
        SigningKey::from_bytes(blake3::hash(b"ask-answer-proof-holder-key").as_bytes());
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(b"ask-answer-proof-holder-slip").as_bytes();
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key.verifying_key().to_bytes();
    let slip = fx
        .vault
        .mint_capability_slip(&issuer, claims)
        .expect("the holder's own slip");
    let token = slip.to_token().expect("the slip token");
    let result = put_turn(&fx.vault, 11, "answer");
    let memory = fx.vault.memory(holder, EdgeActorClass::Human);
    let act = AskForwardAct::Word(word(result, "approve_once"));
    let intent_key = "holder-forward-1";
    let challenge = memory
        .tasks_answer_forward_challenge(&handle, intent_key, &act)
        .expect("the forward challenge");
    let signature = holder_key
        .sign(
            &slip
                .binding_transcript(&challenge)
                .expect("the binding transcript"),
        )
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let receipt = memory
        .tasks_answer_forward(
            &handle,
            intent_key,
            &act,
            &AskForwardHolderProof {
                token: token.clone(),
                signature,
            },
        )
        .expect("the relayed word is admitted");
    assert!(
        matches!(&receipt, AskForwardReceipt::Answered { .. }),
        "the forwarded holder word is answered: {receipt:?}"
    );
}

/// A code consent first word admitted under the owner proof, with no
/// settlement yet, cuts only in a transaction that carries the proof.
///
/// Base: a status read with no proof bound cuts it (`Settled`), so the
/// waiting assertion fails. Head: the status read waits (`Pending`); the cut
/// lands when the same word is answered again under the owner proof (an
/// idempotent re-admission whose transaction settles under the proof), and
/// the ask then reads `Settled`.
///
/// A proof-bound status read waits too: `tasks_ask_status` settles with no
/// proof (`settle_in`), so the proof it carries cuts nothing. The test pins
/// that as well.
#[test]
fn a_code_consent_first_word_cuts_only_under_the_proof() {
    let fx = fixture();
    let handle = mint_code_consent_ask(&fx.vault, fx.owner, &[]).expect("the code consent ask");
    let result = put_turn(&fx.vault, 11, "answer");
    let proof = owner_proof(&fx.vault, fx.owner);
    let writer = WriteActor::new(fx.owner, EdgeActorClass::Human);
    admit_word_unsettled(
        &fx.vault,
        &handle,
        writer,
        &word(result, "approve_once"),
        Some(&proof),
    )
    .expect("the owner's word is admitted under the owner proof");
    let memory = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let proven = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .with_owner_authorship(&proof);
    let status = memory.tasks_ask_status(handle).expect("the ask reads");
    assert!(
        matches!(&status, TaskAskStatus::Pending { .. }),
        "the admitted word waits for its proof in the cutting transaction: {status:?}"
    );
    let status = proven.tasks_ask_status(handle).expect("the ask reads");
    assert!(
        matches!(&status, TaskAskStatus::Pending { .. }),
        "a status read settles with no proof, so the word still waits: {status:?}"
    );
    proven
        .tasks_answer(&handle, &word(result, "approve_once"))
        .expect("the word answered again under the proof cuts");
    let status = memory.tasks_ask_status(handle).expect("the ask reads");
    assert!(
        matches!(&status, TaskAskStatus::Settled(_)),
        "the proof's transaction cut the ask: {status:?}"
    );
}
