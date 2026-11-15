//! The reveal family's doors: an agent asks for a secret's value by its handle,
//! and `reveal.wait` collects the grant decision with the value only under a grant.
//!
//! Proves through `oneiron_testkit::door::invoke`, the in-process verb door:
//! P1, `peek` and `wait` on the secret handle itself never return the value;
//! P2, `reveal` returns a pending handle; P3, `wait` on that pending handle
//! returns the grant decision and, under a grant, the value with a receipt.
//! Plus the two guards on the value: with no grant the wait stays pending and
//! value-free, and another agent's reveal reads as not found.
//!
//! Canon `oneiron/agents/oneiron-arch-0067-context-board-v1.md:308`: "`peek`
//! and `wait` on the secret handle itself never return the value. `reveal`
//! returns a pending handle. `wait` on that pending handle returns the grant
//! decision and, under a grant, the value with a receipt." Canon
//! `oneiron/gate/oneiron-arch-0069-secret-custody-v1.md:277` ("What each verb
//! gives back on a secret handle", owner, 2026-10-08) says the same.
//!
//! Secrets come from the public out-of-crate fixture
//! `Vault::register_test_secret` (`test-support`, on under `--all-features`);
//! the owner grants and denies through public `Vault::secret_reveals` and
//! `Vault::answer_secret_reveal`. No `test_doors` item, no real host.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test reveal_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::retrieval_depth::short_ref_or_hex;
use oneiron::secret_custody::SecretRevealAnswer;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault};
use oneiron_keystore::MemoryKeystore;
use oneiron_testkit::{FAKE_EPOCH, TestVault, door};
use serde_json::{Value, json};

/// The value the fixture secret holds: UTF-8, so a granted `reveal.wait`
/// carries it as `value`.
const SECRET_VALUE: &str = "reveal-doors-fixture-value-9f31";
/// The agent's why on every reveal: one line, no credential in it.
const SECRET_WHY: &str = "the model needs the value for this step";

/// One test's vault: the open vault, then the copy that owns its temp dir
/// (declared last, so the vault closes before the dir goes).
struct RevealFixture {
    vault: Vault,
    _test_vault: TestVault,
}

impl RevealFixture {
    /// An empty vault, opened owned so owner doors run, with a memory
    /// keystore so custody seals, and its embedded owner present.
    fn open(seed_name: &str) -> Self {
        let test_vault = TestVault::seeded(seed_name, |_, _| Ok(())).expect("seed an empty vault");
        let vault = test_vault.open_owned().expect("open the vault owned");
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("prepare install signing");
        vault
            .ensure_embedded_owner_actor()
            .expect("ensure the embedded owner");
        Self {
            vault,
            _test_vault: test_vault,
        }
    }

    /// The agent principal `name` acts as.
    fn agent_id(&self, name: &str) -> EntityId {
        self.vault
            .ensure_agent_principal(name)
            .expect("ensure the agent principal")
    }

    /// The vault's embedded owner.
    fn owner_id(&self) -> EntityId {
        self.vault
            .ensure_embedded_owner_actor()
            .expect("ensure the embedded owner")
    }
}

/// Registers one portable secret holding `SECRET_VALUE` with no bindings (a
/// masked secret's shape), and answers its id beside its `sc` handle as the
/// engine writes it (`scN:hh`).
fn register_secret_handle(fixture: &RevealFixture, secret_name: &str) -> (EntityId, String) {
    let secret_id = fixture
        .vault
        .register_test_secret(secret_name, SECRET_VALUE.as_bytes(), Vec::new(), FAKE_EPOCH)
        .expect("register the fixture secret");
    let handle_text =
        short_ref_or_hex(&fixture.vault, &secret_id).expect("read the secret's handle");
    assert!(
        handle_text.starts_with("sc"),
        "the custody handle is an sc handle: {handle_text}"
    );
    (secret_id, handle_text)
}

/// `reveal` as `agent` for `handle_text`: the pending reveal id, as 32 hex.
fn reveal_pending_hex(fixture: &RevealFixture, agent: EntityId, handle_text: &str) -> String {
    let caller = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let pending: Value = door::invoke(
        &caller,
        "reveal",
        json!({"handle": handle_text, "why": SECRET_WHY}),
    )
    .expect("the agent reveals the handle");
    pending["reveal"]
        .as_str()
        .expect("a pending reveal id")
        .to_owned()
}

/// `reveal.wait` as `agent` for `reveal_hex`: the wait answer.
fn wait_reveal_answer(fixture: &RevealFixture, agent: EntityId, reveal_hex: &str) -> Value {
    let caller = fixture.vault.memory(agent, EdgeActorClass::Agent);
    door::invoke(&caller, "reveal.wait", json!({"reveal": reveal_hex}))
        .expect("the agent waits its reveal")
}

/// The owner answers the waiting reveal `reveal_hex` with `answer`
/// (`Once` grants this reveal, `Deny` refuses it).
fn owner_answer_reveal(fixture: &RevealFixture, reveal_hex: &str, answer: SecretRevealAnswer) {
    let owner_actor = fixture.owner_id();
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            owner_actor,
            &owner_actor.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("authenticate the owner");
    let reveal_id = EntityId::from_hex(reveal_hex).expect("the pending reveal parses");
    let waiting = fixture
        .vault
        .secret_reveals(&owner_proof, true, 50)
        .expect("the owner reads the waiting asks");
    let ask = waiting
        .iter()
        .find(|ask| ask.receipt.reveal == reveal_id)
        .expect("the reveal waits on the owner");
    let digest = ask.once_digest.expect("the ask carries its digest");
    fixture
        .vault
        .answer_secret_reveal(&owner_proof, &reveal_id, digest.as_bytes(), answer)
        .expect("the owner answers the reveal");
}

/// Asserts the serialized `answer` holds no copy of the secret value.
fn assert_value_absent(answer: &Value, what: &str) {
    let serialized = serde_json::to_string(answer).expect("serialize the answer");
    assert!(
        !serialized.contains(SECRET_VALUE),
        "{what} carries no secret value: {serialized}"
    );
}

/// P1: `peek` and `wait` on the secret handle itself never return the value.
///
/// Canon `oneiron/agents/oneiron-arch-0067-context-board-v1.md:308`: "`peek`
/// and `wait` on the secret handle itself never return the value." Canon
/// `oneiron/gate/oneiron-arch-0069-secret-custody-v1.md:277` says the same.
#[test]
fn peek_and_wait_on_the_secret_handle_itself_never_return_the_value() {
    let fixture = RevealFixture::open("reveal-p1");
    let agent = fixture.agent_id("reveal-p1-agent");
    let (secret_id, handle_text) = register_secret_handle(&fixture, "reveal-p1-secret");
    let caller = fixture.vault.memory(agent, EdgeActorClass::Agent);
    // The bare `peek` takes an ask handle, not a secret handle.
    let peek_refused = door::invoke(&caller, "peek", json!({"group_ref": handle_text}))
        .expect_err("peek on a secret handle is refused");
    assert_eq!(peek_refused.code, "BAD_REQUEST", "the peek refusal code");
    assert!(
        peek_refused.message.starts_with("invalid SDK request:"),
        "the peek refusal names its bad input: {}",
        peek_refused.message
    );
    assert!(
        !peek_refused.message.contains(SECRET_VALUE),
        "the peek refusal carries no value: {}",
        peek_refused.message
    );
    // The bare `wait` takes an ask handle and a step key, not a secret handle.
    let wait_refused = door::invoke(
        &caller,
        "wait",
        json!({"handle": {"group_ref": handle_text}, "step_key": "reveal-p1"}),
    )
    .expect_err("wait on a secret handle is refused");
    assert_eq!(wait_refused.code, "BAD_REQUEST", "the wait refusal code");
    assert!(
        wait_refused.message.starts_with("invalid SDK request:"),
        "the wait refusal names its bad input: {}",
        wait_refused.message
    );
    assert!(
        !wait_refused.message.contains(SECRET_VALUE),
        "the wait refusal carries no value: {}",
        wait_refused.message
    );
    // `reveal.wait` takes a reveal id: the handle is not one.
    let reveal_wait_refused = door::invoke(&caller, "reveal.wait", json!({"reveal": handle_text}))
        .expect_err("reveal.wait on the secret handle is refused");
    assert_eq!(
        reveal_wait_refused.code, "BAD_REQUEST",
        "the reveal.wait refusal code"
    );
    assert_eq!(
        reveal_wait_refused.message, "reveal is not a reveal id",
        "the reveal.wait refusal message"
    );
    // Even the secret's own entity id finds no reveal row.
    let unknown_reveal = door::invoke(
        &caller,
        "reveal.wait",
        json!({"reveal": secret_id.to_hex()}),
    )
    .expect_err("reveal.wait on the secret's id finds no reveal");
    assert_eq!(unknown_reveal.code, "NOT_FOUND", "the unknown reveal code");
    assert_eq!(
        unknown_reveal.message, "entity not found",
        "the unknown reveal message"
    );
    // `reveal.describe` shows the card: label and status, never the value.
    let card: Value = door::invoke(&caller, "reveal.describe", json!({"handle": handle_text}))
        .expect("the agent describes the handle");
    assert_eq!(
        card["label"].as_str(),
        Some("reveal-p1-secret"),
        "the card names the custody name: {card}"
    );
    assert_eq!(
        card["status"].as_str(),
        Some("active"),
        "the card shows active: {card}"
    );
    assert_eq!(
        card["class"].as_str(),
        Some("custody-portable"),
        "the card shows the class: {card}"
    );
    assert!(
        card.get("value").is_none() && card.get("value_base64").is_none(),
        "the card has no value field: {card}"
    );
    assert_value_absent(&card, "the describe card");
    // A handle that names no secret is refused, naming the handle, no value.
    let unknown_handle = door::invoke(
        &caller,
        "reveal",
        json!({"handle": "sc999999", "why": SECRET_WHY}),
    )
    .expect_err("a reveal of an unknown handle is refused");
    assert_eq!(
        unknown_handle.code, "BAD_REQUEST",
        "the unknown handle code"
    );
    assert_eq!(
        unknown_handle.message, "no live secret custody record for ref `sc999999`",
        "the unknown handle message"
    );
}

/// P2: `reveal` returns a pending handle.
///
/// Canon `oneiron/agents/oneiron-arch-0067-context-board-v1.md:308`:
/// "`reveal` returns a pending handle." Canon
/// `oneiron/gate/oneiron-arch-0069-secret-custody-v1.md:277` says the same.
#[test]
fn reveal_returns_a_pending_handle() {
    let fixture = RevealFixture::open("reveal-p2");
    let agent = fixture.agent_id("reveal-p2-agent");
    let (_secret_id, handle_text) = register_secret_handle(&fixture, "reveal-p2-secret");
    let caller = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let pending: Value = door::invoke(
        &caller,
        "reveal",
        json!({"handle": handle_text, "why": SECRET_WHY}),
    )
    .expect("the agent reveals the handle");
    let pending_hex = pending["reveal"]
        .as_str()
        .expect("a pending reveal id")
        .to_owned();
    assert_eq!(
        pending_hex.len(),
        32,
        "the pending handle is 32 hex: {pending}"
    );
    assert!(
        pending_hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "the pending handle is hex: {pending}"
    );
    EntityId::from_hex(&pending_hex).expect("the pending handle parses");
    assert_value_absent(&pending, "the pending answer");
    // Every call gets its own pending handle.
    let pending_again: Value = door::invoke(
        &caller,
        "reveal",
        json!({"handle": handle_text, "why": SECRET_WHY}),
    )
    .expect("the agent reveals the handle again");
    let pending_again_hex = pending_again["reveal"]
        .as_str()
        .expect("a second pending reveal id")
        .to_owned();
    assert_ne!(
        pending_hex, pending_again_hex,
        "each reveal mints its own pending handle"
    );
    assert_value_absent(&pending_again, "the second pending answer");
}

/// P3: `wait` on that pending handle returns the grant decision and, under a
/// grant, the value with a receipt.
///
/// Canon `oneiron/agents/oneiron-arch-0067-context-board-v1.md:308`: "`wait`
/// on that pending handle returns the grant decision and, under a grant, the
/// value with a receipt." Canon
/// `oneiron/gate/oneiron-arch-0069-secret-custody-v1.md:277` says the same.
#[test]
fn wait_on_the_pending_handle_returns_the_decision_and_the_granted_value_with_a_receipt() {
    let fixture = RevealFixture::open("reveal-p3");
    let agent = fixture.agent_id("reveal-p3-agent");
    let (_secret_id, handle_text) = register_secret_handle(&fixture, "reveal-p3-secret");
    let bare_handle = handle_text.split(':').next().expect("the bare handle");
    let answered_by = format!("owner:{}", fixture.owner_id().to_hex());
    let agent_connection = format!("agent:{}", agent.to_hex());
    // The owner grants the first reveal once.
    let granted_hex = reveal_pending_hex(&fixture, agent, &handle_text);
    owner_answer_reveal(&fixture, &granted_hex, SecretRevealAnswer::Once);
    // The first granted wait carries the value with its receipt.
    let granted = wait_reveal_answer(&fixture, agent, &granted_hex);
    assert_eq!(
        granted["decision"].as_str(),
        Some("granted"),
        "the granted decision: {granted}"
    );
    assert_eq!(
        granted["value"].as_str(),
        Some(SECRET_VALUE),
        "the granted wait carries the value"
    );
    assert!(
        granted.get("value_base64").is_none(),
        "a text value travels as value: {granted}"
    );
    let receipt = &granted["receipt"];
    assert_eq!(
        receipt["handle"].as_str(),
        Some(bare_handle),
        "the receipt names the handle: {granted}"
    );
    assert_eq!(
        receipt["class"].as_str(),
        Some("custody-portable"),
        "the receipt names the class: {granted}"
    );
    assert_eq!(
        receipt["why"].as_str(),
        Some(SECRET_WHY),
        "the receipt keeps the why: {granted}"
    );
    assert_eq!(
        receipt["connection"].as_str(),
        Some(agent_connection.as_str()),
        "the receipt names the connection: {granted}"
    );
    assert_eq!(
        receipt["answered_by"].as_str(),
        Some(answered_by.as_str()),
        "the receipt names who answered: {granted}"
    );
    assert!(
        receipt["decision"]
            .as_str()
            .is_some_and(|decision| decision.starts_with("gate:")),
        "the receipt names the consent act: {granted}"
    );
    assert!(
        receipt["lease"]
            .as_str()
            .is_some_and(|lease| lease.len() == 32),
        "the granted receipt names its lease: {granted}"
    );
    assert!(
        receipt["delivered_at"].as_u64().is_some(),
        "the granted receipt is stamped: {granted}"
    );
    // The second wait answers granted with the receipt and no value.
    let granted_again = wait_reveal_answer(&fixture, agent, &granted_hex);
    assert_eq!(
        granted_again["decision"].as_str(),
        Some("granted"),
        "the second wait stays granted: {granted_again}"
    );
    assert!(
        granted_again.get("value").is_none() && granted_again.get("value_base64").is_none(),
        "the second wait carries no value field: {granted_again}"
    );
    assert_value_absent(&granted_again, "the second wait");
    // The owner denies the second reveal: decision denied, receipt, no value.
    let denied_hex = reveal_pending_hex(&fixture, agent, &handle_text);
    owner_answer_reveal(&fixture, &denied_hex, SecretRevealAnswer::Deny);
    let denied = wait_reveal_answer(&fixture, agent, &denied_hex);
    assert_eq!(
        denied["decision"].as_str(),
        Some("denied"),
        "the denied decision: {denied}"
    );
    assert!(
        denied.get("value").is_none() && denied.get("value_base64").is_none(),
        "the denied wait carries no value field: {denied}"
    );
    assert_value_absent(&denied, "the denied wait");
    assert_eq!(
        denied["receipt"]["answered_by"].as_str(),
        Some(answered_by.as_str()),
        "the denial names who answered: {denied}"
    );
}

/// With no grant, the wait stays pending and the value stays withheld.
///
/// Canon `oneiron/gate/oneiron-arch-0069-secret-custody-v1.md:279`:
/// "Outside, one ask goes to the owner, with the why on it."
#[test]
fn without_a_grant_the_wait_stays_pending_and_the_value_stays_withheld() {
    let fixture = RevealFixture::open("reveal-no-grant");
    let agent = fixture.agent_id("reveal-no-grant-agent");
    let (_secret_id, handle_text) = register_secret_handle(&fixture, "reveal-no-grant-secret");
    let pending_hex = reveal_pending_hex(&fixture, agent, &handle_text);
    // Nothing granted: the wait answers pending, with no value.
    let waiting = wait_reveal_answer(&fixture, agent, &pending_hex);
    assert_eq!(
        waiting["decision"].as_str(),
        Some("pending"),
        "the ungranted wait pends: {waiting}"
    );
    assert!(
        waiting.get("value").is_none() && waiting.get("value_base64").is_none(),
        "the pending wait carries no value field: {waiting}"
    );
    assert_value_absent(&waiting, "the pending wait");
    // The card says a reveal would ask the owner.
    let caller = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let card: Value = door::invoke(&caller, "reveal.describe", json!({"handle": handle_text}))
        .expect("the agent describes the handle");
    assert_eq!(
        card["reveal"].as_str(),
        Some("asks"),
        "with no grant the handle asks: {card}"
    );
    assert!(card["grant_ref"].is_null(), "no grant covers it: {card}");
    assert_value_absent(&card, "the describe card");
}

/// Another agent's reveal reads as not found, even once it granted.
///
/// The engine's own words, `crates/oneiron/src/secret_custody/reveal/agent.rs`
/// (`wait_secret_reveal`): "Another agent's reveal reads as not found."
#[test]
fn a_wait_on_a_reveal_that_is_not_the_callers_is_refused() {
    let fixture = RevealFixture::open("reveal-not-callers");
    let agent = fixture.agent_id("reveal-not-callers-agent");
    let other = fixture.agent_id("reveal-not-callers-other");
    let (_secret_id, handle_text) = register_secret_handle(&fixture, "reveal-not-callers-secret");
    let pending_hex = reveal_pending_hex(&fixture, agent, &handle_text);
    owner_answer_reveal(&fixture, &pending_hex, SecretRevealAnswer::Once);
    let _delivered = wait_reveal_answer(&fixture, agent, &pending_hex);
    // The value went out to its asker; the other agent's wait is refused.
    let stranger = fixture.vault.memory(other, EdgeActorClass::Agent);
    let refused = door::invoke(&stranger, "reveal.wait", json!({"reveal": pending_hex}))
        .expect_err("another agent's reveal reads as not found");
    assert_eq!(refused.code, "NOT_FOUND", "the stranger refusal code");
    assert_eq!(
        refused.message, "entity not found",
        "the stranger refusal message"
    );
    assert!(
        !refused.message.contains(SECRET_VALUE),
        "the refusal carries no value: {}",
        refused.message
    );
}
