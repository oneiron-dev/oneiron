//! ROLES-CHECKIN P2.3b, piece 2f (ARCH-0082 #composing and #ladder; Engine
//! ruling P23-SHAPE Q2, Q5, Q6, Q10 and Q11 = A): `vault.check_in.preflight`
//! and `vault.check_in.open` through the generated verb dispatch, JSON in and
//! JSON out, on the caller's own `Memory`.
//!
//! - The act class is the verb row's own: an always-ask act waits, an act
//!   asked when unsure waits too (no decision model is sure), reversible work
//!   goes, a read verb goes on the power, an `unstated` verb opens nothing.
//! - The role and the power are the caller's own live owner Grant's: no Grant
//!   listing the verb, or a Grant whose worlds miss the effect, is absent (an
//!   erase may still be proposed); the vault owner goes on its own proof; a
//!   person without a Grant is refused.
//! - `preflight` writes nothing. `open` opens the durable ask on the
//!   grantor's rung; a repeat of the same saved call, after a restart too,
//!   returns the same handle and writes nothing; another effect is another
//!   ask; once the asker's `until` lets it go, the same call is asked afresh.
//!
//! On the base (P2.3a) this file builds and every case fails at its first
//! call: no verb row is named `vault.check_in.*`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_agent_verbs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const PREFLIGHT: &str = "vault.check_in.preflight";
const OPEN: &str = "vault.check_in.open";
/// `outbound_send`: a Delegate holds it only when named, and then always asks.
const SEND: &str = "connector.call";
/// `spawn`: a Delegate asks when unsure.
const SPAWN: &str = "self.agents.spawn";
/// `reversible_work`: a Delegate goes.
const REVERSIBLE: &str = "vault.projects.goal.propose";
/// A `read` verb.
const READ: &str = "vault.gate.decision.get";
/// An `unstated` verb.
const UNSTATED: &str = "vault.evals.labels.ask";
/// `erase`: any role may propose it.
const ERASE: &str = "vault.records.erase_confirm";

const T0: u64 = 1_790_000_000;
const HOUR: u64 = 60 * 60;

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    keystore: Arc<MemoryKeystore>,
    dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled, so the owner's Grant acts
    /// on `ThisInstall` land.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let vault = open_on(&dir, &clock, &keystore);
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
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            clock,
            keystore,
            dir,
            owner,
            owner_proof,
        }
    }

    /// The same vault, closed and opened again on the same clock and keys.
    fn reopen(self) -> Self {
        let Self {
            vault,
            clock,
            keystore,
            dir,
            owner,
            owner_proof,
        } = self;
        drop(vault);
        let vault = open_on(&dir, &clock, &keystore);
        Self {
            vault,
            clock,
            keystore,
            dir,
            owner,
            owner_proof,
        }
    }

    /// An enabled, active agent definition the owner creates.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("check-in-asker-{}", id.to_hex()),
                    "desc": "check-in asker fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        id
    }

    /// The owner's live Grant for `agent` naming `read` and `verbs`, over
    /// every world or over `world` alone; the Grant's id.
    fn grant(&self, agent: EntityId, verbs: &[&str], world: Option<EntityId>) -> EntityId {
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        if let Some(world) = world {
            scope.worlds = [ScopeId(world)].into_iter().collect();
        }
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the Grant");
        assert!(minted.grant.confers, "the Grant confers");
        minted.grant.grant_ref
    }

    fn as_agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }

    /// A live person who is not the owner.
    fn person(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .expect("person row");
        id
    }

    /// Every `check_in` receipt in the vault.
    fn receipts(&self) -> Vec<String> {
        let mut query = ReceiptQuery::new(100);
        query.kinds = [ReceiptKind::CheckIn].into();
        let mut receipts = self.vault.receipts(query).expect("receipts");
        receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
        receipts
            .into_iter()
            .map(|receipt| receipt.outcome)
            .collect()
    }
}

fn open_on(
    dir: &tempfile::TempDir,
    clock: &Arc<ManualClock>,
    keystore: &Arc<MemoryKeystore>,
) -> Vault {
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::<MemoryKeystore>::clone(keystore));
    vault
}

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// An ask for `verb`'s act at the vault scope over the effect `byte`.
fn ask(verb: &str, byte: u8) -> Value {
    json!({ "verb": verb, "effect_digest": digest(byte) })
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> MemoryError {
    invoke(memory, verb, input).expect_err("the call is refused")
}

#[test]
fn preflight_answers_from_the_verb_rows_class_and_writes_nothing() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SEND, SPAWN, REVERSIBLE, READ, UNSTATED], None);
    let me = fx.as_agent(agent);
    let send = call(&me, PREFLIGHT, ask(SEND, 0x51));
    assert_eq!(
        send,
        json!({ "outcome": "wait", "reason": "always_ask", "act_class": "outbound_send",
                "mode": "manual", "handle": null }),
        "a named send always asks, and no ask is open"
    );
    let spawn = call(&me, PREFLIGHT, ask(SPAWN, 0x52));
    assert_eq!(
        (
            spawn["outcome"].as_str(),
            spawn["reason"].as_str(),
            spawn["mode"].as_str()
        ),
        (Some("wait"), Some("unsure"), Some("auto")),
        "no decision model is sure, so an act asked when unsure waits: {spawn}"
    );
    assert_eq!(
        call(&me, PREFLIGHT, ask(REVERSIBLE, 0x53)),
        json!({ "outcome": "go", "reason": "never_ask", "act_class": "reversible_work" })
    );
    assert_eq!(
        call(&me, PREFLIGHT, ask(READ, 0x54)),
        json!({ "outcome": "go", "reason": "read", "act_class": null })
    );
    assert_eq!(
        call(&me, PREFLIGHT, ask(UNSTATED, 0x55)),
        json!({ "outcome": "unstated" })
    );
    assert_eq!(
        call(&me, OPEN, ask(UNSTATED, 0x55)),
        json!({ "outcome": "unstated" }),
        "an unstated verb opens nothing"
    );
    assert!(
        fx.receipts().is_empty(),
        "nothing was opened: {:?}",
        fx.receipts()
    );
}

#[test]
fn a_caller_without_the_power_is_absent_and_may_propose_an_erase() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    let me = fx.as_agent(agent);
    let bare = call(&me, PREFLIGHT, ask(SEND, 0x61));
    assert_eq!(
        bare["outcome"].as_str(),
        Some("absent"),
        "no Grant at all: {bare}"
    );
    fx.grant(agent, &[REVERSIBLE], None);
    for verb in [PREFLIGHT, OPEN] {
        let unlisted = call(&me, verb, ask(SEND, 0x61));
        assert_eq!(
            (unlisted["outcome"].as_str(), unlisted["why"].as_str()),
            (
                Some("absent"),
                Some("no live owner Grant of the caller lists the verb")
            ),
            "{verb}: the Grant does not list the send"
        );
        assert_eq!(
            call(&me, verb, ask(ERASE, 0x62)),
            json!({ "outcome": "propose", "act_class": "erase" }),
            "{verb}: any role may propose an erase"
        );
    }
    let narrowed = fx.agent();
    fx.grant(narrowed, &[SEND], Some(base_world_id()));
    let narrow = fx.as_agent(narrowed);
    let outside = call(&narrow, OPEN, ask(SEND, 0x63));
    assert_eq!(
        (outside["outcome"].as_str(), outside["why"].as_str()),
        (
            Some("absent"),
            Some("the caller's Grant does not reach where the effect sits")
        ),
        "the Grant holds one world and the effect names none"
    );
    let inside = call(
        &narrow,
        PREFLIGHT,
        json!({ "verb": SEND, "world_ref": base_world_id().to_hex(), "effect_digest": digest(0x63) }),
    );
    assert_eq!(
        inside["outcome"].as_str(),
        Some("wait"),
        "inside its world: {inside}"
    );
    assert!(
        fx.receipts().is_empty(),
        "nothing was opened: {:?}",
        fx.receipts()
    );
}

#[test]
fn the_owner_goes_on_its_own_proof_and_a_person_without_a_grant_is_refused() {
    let fx = Fixture::rooted();
    let owner = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    for verb in [PREFLIGHT, OPEN] {
        assert_eq!(
            call(&owner, verb, ask(SEND, 0x71)),
            json!({ "outcome": "go", "reason": "own_proof", "act_class": "outbound_send" }),
            "{verb}"
        );
    }
    let person = fx.person();
    let error = refused(
        &fx.vault.memory(person, EdgeActorClass::Human),
        OPEN,
        ask(SEND, 0x71),
    );
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
    assert!(
        error
            .message
            .contains("neither the vault owner nor an agent"),
        "{error:?}"
    );
    assert!(
        fx.receipts().is_empty(),
        "nothing was opened: {:?}",
        fx.receipts()
    );
}

#[test]
fn a_digest_that_is_not_hex_and_a_name_no_row_has_are_bad_requests() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SEND], None);
    let me = fx.as_agent(agent);
    let short = refused(&me, OPEN, json!({ "verb": SEND, "effect_digest": "5e5e" }));
    assert_eq!(short.code, MEMORY_CODE_BAD_REQUEST, "{short:?}");
    assert!(short.message.contains("effect_digest"), "{short:?}");
    let unknown = refused(&me, PREFLIGHT, ask("vault.no_such_verb", 0x81));
    assert_eq!(unknown.code, MEMORY_CODE_BAD_REQUEST, "{unknown:?}");
    assert!(
        unknown.message.contains("vault.no_such_verb"),
        "{unknown:?}"
    );
}

#[test]
fn open_returns_a_handle_that_a_repeat_finds_again_after_a_restart() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    let grant = fx.grant(agent, &[SEND], None);
    let opened = call(&fx.as_agent(agent), OPEN, ask(SEND, 0x91));
    assert_eq!(
        (opened["outcome"].as_str(), opened["reason"].as_str()),
        (Some("wait"), Some("always_ask")),
        "{opened}"
    );
    let handle = &opened["handle"];
    assert_eq!(handle["state"].as_str(), Some("open"), "{handle}");
    assert_eq!(
        handle["rung"].as_str(),
        Some("grantor"),
        "the owner who granted it is asked"
    );
    assert_eq!(handle["repeat"].as_bool(), Some(false));
    let id = EntityId::from_hex(handle["handle"].as_str().expect("handle")).expect("id");
    let row = fx
        .vault
        .pending_check_in(&id)
        .expect("read")
        .expect("the row is stored");
    assert_eq!(
        (
            row.asker,
            row.grant_ref.as_str(),
            row.verb.as_str(),
            row.effect_digest
        ),
        (agent, grant.to_hex().as_str(), SEND, [0x91; 32]),
        "the row names the asker, its own Grant, the verb and the effect"
    );
    assert_eq!(
        row.current_rung().expect("a rung").holders[0].principal,
        fx.owner,
        "the grantor's rung pins the owner"
    );
    let receipts = fx.receipts();
    assert_eq!(
        receipts.first().map(String::as_str),
        Some("opened"),
        "{receipts:?}"
    );

    let fx = fx.reopen();
    let me = fx.as_agent(agent);
    let again = call(&me, OPEN, ask(SEND, 0x91));
    assert_eq!(
        again["handle"]["handle"], opened["handle"]["handle"],
        "the same saved call"
    );
    assert_eq!(again["handle"]["repeat"].as_bool(), Some(true));
    let seen = call(&me, PREFLIGHT, ask(SEND, 0x91));
    assert_eq!(
        seen["handle"]["handle"], opened["handle"]["handle"],
        "preflight names it too"
    );
    assert_eq!(fx.receipts(), receipts, "a repeat writes nothing");

    let other = call(&me, OPEN, ask(SEND, 0x92));
    assert_ne!(
        other["handle"]["handle"], opened["handle"]["handle"],
        "another effect"
    );
    assert_eq!(other["handle"]["repeat"].as_bool(), Some(false));
}

#[test]
fn an_ask_that_let_go_is_asked_afresh() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SPAWN], None);
    let me = fx.as_agent(agent);
    let first = call(
        &me,
        OPEN,
        json!({ "verb": SPAWN, "effect_digest": digest(0xA7), "until": T0 + HOUR }),
    );
    assert_eq!(first["handle"]["state"].as_str(), Some("open"), "{first}");
    fx.clock.set(T0 + HOUR);
    fx.vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping");
    let id = EntityId::from_hex(first["handle"]["handle"].as_str().expect("handle")).expect("id");
    let row = fx.vault.pending_check_in(&id).expect("read").expect("row");
    assert!(
        matches!(row.state, oneiron::check_in::PendingState::LetGo { .. }),
        "the pass lets the ask go at its until: {:?}",
        row.state
    );
    let seen = call(&me, PREFLIGHT, ask(SPAWN, 0xA7));
    assert_eq!(
        seen["handle"],
        Value::Null,
        "a let-go ask answers no repeat: {seen}"
    );
    let second = call(
        &me,
        OPEN,
        json!({ "verb": SPAWN, "effect_digest": digest(0xA7), "until": T0 + 3 * HOUR }),
    );
    assert_ne!(
        second["handle"]["handle"], first["handle"]["handle"],
        "asked afresh"
    );
    assert_eq!(second["handle"]["state"].as_str(), Some("open"), "{second}");
    assert_eq!(second["handle"]["repeat"].as_bool(), Some(false));
}
