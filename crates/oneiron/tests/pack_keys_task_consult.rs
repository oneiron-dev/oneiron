//! The consult expiry's recovery menu is the owner's pack Setting key.
//!
//! A consult past its deadline expires with an artifact that carries the
//! `task.consult.expiry_recovery` menu in force in that write: the shipped
//! three by default, then the owner's narrower menu once set, while the
//! first artifact keeps what was offered then. An empty, repeated, or
//! unknown menu is refused.
//!
//! `cargo test --locked -p oneiron --all-features --test pack_keys_task_consult`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    ConsultDigestRoute, ConsultPayload, ConsultPayloadRef, ConsultRecovery, TaskAssignee,
    TaskCreateSpec, TaskKind, TaskTtl, decode_consult_expiry_recovery,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value;
use serde_json::json;

/// The asker's clock time at create.
const ASK_NOW: u64 = 1_772_400_000;
/// The consult deadline, one minute after the ask.
const ASK_DEADLINE: u64 = ASK_NOW + 60;
/// The engine clock, pinned inside the ask window.
const CLOCK_AT: u64 = ASK_NOW + 30;
/// The owner's recovery menu key.
const KEY: &str = "task.consult.expiry_recovery";

/// One vault on a pinned clock, with its asker and peer in place.
struct Fixture {
    vault: Vault,
    asker: EntityId,
    peer: EntityId,
    _clock: Arc<ManualClock>,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A vault on a pinned clock, with the first-party asker and one peer.
fn open_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(CLOCK_AT);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    let asker = put_person(&vault, 0xE1);
    let peer = put_person(&vault, 0xE2);
    Fixture {
        vault,
        asker,
        peer,
        _clock: clock,
        _dir: dir,
    }
}

/// One PERSON row, by seed.
fn put_person(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("person id");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .expect("put person");
    id
}

/// One TURN holding a question, parsed as a typed consult ref.
fn put_question(vault: &Vault, seed: u8) -> ConsultPayloadRef {
    let turn = EntityId::from_bytes([seed; 16]).expect("turn id");
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("role"), Value::from("question"))]),
    )
    .expect("encode turn body");
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: ASK_NOW,
                end: ASK_NOW,
            },
            ASK_NOW,
            &body,
        )
        .expect("put turn");
    ConsultPayloadRef::parse(vault, &format!("tn_{}", turn.to_hex())).expect("parse turn ref")
}

/// One consult ask of `peer` about `question`, due at `deadline`.
fn consult_spec(question: ConsultPayloadRef, peer: EntityId, deadline: u64) -> TaskCreateSpec {
    TaskCreateSpec::new(Value::Nil, None, None, Some(ASK_NOW))
        .with_kind(TaskKind::Consult)
        .with_consult(ConsultPayload::question(
            question,
            Vec::new(),
            EntityId::now(),
        ))
        .with_assignee(TaskAssignee::Peer { actor_ref: peer })
        .with_ttl(TaskTtl::at(deadline))
}

/// One consult TASK on its peer's board.
fn open_consult(vault: &Vault, asker: EntityId, peer: EntityId, seed: u8) -> EntityId {
    let question = put_question(vault, seed);
    vault
        .memory(asker, EdgeActorClass::Agent)
        .tasks_create(&consult_spec(question, peer, ASK_DEADLINE))
        .expect("create consult")
        .task_ref
        .expect("the consult mints one TASK")
}

/// No digest route: the expiry still commits, with no digest scheduled.
fn no_digest_route(_asker: EntityId) -> MemoryResult<Option<ConsultDigestRoute>> {
    Ok(None)
}

/// The TASK's terminal `result_ref`, read off its stored body.
fn task_result_ref(vault: &Vault, task: EntityId) -> EntityId {
    let body = vault
        .get(&task)
        .expect("read task")
        .expect("the TASK stands");
    let value = rmpv::decode::read_value(&mut body.as_slice()).expect("the TASK body decodes");
    let Value::Map(entries) = &value else {
        panic!("the TASK body is one map");
    };
    let state = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("state"))
        .map(|(_, state)| state)
        .expect("the TASK carries its state");
    let Value::Map(state_entries) = state else {
        panic!("the lapsed TASK is terminal");
    };
    let terminal = state_entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("terminal"))
        .map(|(_, terminal)| terminal)
        .expect("the terminal state names its record");
    let Value::Map(terminal_entries) = terminal else {
        panic!("the terminal record is one map");
    };
    let disposition = terminal_entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("disposition"))
        .and_then(|(_, disposition)| disposition.as_str())
        .expect("the terminal record names its disposition");
    assert_eq!(disposition, "expired", "the lapsed TASK expired");
    let result = terminal_entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("result_ref"))
        .and_then(|(_, result)| result.as_str())
        .expect("the expiry names its artifact");
    EntityId::from_hex(result).expect("the artifact ref parses")
}

/// The recovery menu one expired consult's artifact offers.
fn expiry_menu(vault: &Vault, task: EntityId) -> Vec<ConsultRecovery> {
    let artifact = task_result_ref(vault, task);
    let body = vault
        .get(&artifact)
        .expect("read artifact")
        .expect("the artifact stands");
    decode_consult_expiry_recovery(&body).expect("the artifact decodes")
}

/// The embedded owner's proof.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof")
}

#[test]
fn a_lapsed_consult_offers_todays_three_recoveries_by_default_and_the_owners_menu_once_set() {
    let fx = open_fixture();
    let first = open_consult(&fx.vault, fx.asker, fx.peer, 0x7A);
    let report = fx
        .vault
        .settle_due_consults(ASK_DEADLINE + 1, &no_digest_route)
        .expect("sweep the due consult");
    assert_eq!(report.expired_task_refs, vec![first]);
    assert_eq!(
        expiry_menu(&fx.vault, first),
        vec![
            ConsultRecovery::RetryAssignee,
            ConsultRecovery::NudgeAssignee,
            ConsultRecovery::TryPeer(None),
        ]
    );

    let proof = owner_proof(&fx.vault);
    let outcome = fx
        .vault
        .set_setting(
            SettingCaller::Owner(&proof),
            SetSetting::vault_value(KEY, json!(["try_peer", "retry_assignee"])),
        )
        .expect("the owner sets the menu");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the set applies: {outcome:?}"
    );

    let second = open_consult(&fx.vault, fx.asker, fx.peer, 0x7B);
    assert_ne!(second, first, "the second ask mints a fresh TASK");
    let swept = fx
        .vault
        .settle_due_consults(ASK_DEADLINE + 2, &no_digest_route)
        .expect("sweep the second consult");
    assert_eq!(swept.expired_task_refs, vec![second]);
    assert_eq!(
        expiry_menu(&fx.vault, second),
        vec![
            ConsultRecovery::TryPeer(None),
            ConsultRecovery::RetryAssignee,
        ]
    );
    assert_eq!(
        expiry_menu(&fx.vault, first),
        vec![
            ConsultRecovery::RetryAssignee,
            ConsultRecovery::NudgeAssignee,
            ConsultRecovery::TryPeer(None),
        ],
        "the first artifact keeps what was offered then"
    );
}

#[test]
fn the_owner_cannot_set_an_empty_or_repeated_recovery_menu() {
    let fx = open_fixture();
    let proof = owner_proof(&fx.vault);
    for value in [
        json!([]),
        json!(["nudge_assignee", "nudge_assignee"]),
        json!(["call_assignee"]),
    ] {
        assert!(
            fx.vault
                .set_setting(
                    SettingCaller::Owner(&proof),
                    SetSetting::vault_value(KEY, value.clone())
                )
                .is_err(),
            "the menu {value} is refused"
        );
    }
}
