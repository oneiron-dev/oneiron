// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! FIX-LIST [ASK-OPTION-KEY-CREDENTIAL-NAME-MASKED]: an ask's option ids and
//! its outcome binding's mapping names are map keys the asker picks. The
//! vault's write-door secret scan, on by default, reads a key such as
//! `token`, `api-key` or `deploy_secret` as a credential name, and its mask
//! lifts that map member into custody, so the kept ask no longer decodes.
//! `tasks_ask` and the `can(ask)` preflight now refuse such a name up front,
//! with a BAD_REQUEST that names it. An ask whose names are neutral still
//! asks with the scan on.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test ask_option_credential_name`

use oneiron::llm::decision::questions::{OutcomeBinding, OutcomeSource};
use oneiron::memory::MemoryError;
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskOption, TaskAskOptionId, TaskAskQuestion,
    TaskAskSpec, TaskAskTarget, TaskAssignee,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use oneiron_testkit::dreamer::attach_test_host;

/// A device vault with its owner, the secret scan at its default (on), and
/// one TURN the asks are about. The vault drops before its directory.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    question: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    attach_test_host(&vault).unwrap();
    assert_eq!(
        vault.secret_scan_mode().unwrap(),
        SecretScanMode::On,
        "the write-door secret scan is on, its default"
    );
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )
    .unwrap();
    let question = EntityId::now();
    vault
        .put_entity(
            &question,
            ENTITY_TYPE_TURN,
            TimeRange { start: 2, end: 2 },
            2,
            &body,
        )
        .unwrap();
    Fixture {
        vault,
        _dir: dir,
        owner,
        question,
    }
}

impl Fixture {
    /// The owner's ask of themselves about the TURN, with these option ids
    /// and, if given, an outcome binding with these mapping names.
    fn spec(&self, intent_key: &str, options: &[&str], mapping: Option<&[&str]>) -> TaskAskSpec {
        let reference =
            ConsultPayloadRef::parse(&self.vault, &format!("tn_{}", self.question.to_hex()))
                .unwrap();
        let mut question = TaskAskQuestion::new(reference);
        for id in options {
            question
                .options
                .insert(TaskAskOptionId::new(*id).unwrap(), TaskAskOption::new(*id));
        }
        question.outcome_binding = mapping.map(|names| OutcomeBinding {
            source: OutcomeSource::Claim {
                predicate: "release.outcome".to_owned(),
            },
            horizon: 3600,
            mapping: names
                .iter()
                .map(|name| ((*name).to_owned(), true))
                .collect(),
            noise_weight: 0.5,
            linked_by: None,
        });
        TaskAskSpec {
            intent_key: intent_key.into(),
            ..TaskAskSpec::shorthand(
                Some(TaskAskTarget::Responder(TaskAssignee::Human {
                    actor_ref: self.owner,
                })),
                question,
                Some(u64::MAX),
                TaskAskDefault::AskMe,
            )
        }
    }
}

/// `error` is the up-front refusal that names `name`.
fn assert_refused_by_name(error: &MemoryError, name: &str, door: &str) {
    assert_eq!(error.code, "BAD_REQUEST", "{door}: {error:?}");
    assert!(
        error.message.contains(&format!("`{name}`")),
        "{door} refuses the ask by the name `{name}`: {error:?}"
    );
}

#[test]
fn ask_with_a_credential_named_option_id_is_refused_by_name() {
    let fx = fixture();
    let memory = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let spec = fx.spec("option-named-token", &["proceed", "token"], None);
    let error = memory
        .tasks_ask(&spec)
        .expect_err("tasks_ask refuses an option id the scan reads as a credential name");
    assert_refused_by_name(&error, "token", "tasks_ask");
    let error = memory
        .tasks_can_ask(&spec)
        .expect_err("the can(ask) preflight refuses it too");
    assert_refused_by_name(&error, "token", "tasks_can_ask");
}

#[test]
fn ask_with_a_credential_named_outcome_mapping_is_refused_by_name() {
    let fx = fixture();
    let memory = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let spec = fx.spec(
        "outcome-named-api-key",
        &["shipped", "held"],
        Some(&["shipped", "api-key"][..]),
    );
    let error = memory
        .tasks_ask(&spec)
        .expect_err("tasks_ask refuses an outcome name the scan reads as a credential name");
    assert_refused_by_name(&error, "api-key", "tasks_ask");
}

#[test]
fn ask_with_neutral_names_asks_with_the_scan_on() {
    let fx = fixture();
    let memory = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let spec = fx.spec(
        "neutral-names",
        &["shipped", "held", "token_count"],
        Some(&["shipped", "held"][..]),
    );
    memory
        .tasks_can_ask(&spec)
        .unwrap_or_else(|error| panic!("the preflight admits neutral names: {error:?}"));
    memory
        .tasks_ask(&spec)
        .unwrap_or_else(|error| panic!("an ask with neutral names is kept: {error:?}"));
}
