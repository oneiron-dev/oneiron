//! Owner-device ask words check admission before prompting, ask for presence
//! only for approvals, and check that the proof covers the write's importance.
//! The `can` preview checks admission and key availability without prompting.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::error::{OWNER_PRESENCE_REQUIRED, RecordError};
use oneiron::memory::{
    CanAnswer, CanVerbGate, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN,
    MEMORY_CODE_INVALID_STATE, Memory,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskHandle, TaskAskOption, TaskAskOptionId,
    TaskAskQuestion, TaskAskSpec, TaskAskStatus, TaskAskTarget, TaskAskWord,
};
use oneiron::test_doors::ask_answer_proof::mint_code_consent_ask;
use oneiron::test_doors::ask_word_presence::tasks_answer_asked_as;
use oneiron::test_doors::owner_device_answer::{OwnerDeviceVault, open_owner_device_vault};
use oneiron::verbs::{CanRequest, CanVerb, CanVerbRequest, TaskAnswerRequest};
use oneiron::world_keys::OwnerActImportance;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use oneiron_keystore::{
    ManualPresenceClock, PresenceError, PresenceGate, PresenceWindow, ScriptedPresence,
};

struct Fixture {
    device: OwnerDeviceVault,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("a private directory for the test vault");
        let device = open_owner_device_vault(dir.path()).expect("a hosted vault with its owner");
        Self { device, _dir: dir }
    }

    fn code_consent_ask(&self) -> TaskAskHandle {
        mint_code_consent_ask(&self.device.vault, self.device.owner, &[])
            .expect("a code consent ask addressed to the owner with no holder offer")
    }

    fn owner_device(&self) -> Memory<'_> {
        self.device
            .vault
            .memory(self.device.owner, EdgeActorClass::Human)
            .answering_as_owner_device()
    }
}

fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

fn put_turn(vault: &Vault) -> EntityId {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![("role".into(), "answer".into())]),
    )
    .expect("the answer TURN body encodes as MessagePack");
    let turn = EntityId::now();
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange { start: 11, end: 11 },
            11,
            &body,
        )
        .expect("the word can cite a stored TURN");
    turn
}

fn option_word(result_ref: EntityId, option: &str) -> TaskAskWord {
    let mut word = TaskAskWord::new(result_ref);
    word.option = Some(TaskAskOptionId::new(option).expect("the option id has valid syntax"));
    word
}

#[test]
fn an_approving_word_asks_for_the_person_once_and_is_admitted() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the owner key is enrolled for signing");
    let handle = fx.code_consent_ask();
    let word = option_word(put_turn(&fx.device.vault), "approve_once");
    let presence = scripted_gate(&fx.device.vault, [Ok(())]);

    fx.owner_device()
        .tasks_answer(&handle, &word)
        .expect("a confirmed owner can give the approving word");
    assert_eq!(presence.prompts(), 1, "the approval prompts exactly once");
    assert_eq!(
        presence.reasons(),
        ["approve an action an agent is waiting to take"],
        "the prompt names what the code consent word approves"
    );
}

#[test]
fn a_declined_prompt_refuses_an_approving_word_and_records_nothing() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the owner key is enrolled for signing");
    let handle = fx.code_consent_ask();
    let word = option_word(put_turn(&fx.device.vault), "approve_once");
    let memory = fx.owner_device();
    let presence = scripted_gate(&fx.device.vault, [Err(PresenceError::Declined)]);

    let refused = memory
        .tasks_answer(&handle, &word)
        .expect_err("declining the prompt refuses the approving word");
    assert!(
        refused
            .reason_codes
            .iter()
            .any(|code| code == OWNER_PRESENCE_REQUIRED)
            && refused
                .reason_codes
                .iter()
                .any(|code| code == "here:declined"),
        "the refusal names owner presence and the device's decline: {refused:?}"
    );
    assert_eq!(
        presence.prompts(),
        1,
        "the declined approval prompted exactly once"
    );
    assert!(
        memory
            .tasks_ask_evidence(handle)
            .expect("the owner can read the ask's live evidence")
            .is_empty(),
        "declining the prompt records no answer evidence"
    );
    let status = memory
        .tasks_ask_status(handle)
        .expect("the ask's status remains readable");
    assert!(
        matches!(&status, TaskAskStatus::Pending { .. }),
        "the declined approval leaves the ask waiting: {status:?}"
    );

    scripted_gate(&fx.device.vault, [Ok(())]);
    memory
        .tasks_answer(&handle, &word)
        .expect("the same word is admitted when the owner confirms");
}

#[test]
fn a_denying_word_raises_no_prompt_and_is_admitted() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the owner key is enrolled for signing");
    let handle = fx.code_consent_ask();
    let word = option_word(put_turn(&fx.device.vault), "deny");
    let presence = scripted_gate(&fx.device.vault, []);

    fx.owner_device()
        .tasks_answer(&handle, &word)
        .expect("the owner's signed denial is admitted without confirmation");
    assert_eq!(presence.prompts(), 0, "the denial does not prompt");
}

#[test]
fn a_word_on_a_plain_ask_raises_no_prompt() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the owner key is enrolled for signing");
    let option = TaskAskOptionId::new("keep").expect("the plain ask has a valid option id");
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Turn(put_turn(&fx.device.vault)));
    question
        .options
        .insert(option.clone(), TaskAskOption::new("Keep"));
    let handle = fx
        .device
        .vault
        .memory(fx.device.owner, EdgeActorClass::Human)
        .tasks_ask(&TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(BTreeSet::from([fx.device.owner]))),
            question,
            None,
            TaskAskDefault::AskMe,
        ))
        .expect("the owner opens a plain ask addressed to themself")
        .handle;
    let mut word = TaskAskWord::new(put_turn(&fx.device.vault));
    word.option = Some(option);
    let presence = scripted_gate(&fx.device.vault, []);

    fx.owner_device()
        .tasks_answer(&handle, &word)
        .expect("the owner's option word on a plain ask is admitted");
    assert_eq!(
        presence.prompts(),
        0,
        "the plain ask's option does not prompt"
    );
}

#[test]
fn a_word_the_admission_refuses_raises_no_prompt() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the owner key is enrolled for signing");
    let vault = &fx.device.vault;
    let handle = fx.code_consent_ask();
    let result = put_turn(vault);
    let approve = option_word(result, "approve_once");
    let memory = fx.owner_device();
    let presence = scripted_gate(vault, []);

    let unknown = TaskAskHandle {
        group_ref: EntityId::now(),
    };
    let refused = memory
        .tasks_answer(&unknown, &approve)
        .expect_err("there is no ask for the unknown handle");
    assert_eq!(
        refused.message, "unknown ask handle",
        "the missing handle is the refusal"
    );
    assert_eq!(presence.prompts(), 0, "an unknown ask does not prompt");

    let unoffered = option_word(result, "approve_and_stop_asking");
    let refused = memory
        .tasks_answer(&handle, &unoffered)
        .expect_err("the code consent ask does not offer the standing approval");
    assert_eq!(
        refused.code, MEMORY_CODE_BAD_REQUEST,
        "an unoffered option is a bad request"
    );
    assert_eq!(
        refused.message, "invalid TASK body: tasks.ask.option",
        "word admission rejects the unoffered option before importance is checked"
    );
    assert_eq!(presence.prompts(), 0, "an unoffered option does not prompt");

    let outsider = EntityId::now();
    vault
        .put_entity(
            &outsider,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"outsider",
        )
        .expect("the outsider is a live PERSON without ownership");
    let refused = vault
        .memory(outsider, EdgeActorClass::Human)
        .answering_as_owner_device()
        .tasks_answer(&handle, &approve)
        .expect_err("the owner-device surface cannot authenticate the outsider as owner");
    assert_eq!(
        refused.code, MEMORY_CODE_FORBIDDEN,
        "lack of owner authentication is forbidden"
    );
    assert_eq!(
        refused.message,
        "consent owner not authenticated: authenticated actor is not an owner of this vault",
        "the live outsider fails the ownership check, not the ask's option check"
    );
    assert_eq!(
        presence.prompts(),
        0,
        "the outsider is refused before any prompt"
    );

    let presence = scripted_gate(vault, [Ok(())]);
    memory
        .tasks_answer(&handle, &approve)
        .expect("the valid approving word is admitted from the owner after confirmation");
    assert_eq!(
        presence.prompts(),
        1,
        "the valid approval reaches the prompt"
    );
}

#[test]
fn the_write_refuses_an_approving_word_under_a_proof_signed_for_an_ordinary_word() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the owner key is enrolled for signing");
    let handle = fx.code_consent_ask();
    let word = option_word(put_turn(&fx.device.vault), "approve_once");
    let memory = fx.owner_device();

    let refused = tasks_answer_asked_as(&memory, &handle, &word, OwnerActImportance::Ordinary)
        .expect_err("the write refuses an approval proved at ordinary importance");
    assert_eq!(
        refused.code, MEMORY_CODE_INVALID_STATE,
        "a concurrent write is an invalid state"
    );
    assert_eq!(
        refused.message,
        concat!(
            "concurrent write detected: this act would change more than it did when the ",
            "person at this device was asked; nothing was written"
        ),
        "the refusal identifies the importance rise at the write"
    );
    assert!(
        memory
            .tasks_ask_evidence(handle)
            .expect("the owner can read the ask's live evidence after rollback")
            .is_empty(),
        "refusing a rise rolls back the admitted word"
    );
    let status = memory
        .tasks_ask_status(handle)
        .expect("the ask's status remains readable");
    assert!(
        matches!(&status, TaskAskStatus::Pending { .. }),
        "the refused write leaves the ask waiting: {status:?}"
    );
    scripted_gate(&fx.device.vault, [Ok(())]);
    tasks_answer_asked_as(&memory, &handle, &word, OwnerActImportance::Important)
        .expect("the same approving word is admitted with a proof signed at important importance");

    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the second vault's owner key is enrolled for signing");
    let handle = fx.code_consent_ask();
    let denial = option_word(put_turn(&fx.device.vault), "deny");
    tasks_answer_asked_as(
        &fx.owner_device(),
        &handle,
        &denial,
        OwnerActImportance::Ordinary,
    )
    .expect("a denial is admitted with a proof signed at ordinary importance");
}

#[test]
fn the_preview_of_an_approving_word_raises_no_prompt() {
    for (enrolled, expected_gate) in [(true, CanVerbGate::Auto), (false, CanVerbGate::Refused)] {
        let fx = Fixture::open();
        if enrolled {
            fx.device
                .enrol_owner_key()
                .expect("the preview's key-present vault has an enrolled key");
        }
        let handle = fx.code_consent_ask();
        let word = option_word(put_turn(&fx.device.vault), "approve_once");
        let presence = scripted_gate(&fx.device.vault, []);
        let request = CanRequest::Verb(Box::new(CanVerbRequest {
            verb: CanVerb {
                name: "tasks.answer".to_owned(),
                params: serde_json::to_value(TaskAnswerRequest { handle, word })
                    .expect("the approval parameters serialize as a tasks.answer request"),
                actor: None,
            },
        }));
        let answer = fx
            .owner_device()
            .can(&request)
            .expect("can returns the approval's verb gate");
        let CanAnswer::Verb(answer) = answer else {
            panic!("can for tasks.answer must return a verb gate: {answer:?}");
        };
        assert_eq!(
            answer.gate, expected_gate,
            "the approval preview allows only with a key (enrolled: {enrolled})"
        );
        if !enrolled {
            assert_eq!(
                answer.reasons,
                [RecordError::OwnerKeyRequired.to_string()],
                "preview exposes the owner-key refusal as a reason message"
            );
        }
        assert_eq!(
            presence.prompts(),
            0,
            "the preview never prompts (enrolled: {enrolled})"
        );
    }
}
