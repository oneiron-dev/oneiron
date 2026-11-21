//! Owner-device ask words check admission before prompting, ask for presence
//! only for approvals, and check that the proof covers the write's importance.
//! The `can` preview checks admission and key availability without prompting.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::WriteActor;
use oneiron::attempt_queue::AttemptId;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::disclosure::{AttendeeIdentityChoice, UnknownAttendeeAsk};
use oneiron::disclosure::{PREDICATE_DISCLOSURE_ATTENDEE_ASK, attendee_ask_ref};
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use oneiron::error::{OWNER_PRESENCE_REQUIRED, RecordError};
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::llm::manifest::{ModelManifest, TeacherProbeApproval};
use oneiron::llm::registry::{
    ModelBackendPin, ModelRegistryRow, ModelWireFormat, PricedModelBackend,
};
use oneiron::llm::{LlmCatalogCost, LlmCatalogEntry, ModelId, ModelLocality, ModelTierRef};
use oneiron::memory::{
    CanAnswer, CanVerbGate, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN,
    MEMORY_CODE_INVALID_STATE, Memory,
};
use oneiron::model_binding::{MODEL_ROLES, ModelBinding, ModelRole, ModelSlot};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use oneiron::runtime_hooks::InvocationId;
use oneiron::skill_optimize::offer_doors::{OfferPassRequest, trigger as trigger_offer_pass};
use oneiron::skill_optimize::{
    ComputeDestination, EvalSeat, OfferCandidate, OfferCost, OfferEvidence, OfferModelPin,
    OfferOption, SeatWorkload, SwitchApplication, TrainingOfferDraft, training_offer_switch,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskHandle, TaskAskOption, TaskAskOptionId,
    TaskAskQuestion, TaskAskSettlementReason, TaskAskSpec, TaskAskStatus, TaskAskTarget,
    TaskAskWord,
};
use oneiron::task_verb::{TaskAskElectorate, TaskAskNeed};
use oneiron::test_doors::ask_answer_proof::mint_code_consent_ask;
use oneiron::test_doors::ask_word_presence::tasks_answer_asked_as;
use oneiron::test_doors::owner_device_answer::{OwnerDeviceVault, open_owner_device_vault};
use oneiron::test_doors::verb_hook_ask::{HookAsk, SavedAsk};
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

fn create_attendee_contact(vault: &Vault, owner: EntityId, address: &str) -> EntityId {
    let contact = vault.new_entity_id().expect("The contact has a new id.");
    let record = CounterpartyContactRecord::public(owner, address, 11)
        .expect("The public contact record is valid.");
    vault
        .create_counterparty_contact(&contact, &record)
        .expect("The contact is stored as active.");
    contact
}

fn raise_attendee_ask(
    memory: &Memory<'_>,
    session_key: &str,
    candidate: EntityId,
) -> TaskAskHandle {
    memory
        .raise_unknown_attendee_ask(&UnknownAttendeeAsk {
            session_key: session_key.to_owned(),
            speaker_key: "speaker-1".to_owned(),
            roster_revision: 1,
            trigger_turn: None,
            candidates: vec![candidate],
            until: 4_102_444_800, // 2100-01-01 UTC; no test clock read.
        })
        .expect("The owner raises an ask while its candidate is active.")
        .handle
}

fn attendee_word(vault: &Vault, choice: AttendeeIdentityChoice) -> TaskAskWord {
    let mut word = TaskAskWord::new(put_turn(vault));
    word.option = Some(
        choice
            .option()
            .expect("The attendee choice is a valid option."),
    );
    word
}

fn assert_ask_waits_without_evidence(memory: &Memory<'_>, handle: TaskAskHandle) {
    assert!(
        memory
            .tasks_ask_evidence(handle)
            .expect("The owner can read the ask's live evidence.")
            .is_empty(),
        "the refused approval records no evidence"
    );
    let status = memory
        .tasks_ask_status(handle)
        .expect("The owner can read the ask's status.");
    assert!(
        matches!(&status, TaskAskStatus::Pending { .. }),
        "the refused approval leaves the ask pending: {status:?}"
    );
}

#[test]
fn an_approving_attendee_word_for_a_contact_no_longer_live_raises_no_prompt() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("The owner key is enrolled for signing.");
    let vault = &fx.device.vault;
    let asker = vault.memory(fx.device.owner, EdgeActorClass::Human);
    let contact_a = create_attendee_contact(vault, fx.device.owner, "speaker-a@contacts.example");
    let contact_b = create_attendee_contact(vault, fx.device.owner, "speaker-b@contacts.example");
    let ask_a = raise_attendee_ask(&asker, "attendee-session-a", contact_a);
    let ask_b = raise_attendee_ask(&asker, "attendee-session-b", contact_b);
    vault
        .revoke_counterparty_contact(&contact_a, 12)
        .expect("Contact A is revoked after its ask freezes it as a candidate.");

    let memory = fx.owner_device();
    let presence = scripted_gate(vault, []);
    let approve_a = attendee_word(vault, AttendeeIdentityChoice::Contact(contact_a));
    let refused = memory
        .tasks_answer(&ask_a, &approve_a)
        .expect_err("The revoked contact cannot be approved as the speaker.");
    assert_eq!(
        refused.message, "invalid claim body: disclosure.attendee_ask value invalid",
        "the refusal is for the inactive candidate"
    );
    assert_eq!(
        presence.prompts(),
        0,
        "the refused approval does not prompt"
    );
    assert_ask_waits_without_evidence(&memory, ask_a);

    let unknown = attendee_word(vault, AttendeeIdentityChoice::Unknown);
    memory
        .tasks_answer(&ask_a, &unknown)
        .expect("Unknown is admitted even with a revoked candidate.");
    assert_eq!(presence.prompts(), 0, "unknown does not prompt");

    let presence = scripted_gate(vault, [Ok(())]);
    let approve_b = attendee_word(vault, AttendeeIdentityChoice::Contact(contact_b));
    memory
        .tasks_answer(&ask_b, &approve_b)
        .expect("The owner confirms the active contact as the speaker.");
    assert_eq!(presence.prompts(), 1, "the active contact prompts once");
    assert_eq!(presence.reasons(), ["confirm who a speaker is"]);
    let status = memory
        .tasks_ask_status(ask_b)
        .expect("The owner can read the confirmed ask's status.");
    let TaskAskStatus::Settled(result) = &status else {
        panic!("the active contact's first word must settle the ask: {status:?}");
    };
    assert_eq!(result.settlement.reason, TaskAskSettlementReason::FirstWord);
}

const INCUMBENT_MODEL: &str = "fixture/companion-incumbent@r1";
const STOCK_MODEL: &str = "fixture/companion-stock@r1";
const REPLACEMENT_MODEL: &str = "fixture/companion-replacement@r1";

fn fixture_model(id: &str) -> ModelId {
    ModelId::new(id).expect("The fixture model id has a provider, name and revision.")
}

fn register_fixture_model(vault: &Vault, id: &str) {
    let model = fixture_model(id);
    let price = LlmCatalogCost {
        input_per_million: "0".into(),
        output_per_million: "0".into(),
        cache_read_per_million: None,
        cache_write_per_million: None,
        currency: None,
    };
    let backend = PricedModelBackend {
        pin: ModelBackendPin {
            model: model.clone(),
            backend: "fixture".to_owned(),
            serving_revision: "r1".to_owned(),
            quantization: None,
            context_window_tokens: 4096,
        },
        price: price.clone(),
    };
    vault
        .put_model_registry_row(&ModelRegistryRow {
            version: 1,
            wire: ModelWireFormat::Local,
            catalog: LlmCatalogEntry {
                model,
                display_name: id.to_owned(),
                locality: ModelLocality::OnDevice,
                context_window_tokens: 4096,
                max_output_tokens: None,
                cost: Some(price),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([(
                    "backends".to_owned(),
                    serde_json::to_value([backend]).expect("The fixture backend serializes."),
                )]),
            },
            scores: BTreeMap::new(),
            fetched_at: BTreeMap::new(),
            tokens_per_o200k: None,
            answer_tokens_per_o200k: None,
            stale_since: None,
            source_rows: None,
        })
        .expect("The fixture model's serving revision is registered.");
}

fn companion_manifest(companion: &str) -> ModelManifest {
    let mut roles = BTreeMap::new();
    for role in MODEL_ROLES {
        let (model, slot) = match role {
            ModelRole::GenerativeReasoner => (fixture_model(companion), ModelSlot::Llm),
            ModelRole::ExtractionEncoder => (
                fixture_model("fixture/extraction-encoder@r1"),
                ModelSlot::Oneironer,
            ),
            _ => (
                fixture_model(&format!("fixture/{role:?}@r1")),
                ModelSlot::Llm,
            ),
        };
        roles.insert(
            role,
            ModelBinding {
                model,
                slot,
                tier: ModelTierRef("fixture".to_owned()),
                route_models: BTreeMap::new(),
                disposition: None,
                reads_audio: false,
            },
        );
    }
    ModelManifest {
        version: 2,
        roles,
        routes: BTreeMap::from([
            (ModelSlot::Llm, ModelLocality::OnDevice),
            (ModelSlot::Embedder, ModelLocality::OnDevice),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]),
        verdict: None,
        seat_policy: None,
    }
}

fn companion_stock_offer(at: u64) -> TrainingOfferDraft {
    let pin = |model: &str| OfferModelPin {
        model: model.to_owned(),
        revision: "r1".to_owned(),
        content_hash: None,
    };
    let cost = OfferCost {
        currency: "USD".to_owned(),
        monthly_before: Some(40.0),
        monthly_after: Some(25.0),
        one_off: None,
        payback_months: None,
    };
    TrainingOfferDraft {
        seat: EvalSeat::Companion,
        offer_skill: None,
        incumbent: pin(INCUMBENT_MODEL),
        candidate: OfferCandidate::Stock {
            model: pin(STOCK_MODEL),
            licence: "apache-2.0".to_owned(),
            source: "fixture-registry".to_owned(),
        },
        baseline: OfferOption {
            label: "today".to_owned(),
            model: pin(INCUMBENT_MODEL),
            cost: cost.clone(),
            score: None,
            evidence_refs: Vec::new(),
        },
        alternatives: Vec::new(),
        workload: SeatWorkload {
            from: at - 30 * 86_400,
            until: at,
            calls: None,
            input_tokens: None,
            output_tokens: None,
            complete: false,
            receipt_refs: vec!["fixture-workload:companion".to_owned()],
        },
        cost,
        evidence: OfferEvidence {
            cohort: None,
            exposures: Vec::new(),
            rubric_revision: None,
            card: None,
            paired_measurement: None,
            losses: Vec::new(),
            risk: None,
        },
        destination: ComputeDestination::OnDevice,
        previous: None,
        what_changed: None,
        check_at: at + 7 * 86_400,
        source_rows: Some(Vec::new()),
    }
}

fn raise_companion_stock_offer(fx: &Fixture) -> (EntityId, TaskAskHandle) {
    let vault = &fx.device.vault;
    for model in [INCUMBENT_MODEL, STOCK_MODEL, REPLACEMENT_MODEL] {
        register_fixture_model(vault, model);
    }
    let manifest = companion_manifest(INCUMBENT_MODEL);
    let policy = vault
        .teacher_probe_policy(None)
        .expect("The vault has the shipped teacher probe policy.");
    let approval = TeacherProbeApproval::for_scored_checkpoint(&manifest, &policy, 1_000_000)
        .expect("The fixture's teacher pin has a passing probe receipt.");
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &approval)
        .expect("The manifest binds the incumbent to the Companion seat.");

    let owner = fx.device.owner;
    let decision = vault
        .new_entity_id()
        .expect("The owner authentication has a fresh decision id.");
    let proof = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            GateDecisionId::from_bytes(*decision.as_bytes()),
        )
        .expect("The owner can authenticate to queue a Coach pass.");
    let pass = trigger_offer_pass(vault, &proof, OfferPassRequest {})
        .expect("The owner queues the Coach's training offer pass.");
    let attempt =
        AttemptId::from_bytes(pass.attempt.as_bytes()).expect("The pass names the queued attempt.");
    let runner = DreamerRunnerStore::new(vault);
    let queued_at = runner
        .status(attempt)
        .expect("The queued Coach attempt is readable.")
        .expect("The trigger recorded a Coach attempt.")
        .attempt
        .created_at;
    let admitted = runner
        .admit_next_coach_host_job(AdmitDreamerAttempt {
            lease_owner: "stock-switch-fixture".to_owned(),
            now: queued_at,
            budget_id: "stock-switch-fixture".to_owned(),
            budget_total_units: 1 << 20,
            reserve_units: 1,
            started_milestone: None,
        })
        .expect("The Coach can take the queued host job.");
    let DreamerAdmissionOutcome::Admitted(admitted) = admitted else {
        panic!("the fresh vault's Coach offer job must be admitted: {admitted:?}");
    };
    assert_eq!(admitted.status.attempt.id, attempt);

    let prior_tasks = vault
        .entities_by_type(ENTITY_TYPE_TASK)
        .expect("The TASK ids before the Coach issues the ask are readable.");
    let offer = vault
        .run_coach_training_offer(&admitted, companion_stock_offer(queued_at), queued_at)
        .expect("The Coach records the stock offer and issues its owner's ask.");
    let memory = fx.owner_device();
    // Only the newly issued ask group answers peek; its member TASK is not a handle.
    let mut asks = vault
        .entities_by_type(ENTITY_TYPE_TASK)
        .expect("The TASK ids after the Coach issues the ask are readable.")
        .into_iter()
        .filter(|id| !prior_tasks.contains(id))
        .map(|group_ref| TaskAskHandle { group_ref })
        .filter(|handle| memory.tasks_ask_peek(*handle).is_ok());
    let handle = asks
        .next()
        .expect("The Coach issued an ask the owner can read.");
    assert!(
        asks.next().is_none(),
        "only one new ask is visible to the owner"
    );
    (offer.id, handle)
}

#[test]
fn an_approving_switch_word_for_a_seat_that_moved_raises_no_prompt() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("The owner key is enrolled for signing.");
    let vault = &fx.device.vault;
    let (offer, handle) = raise_companion_stock_offer(&fx);
    vault
        .set_model_manifest(&companion_manifest(REPLACEMENT_MODEL))
        .expect("The Companion seat moves to another model after the ask was raised.");

    let memory = fx.owner_device();
    let presence = scripted_gate(vault, []);
    let approve = option_word(put_turn(vault), "approve_switch");
    let refused = memory
        .tasks_answer(&handle, &approve)
        .expect_err("The offer's old incumbent is no longer bound to the seat.");
    assert_eq!(
        refused.message,
        "invalid config: the seat moved since the offer was made; answer a newer offer",
        "the refusal names the moved seat"
    );
    assert_eq!(presence.prompts(), 0, "the refused switch does not prompt");
    assert_ask_waits_without_evidence(&memory, handle);
    assert!(
        training_offer_switch(vault, &offer)
            .expect("The refused offer's switch is readable.")
            .is_none(),
        "the refused approval records no switch"
    );

    let keep = option_word(put_turn(vault), "keep_baseline");
    memory
        .tasks_answer(&handle, &keep)
        .expect("Keeping the baseline is admitted even after the seat moved.");
    assert_eq!(
        presence.prompts(),
        0,
        "keeping the baseline does not prompt"
    );

    let control = Fixture::open();
    control
        .device
        .enrol_owner_key()
        .expect("The control's owner key is enrolled for signing.");
    let vault = &control.device.vault;
    let (offer, handle) = raise_companion_stock_offer(&control);
    let presence = scripted_gate(vault, [Ok(())]);
    let approve = option_word(put_turn(vault), "approve_switch");
    control
        .owner_device()
        .tasks_answer(&handle, &approve)
        .expect("The owner confirms the switch from the still-bound incumbent.");
    assert_eq!(presence.prompts(), 1, "the switch prompts once");
    assert_eq!(presence.reasons(), ["approve an offered AI model change"]);
    let switch = training_offer_switch(vault, &offer)
        .expect("The confirmed offer's switch is readable.")
        .expect("The confirmed offer recorded a stock switch.");
    assert_eq!(switch.application, SwitchApplication::Bound);
    assert_eq!(switch.binding.model, fixture_model(STOCK_MODEL));
}

#[test]
fn an_approving_word_on_an_ask_with_a_deleted_member_task_raises_no_prompt() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("The owner key is enrolled for signing.");
    let vault = &fx.device.vault;
    let holder = EntityId::now();
    vault
        .put_entity(
            &holder,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"holder",
        )
        .expect("The holder is a live PERSON.");
    let broken = mint_code_consent_ask(vault, fx.device.owner, &[holder])
        .expect("The broken ask addresses the owner and the holder.");
    let intact = mint_code_consent_ask(vault, fx.device.owner, &[holder])
        .expect("The control ask addresses the owner and the holder.");
    let other_task = EntityId::derive(
        oneiron_contracts::entity_id::derived_domains::TASK_ASK_MEMBER,
        &[broken.group_ref.as_bytes(), holder.as_bytes()],
    )
    .expect("The holder member TASK id derives.");
    assert!(
        vault
            .delete_entity(&other_task)
            .expect("The ordinary delete door runs."),
        "The other member TASK existed."
    );

    let memory = fx.owner_device();
    let presence = scripted_gate(vault, []);
    let approve = option_word(put_turn(vault), "approve_once");
    let refused = memory
        .tasks_answer(&broken, &approve)
        .expect_err("The deleted member TASK refuses the settlement scan.");
    assert_eq!(
        refused.code, MEMORY_CODE_BAD_REQUEST,
        "The scan refusal is a bad request: {refused:?}"
    );
    assert_eq!(
        refused.message, "invalid TASK body: tasks.ask.fact",
        "The refusal is the settlement's invalid ask."
    );
    assert_eq!(
        presence.prompts(),
        0,
        "The refused approval does not prompt."
    );
    assert!(
        memory
            .tasks_ask_evidence(broken)
            .expect("the evidence can be read without attempting settlement")
            .is_empty(),
        "the refused approval records no evidence"
    );

    let presence = scripted_gate(vault, [Ok(())]);
    memory
        .tasks_answer(&intact, &approve)
        .expect("The same word on the intact ask is admitted.");
    assert_eq!(presence.prompts(), 1, "The intact approval prompts once.");
}

#[test]
fn an_approving_word_on_an_ask_whose_waiter_lost_its_trap_raises_no_prompt() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("The owner key is enrolled for signing.");
    let vault = &fx.device.vault;
    let asker = vault.memory(fx.device.owner, EdgeActorClass::Human);
    let contact = create_attendee_contact(vault, fx.device.owner, "speaker@contacts.example");
    let ask_a = raise_attendee_ask(&asker, "t12-session-a", contact);
    let ask_b = raise_attendee_ask(&asker, "t12-session-b", contact);
    let trap_a = match asker
        .tasks_wait(ask_a, Some("t12-waiter-a"))
        .expect("The asker waits on the broken ask.")
    {
        oneiron::task_verb::TaskAskWait::Pending { trap_ref } => trap_ref,
        other => panic!("A keyed wait on an open ask names its trap: {other:?}"),
    };
    match asker
        .tasks_wait(ask_b, Some("t12-waiter-b"))
        .expect("The asker waits on the control ask.")
    {
        oneiron::task_verb::TaskAskWait::Pending { .. } => {}
        other => panic!("A keyed wait on an open ask names its trap: {other:?}"),
    };
    let trap = EntityId::from_hex(&trap_a).expect("The trap ref parses.");
    assert!(
        vault
            .delete_entity(&trap)
            .expect("The ordinary delete door runs."),
        "The waiter trap CLAIM existed."
    );

    let memory = fx.owner_device();
    let presence = scripted_gate(vault, []);
    let approve = attendee_word(vault, AttendeeIdentityChoice::Contact(contact));
    let refused = memory
        .tasks_answer(&ask_a, &approve)
        .expect_err("The deleted trap refuses the settlement signal.");
    assert_eq!(
        refused.code, MEMORY_CODE_BAD_REQUEST,
        "The trap refusal is a bad request: {refused:?}"
    );
    assert_eq!(
        refused.message, "invalid TASK body: tasks.ask.fact",
        "The refusal is the settlement's invalid ask."
    );
    assert_eq!(
        presence.prompts(),
        0,
        "The refused approval does not prompt."
    );
    assert_ask_waits_without_evidence(&memory, ask_a);

    let presence = scripted_gate(vault, [Ok(())]);
    memory
        .tasks_answer(&ask_b, &approve)
        .expect("The same word on the intact ask is admitted.");
    assert_eq!(presence.prompts(), 1, "The intact approval prompts once.");
    assert_eq!(presence.reasons(), ["confirm who a speaker is"]);
    let status = memory
        .tasks_ask_status(ask_b)
        .expect("The control ask reads.");
    let TaskAskStatus::Settled(result) = &status else {
        panic!("The intact word settles the ask: {status:?}");
    };
    assert_eq!(result.settlement.reason, TaskAskSettlementReason::FirstWord);
}

#[test]
fn a_proceed_word_on_a_verb_hook_ask_asks_for_the_person_once() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the owner key is enrolled");
    let vault = &fx.device.vault;
    let owner = fx.device.owner;
    let decision = vault.new_entity_id().expect("a fresh decision id");
    let proof = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            GateDecisionId::from_bytes(*decision.as_bytes()),
        )
        .expect("the owner can bind the hook");
    let hook = HookAsk::on_verb(vault, owner, &proof, "self.use")
        .expect("the owner binds a pre-hook that asks");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let open = |seq| {
        let invocation = InvocationId::of_run_step(b"owner-device-verb-hook", seq);
        let group_ref = hook
            .ask(vault, &actor, invocation)
            .expect("the hook parks its call");
        (invocation, TaskAskHandle { group_ref })
    };
    let (invocation, handle) = open(1);
    let memory = fx.owner_device();
    let presence = scripted_gate(vault, [Ok(())]);
    let unit = put_turn(vault);
    memory
        .tasks_answer(&handle, &option_word(unit, "proceed"))
        .expect("a confirmed proceed is admitted");
    assert_eq!(presence.prompts(), 1, "proceed prompts once");
    assert_eq!(
        presence.reasons(),
        ["let an action that waits for your approval go ahead"]
    );
    assert_eq!(
        hook.retry(vault, &actor, invocation)
            .expect("the hook wait is readable"),
        SavedAsk::Resume {
            ask: handle.group_ref
        },
    );

    let (_, handle) = open(2);
    let presence = scripted_gate(vault, []);
    memory
        .tasks_answer(&handle, &option_word(unit, "hold"))
        .expect("hold is admitted without confirmation");
    assert_eq!(presence.prompts(), 0, "hold does not prompt");
}

#[test]
fn an_approving_word_on_an_ask_that_has_its_result_raises_no_prompt() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("The owner key is enrolled for signing.");
    let vault = &fx.device.vault;
    let asker = vault.memory(fx.device.owner, EdgeActorClass::Human);
    let contact_a = create_attendee_contact(vault, fx.device.owner, "speaker-a@contacts.example");
    let contact_b = create_attendee_contact(vault, fx.device.owner, "speaker-b@contacts.example");
    let handle = asker
        .raise_unknown_attendee_ask(&UnknownAttendeeAsk {
            session_key: "t14-session".to_owned(),
            speaker_key: "speaker-1".to_owned(),
            roster_revision: 1,
            trigger_turn: None,
            candidates: vec![contact_a, contact_b],
            until: 4_102_444_800,
        })
        .expect("The owner raises an ask with two live candidates.")
        .handle;
    let presence = Arc::new(ScriptedPresence::new([Ok(())]));
    let gate = Arc::new(PresenceGate::new(
        presence.clone(),
        PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000)),
    ));
    vault.install_presence_gate(gate.clone());

    let memory = fx.owner_device();
    let first = attendee_word(vault, AttendeeIdentityChoice::Contact(contact_a));
    memory
        .tasks_answer(&handle, &first)
        .expect("The live contact's word is admitted.");
    assert_eq!(presence.prompts(), 1, "The first approval prompts once.");
    assert_eq!(presence.reasons(), ["confirm who a speaker is"]);
    let status = memory
        .tasks_ask_status(handle)
        .expect("The settled ask reads.");
    let TaskAskStatus::Settled(result) = &status else {
        panic!("The first word settles the ask: {status:?}");
    };
    assert_eq!(result.settlement.reason, TaskAskSettlementReason::FirstWord);
    gate.end_window();

    memory
        .tasks_answer(&handle, &first)
        .expect("The repeated word is admitted after the cut.");
    assert_eq!(
        presence.prompts(),
        1,
        "The repeat asks nobody after the cut."
    );
    let second = attendee_word(vault, AttendeeIdentityChoice::Contact(contact_b));
    memory
        .tasks_answer(&handle, &second)
        .expect("The second contact's word is admitted after the cut.");
    assert_eq!(
        presence.prompts(),
        1,
        "The late approval asks nobody after the cut."
    );
}

#[test]
fn a_repeated_attendee_word_is_judged_by_the_selected_word() {
    let fx = Fixture::open();
    fx.device
        .enrol_owner_key()
        .expect("the device has the owner's key");
    let vault = &fx.device.vault;
    let (owner, other) = (fx.device.owner, EntityId::now());
    let authenticate = |actor: EntityId| {
        let decision = vault.new_entity_id().expect("a fresh decision id");
        vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                true,
                GateDecisionId::from_bytes(*decision.as_bytes()),
            )
            .expect("a live person has a native proof")
    };
    vault
        .put_entity(
            &other,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner B",
        )
        .expect("the second owner exists as a person");
    let members = [owner, other].map(|member_ref| InitialSharedMember {
        member_ref,
        role: Some(FederationGrantRole::Owner),
    });
    vault
        .initialize_shared_vault(&authenticate(owner), 46, None, &members, 1)
        .expect("the owner shares the vault and invites a co-owner");
    let other_proof = authenticate(other);
    let invitations = vault
        .shared_invitations(&other_proof, 46)
        .expect("read the invitation");
    vault
        .accept_shared_invitation(&other_proof, 46, &invitations[0].id)
        .expect("the second owner accepts the invitation");
    let other_memory = vault.memory(other, EdgeActorClass::Human);
    let old = create_attendee_contact(vault, owner, "old@contacts.example");
    let latest = create_attendee_contact(vault, owner, "latest@contacts.example");
    let control = vault
        .memory(owner, EdgeActorClass::Human)
        .raise_unknown_attendee_ask(&UnknownAttendeeAsk {
            session_key: "repeated-attendee-word".to_owned(),
            speaker_key: "speaker-1".to_owned(),
            roster_revision: 1,
            trigger_turn: None,
            candidates: vec![old, latest],
            until: 4_102_444_800,
        })
        .expect("the control freezes both contacts")
        .handle;
    let claim = attendee_ask_ref("repeated-attendee-word", "speaker-1", 1)
        .expect("the frozen question claim has a stable id");
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(claim));
    for choice in [
        AttendeeIdentityChoice::Contact(old),
        AttendeeIdentityChoice::Contact(latest),
        AttendeeIdentityChoice::Unknown,
    ] {
        question
            .options
            .insert(choice.option().unwrap(), TaskAskOption::new("Candidate"));
    }
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(BTreeSet::from([owner, other]))),
        question,
        Some(4_102_444_800),
        TaskAskDefault::Hold,
    );
    spec.intent_key = format!("{PREDICATE_DISCLOSURE_ATTENDEE_ASK}/{}", claim.to_hex());
    spec.need = TaskAskNeed {
        count: 1,
        of: TaskAskElectorate::People(BTreeSet::from([other])),
    };
    let handle = other_memory
        .tasks_ask(&spec)
        .expect("the second owner opens the coverage ask")
        .handle;
    let memory = fx.owner_device();
    let repeated = attendee_word(vault, AttendeeIdentityChoice::Contact(old));
    let selected = attendee_word(vault, AttendeeIdentityChoice::Contact(latest));
    scripted_gate(vault, [Ok(())]);
    memory
        .tasks_answer(&handle, &repeated)
        .expect("the old word waits for coverage");
    memory
        .tasks_answer(&handle, &selected)
        .expect("the latest word waits for coverage");
    other_memory
        .with_owner_authorship(&other_proof)
        .tasks_answer(
            &handle,
            &attendee_word(vault, AttendeeIdentityChoice::Unknown),
        )
        .expect("the second owner supplies coverage but cannot cut on the first owner's word");
    assert!(matches!(
        memory.tasks_ask_status(handle).unwrap(),
        TaskAskStatus::Pending { .. }
    ));
    vault
        .revoke_counterparty_contact(&latest, 12)
        .expect("the latest contact is revoked");
    let presence = scripted_gate(vault, []);
    let refused = memory
        .tasks_answer(&handle, &repeated)
        .expect_err("the selected contact is revoked");
    assert_eq!(
        presence.prompts(),
        0,
        "the old word would cut on the revoked contact"
    );
    assert_eq!(
        refused.message,
        "invalid claim body: disclosure.attendee_ask value invalid"
    );

    let presence = scripted_gate(vault, [Ok(())]);
    memory
        .tasks_answer(&control, &repeated)
        .expect("the same word approves a live contact on the control");
    assert_eq!(presence.prompts(), 1);
}
