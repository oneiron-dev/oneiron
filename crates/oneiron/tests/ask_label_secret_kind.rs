// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! FIX-LIST [ASK-LABEL-SOLICITS-SECRET] (RULING ASK-LABEL-SOLICITS-SECRET = A,
//! scope A2): an answer is a choice among option ids, so an ask whose text
//! names a secret value kind collects that secret as ordinary answer
//! evidence ("Select digit 1 of your payment PIN", options d0..d9). Canon
//! ARCH-0028 #mcp-tasks: "Forms never ask for secrets ... Secrets go through
//! custody." `tasks_ask` (the `tasks.ask` verb's call, and a code run's
//! self-call) and the `can(ask)` preflight now refuse a caller-written ask
//! whose question label, option labels, option `then` or recommendation
//! reason names such a kind, and the refusal names custody as the way.
//!
//! Every phrase of the guard's list is asked with here, also with a
//! qualifier between its words ("private SSH key") and a possessive ("card's
//! security code"). Words that only contain a kind ("pinned", "opinion"),
//! phrase words a function word splits ("verification on the code") and
//! reworded questions are admitted. A listed word in another sense ("Pin
//! this message?") is refused, as a question about a credential is, and its
//! reword is admitted.
//!
//! Public paths only; no test door. Red on main by assertion: main admits
//! every one of these asks.
//! `cargo test --locked -p oneiron --all-features --test ask_label_secret_kind`

use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskOption, TaskAskOptionId, TaskAskPreflight,
    TaskAskQuestion, TaskAskRec, TaskAskReceipt, TaskAskSpec, TaskAskTarget, TaskAssignee,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};
use oneiron_testkit::dreamer::attach_test_host;

/// A device vault with its owner and one TURN the asks are about. The vault
/// drops before its directory.
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

/// One option of an ask: its id, its label and its stated consequence.
struct Choice<'a> {
    id: &'a str,
    label: &'a str,
    then: Option<&'a str>,
}

const fn choice<'a>(id: &'a str, label: &'a str) -> Choice<'a> {
    Choice {
        id,
        label,
        then: None,
    }
}

impl Fixture {
    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner's ask of themselves about the TURN, with this question
    /// label, these options and, if given, a recommendation and its reason.
    fn spec(
        &self,
        intent_key: &str,
        label: &str,
        choices: &[Choice<'_>],
        rec: Option<(&str, &str)>,
    ) -> TaskAskSpec {
        let reference =
            ConsultPayloadRef::parse(&self.vault, &format!("tn_{}", self.question.to_hex()))
                .unwrap();
        let mut question = TaskAskQuestion::new(reference);
        question.label = Some(label.to_owned());
        for choice in choices {
            let mut option = TaskAskOption::new(choice.label);
            option.then = choice.then.map(str::to_owned);
            question
                .options
                .insert(TaskAskOptionId::new(choice.id).unwrap(), option);
        }
        let mut spec = TaskAskSpec {
            intent_key: intent_key.into(),
            ..TaskAskSpec::shorthand(
                Some(TaskAskTarget::Responder(TaskAssignee::Human {
                    actor_ref: self.owner,
                })),
                question,
                Some(u64::MAX),
                TaskAskDefault::AskMe,
            )
        };
        spec.rec = rec.map(|(option, why)| TaskAskRec {
            option: TaskAskOptionId::new(option).unwrap(),
            why: why.to_owned(),
        });
        spec
    }

    /// An ask whose question label is `label`, with two neutral options.
    fn labelled(&self, intent_key: &str, label: &str) -> TaskAskSpec {
        self.spec(
            intent_key,
            label,
            &[choice("yes", "Yes"), choice("no", "No")],
            None,
        )
    }
}

/// `result` is the secret-kind refusal: a bad request naming `field` and
/// `kind`, with custody as its way.
fn assert_secret_refusal<T: std::fmt::Debug>(
    result: MemoryResult<T>,
    field: &str,
    kind: &str,
    door: &str,
    text: &str,
) {
    let error: MemoryError = match result {
        Ok(admitted) => panic!("{door} admits an ask whose {field} is {text:?}: {admitted:?}"),
        Err(error) => error,
    };
    assert_eq!(error.code, "BAD_REQUEST", "{door}, {text:?}: {error:?}");
    assert!(
        error.message.contains(field) && error.message.contains(&format!("({kind})")),
        "{door} names the {field} and the kind {kind} for {text:?}: {error:?}"
    );
    assert!(
        error
            .suggestions
            .iter()
            .any(|way| way.contains("through custody (vault secrets)")),
        "{door} names custody as the way for {text:?}: {error:?}"
    );
}

/// Both doors refuse `spec`, naming `field` and `kind`.
fn assert_refused_at_both_doors(
    memory: &Memory<'_>,
    spec: &TaskAskSpec,
    field: &str,
    kind: &str,
    text: &str,
) {
    assert_secret_refusal::<TaskAskPreflight>(
        memory.tasks_can_ask(spec),
        field,
        kind,
        "tasks_can_ask",
        text,
    );
    assert_secret_refusal::<TaskAskReceipt>(memory.tasks_ask(spec), field, kind, "tasks_ask", text);
}

/// Both doors admit `spec`.
fn assert_admitted_at_both_doors(memory: &Memory<'_>, spec: &TaskAskSpec, text: &str) {
    memory
        .tasks_can_ask(spec)
        .unwrap_or_else(|error| panic!("the preflight admits {text:?}: {error:?}"));
    memory
        .tasks_ask(spec)
        .unwrap_or_else(|error| panic!("tasks_ask admits {text:?}: {error:?}"));
}

#[test]
fn the_payment_pin_digit_ask_is_refused_at_both_doors() {
    let fx = fixture();
    let memory = fx.memory();
    let label = "Select digit 1 of your payment PIN";
    let digits: Vec<String> = (0..10).map(|digit| digit.to_string()).collect();
    let ids: Vec<String> = (0..10).map(|digit| format!("d{digit}")).collect();
    let choices: Vec<Choice<'_>> = ids
        .iter()
        .zip(&digits)
        .map(|(id, digit)| choice(id, digit))
        .collect();
    let spec = fx.spec("payment-pin-digit-1", label, &choices, None);
    assert_refused_at_both_doors(&memory, &spec, "question label", "PIN", label);
}

/// One question per phrase of the guard's list, with the kind it names.
/// Spelling varies as people write it: hyphens, underscores, capitals, lower
/// case, plurals, possessives and qualifiers between a phrase's words.
const KIND_QUESTIONS: &[(&str, &str)] = &[
    ("Type the password you use for the bank", "password"),
    ("What is the passcode of your phone?", "passcode"),
    ("Which passphrase unlocks the backup?", "passphrase"),
    ("Which PINs did the bank send you?", "PIN"),
    ("Select digit 1 of your payment pin", "PIN"),
    ("Read me the pin code on the letter", "PIN"),
    ("Pick the last digit of your pin number", "PIN"),
    ("Enter the one-time code we texted you", "one-time code"),
    ("Enter the one-time login code", "one-time code"),
    ("Is your OTP closer to 4 or to 7?", "one-time code"),
    (
        "Paste the verification code from the email",
        "one-time code",
    ),
    ("Pick the 2FA code's first digit", "one-time code"),
    ("Which MFA codes did the app show?", "one-time code"),
    (
        "Does the CVV on the back start with 1?",
        "card security code",
    ),
    ("Is the card's CVC even?", "card security code"),
    ("What is the card security code?", "card security code"),
    ("What is the card's security code?", "card security code"),
    ("Read me the credit card number", "card number"),
    (
        "Which word starts your seed phrase?",
        "seed or recovery phrase",
    ),
    (
        "Choose the third word of the wallet recovery phrase",
        "seed or recovery phrase",
    ),
    ("Paste the SSH private key", "private key"),
    ("Paste the private SSH key", "private key"),
    ("Which API keys are on the account?", "API key"),
    ("Send the OPENAI_APIKEY value", "API key"),
    ("Share the GitHub access token", "access token"),
    ("Which secret key signs the webhook?", "secret key"),
];

#[test]
fn every_listed_secret_kind_is_refused_with_custody_as_the_way() {
    let fx = fixture();
    let memory = fx.memory();
    for (at, (label, kind)) in KIND_QUESTIONS.iter().enumerate() {
        let spec = fx.labelled(&format!("kind-question-{at}"), label);
        assert_refused_at_both_doors(&memory, &spec, "question label", kind, label);
    }
}

#[test]
fn every_caller_written_text_of_the_ask_is_checked() {
    let fx = fixture();
    let memory = fx.memory();

    let label = "Use the api_key value from your account";
    let spec = fx.spec(
        "option-label",
        "How should the bot sign in?",
        &[
            choice("one", "Keep the current login"),
            choice("two", label),
        ],
        None,
    );
    assert_refused_at_both_doors(&memory, &spec, "option `two` label", "API key", label);

    let then = "Then reply with the one-time code we text you";
    let spec = fx.spec(
        "option-then",
        "Confirm the transfer?",
        &[
            Choice {
                id: "confirm",
                label: "Confirm",
                then: Some(then),
            },
            choice("hold", "Hold it"),
        ],
        None,
    );
    assert_refused_at_both_doors(
        &memory,
        &spec,
        "option `confirm` then",
        "one-time code",
        then,
    );

    let why = "The bank asks for your card number first";
    let spec = fx.spec(
        "recommendation-reason",
        "Pay the invoice today?",
        &[choice("pay", "Pay"), choice("wait", "Wait")],
        Some(("pay", why)),
    );
    assert_refused_at_both_doors(&memory, &spec, "recommendation reason", "card number", why);
}

#[test]
fn a_question_that_names_a_kind_is_refused_and_its_reword_is_admitted() {
    for (at, (named, kind, reworded)) in [
        (
            "Should I rotate the API key now?",
            "API key",
            "Should I rotate the deploy credential now?",
        ),
        (
            "Pin this message to the room?",
            "PIN",
            "Keep this message at the top of the room?",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        // One vault each, so no ask waits beside another on the TURN.
        let fx = fixture();
        let memory = fx.memory();
        let spec = fx.labelled(&format!("named-{at}"), named);
        assert_refused_at_both_doors(&memory, &spec, "question label", kind, named);
        let spec = fx.labelled(&format!("reworded-{at}"), reworded);
        assert_admitted_at_both_doors(&memory, &spec, reworded);
    }
}

#[test]
fn texts_that_name_no_kind_are_admitted() {
    for (at, label) in [
        "Keep the pinned note above the spinner?",
        "What is your opinion on the token count budget?",
        "Should the keyboard shortcut open the passport scan?",
        "Run verification on the code before the merge?",
        "Grant access to the token budget page?",
    ]
    .into_iter()
    .enumerate()
    {
        // One vault each, so no ask waits beside another on the TURN.
        let fx = fixture();
        let memory = fx.memory();
        let spec = fx.spec(
            &format!("contains-a-kind-{at}"),
            label,
            &[
                choice("yes", "Yes, keep it pinned"),
                choice("no", "No opinion"),
            ],
            Some(("yes", "Spinning it up costs one token")),
        );
        assert_admitted_at_both_doors(&memory, &spec, label);
    }
}
