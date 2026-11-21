//! The `library_propose` door's six fresh-replay tests
//! (FIX [BROWSER-LIBRARY-SESSION-DOORS-HELD-BY-NO-TEST]). The sessions are real;
//! both peers, the store and the custody are fakes. Values used as secrets are fabricated.

use super::fresh_guest::{RecordingFreshGuest, replay_requests};
use super::scripted_chromium::Request;
use super::secret_custody::{CustodyCall, RecordingSecretCustody};
use super::session_fixture::SessionFixture;
use super::workflow_store::{PAGE_URL, StoreCall};
use oneiron_browser::{
    AdmissionRefusal, Admitted, BatchOutput, BatchStep, BrowserDriver, BrowserEngine, CheckReceipt,
    EffectReceipt, ExpectInput, ExpectOutput, ObserveInput, OperandGap, ProposeInput,
    ProposeOutput, ReplayAction, ReplayGuest, SecretKind, SecretParam, StoragePhase, SubgoalStatus,
    SupersedeRefusal, SwitchCarried, SwitchComponent, TypeOperand, WorkflowCheck, WorkflowProgram,
    WorkflowProof, is_live_handle,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The site, as the library keys it.
const SITE: &str = "shop.example";
/// The origin, as the carry records it.
const ORIGIN: &str = "https://shop.example";
/// The subgoal.
const SUBGOAL: &str = "Ready form";
/// The Ready heading check.
fn ready() -> ExpectInput {
    heading("Ready")
}

/// The Never heading check.
fn never() -> ExpectInput {
    heading("Never")
}

/// The heading check for `name`.
fn heading(name: &str) -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some(name.to_owned()),
        ..Default::default()
    }
}

/// One Open of the page and its Ready check.
fn common_proposal() -> ProposeInput {
    ProposeInput {
        subgoal: SUBGOAL.to_owned(),
        params: Vec::new(),
        steps: vec![BatchStep::Open {
            url: PAGE_URL.to_owned(),
        }],
        postcondition: vec![ready()],
        args: BTreeMap::new(),
        replay_args: BTreeMap::new(),
        supersedes: None,
        seed: None,
        candidate: None,
        secret_args: BTreeMap::new(),
        snapshot_bounds: None,
    }
}

/// Empty sign-in: no cookie, no item, nothing lost.
fn expected_empty_carry_guest() -> ReplayGuest {
    let kept = |component| SwitchCarried {
        component,
        origin: Some(ORIGIN.to_owned()),
        count: Some(0),
        phase: Some(StoragePhase::FreshExport),
        after_receipt: Some(0),
    };
    ReplayGuest {
        engine: BrowserEngine::Chromium,
        carried: vec![
            SwitchCarried {
                component: SwitchComponent::Cookies,
                origin: None,
                count: Some(0),
                phase: None,
                after_receipt: None,
            },
            kept(SwitchComponent::LocalStorage),
            kept(SwitchComponent::SessionStorage),
        ],
        not_carried: Vec::new(),
    }
}

/// The complete filing call log, including the early lookup for a proposal with a link.
fn filing_calls(
    program: &WorkflowProgram,
    proof: &WorkflowProof,
    link: Option<&str>,
) -> Vec<StoreCall> {
    let mut calls = Vec::new();
    if let Some(link) = link {
        calls.push(StoreCall::SupersedesRefused(
            SITE.to_owned(),
            link.to_owned(),
        ));
    }
    calls.push(StoreCall::Admit(
        SITE.to_owned(),
        serde_json::to_value(program).expect("program encodes"),
        serde_json::to_value(proof).expect("proof encodes"),
        link.map(str::to_owned),
    ));
    calls
}

/// A program that keeps the proposal's unfilled template.
fn template(input: &ProposeInput) -> WorkflowProgram {
    WorkflowProgram {
        subgoal: input.subgoal.clone(),
        params: input.params.clone(),
        secret_params: Vec::new(),
        steps: input.steps.clone(),
        postcondition: input.postcondition.clone(),
    }
}

/// A proof for the common proposal, retaining the live receipt metadata except
/// where a test changes it.
fn proof_for(replay: &BatchOutput) -> WorkflowProof {
    WorkflowProof {
        args: BTreeMap::new(),
        replay_args: BTreeMap::new(),
        held_out: false,
        seed: None,
        solved_url: PAGE_URL.to_owned(),
        solved_title: "Ready".to_owned(),
        replay_url: PAGE_URL.to_owned(),
        replay_receipts: replay.receipts.clone(),
        replay_decisions: Vec::new(),
        replay_guest: expected_empty_carry_guest(),
    }
}

/// The disposition of a pass or refusal, excluding replay and missed-check evidence.
fn assert_disposition(
    output: &ProposeOutput,
    workflow: Option<&str>,
    check: Option<WorkflowCheck>,
    refusal: Option<AdmissionRefusal>,
) {
    assert_eq!(output.admitted, workflow.is_some());
    assert_eq!(output.workflow.as_deref(), workflow);
    assert_eq!(output.refused_by, check);
    assert_eq!(output.refusal, refusal);
    assert_eq!(output.superseded, None);
}

/// A completed batch and its replay guest, even when a later gate refused the proposal.
fn finished_replay<'a>(
    output: &'a ProposeOutput,
    steps: usize,
    url: &str,
    title: &str,
) -> &'a BatchOutput {
    assert_eq!(
        output.replay_guest.as_ref(),
        Some(&expected_empty_carry_guest())
    );
    let replay = output
        .replay
        .as_ref()
        .expect("the answer includes the replay");
    assert_eq!(replay.status, SubgoalStatus::Done);
    assert_eq!(replay.completed, steps);
    assert!(replay.failed_step.is_none() && replay.error.is_none() && replay.stop_cause.is_none());
    assert!(
        replay.failed_receipt.is_none()
            && replay.decisions.is_empty()
            && replay.rebindings.is_empty()
    );
    assert_eq!(replay.receipts.len(), steps);
    let receipt = &replay.receipts[0];
    assert_eq!(
        (
            receipt.seq,
            receipt.verb.as_str(),
            receipt.url.as_str(),
            receipt.title.as_str()
        ),
        (1, "open", url, title)
    );
    assert_open_receipt(receipt, url, title);
    // `next` is not pinned: ProposeOutput's doc says no cursor pages the replay and
    // `page_replay` pages it (FIX [BROWSER-PROPOSE-DOCS-SAY-NO-CURSOR-PAGES-THE-REPLAY]).
    let page = replay
        .observation
        .as_ref()
        .expect("the replay read its page");
    assert_eq!((page.url.as_str(), page.title.as_str()), (url, title));
    replay
}

/// Stable fields of the replay's first effect receipt, from the fresh blank tab.
fn assert_open_receipt(receipt: &EffectReceipt, url: &str, title: &str) {
    assert!(
        receipt.target.is_none()
            && receipt.target_name.is_none()
            && receipt.target_locator.is_none()
    );
    assert!(receipt.rebound.is_none() && receipt.effect_class.is_none() && receipt.fact.is_none());
    assert_eq!(receipt.press, "none");
    assert!(
        receipt.screenshot.is_none()
            && receipt.capture_id.is_none()
            && receipt.screenshot_evidence.is_none()
    );
    assert_eq!(receipt.engine, Some(BrowserEngine::Chromium));
    assert_eq!(
        receipt.action,
        Some(ReplayAction::Open {
            url: url.to_owned()
        })
    );
    assert_eq!(receipt.source_url.as_deref(), Some("about:blank"));
    assert_eq!(receipt.source_title.as_deref(), Some(title));
    assert_eq!(
        (receipt.tab.as_deref(), receipt.result_tab.as_deref()),
        (Some("page-2"), Some("page-2"))
    );
    assert!(
        receipt.source_origin.is_none()
            && receipt.audience.is_none()
            && receipt.engine_switch.is_none()
    );
    assert!(receipt.text_source.is_none() && receipt.text_ref.is_none());
    assert!(receipt.result_unread.is_none() && receipt.outcome.is_none());
}

/// The fresh replay of an Open-only program never sends input.
fn assert_no_input(requests: &[Request]) {
    assert!(
        requests
            .iter()
            .all(|request| !request.method.starts_with("Input.")),
        "an Open-only replay sends no input"
    );
}

/// A prepared successful admission under the fake workflow reference.
fn prepare_filing(fixture: &SessionFixture) {
    fixture.store.lock().expect("store locks").admission = Some(Admitted::Filed {
        workflow: "wf1".to_owned(),
        superseded: None,
    });
}

#[test]
fn a_fresh_peer_replays_the_held_out_values_and_only_its_pass_files_the_template() {
    const SOLVED: &str = "https://shop.example/solved";
    const FRESH: &str = "https://shop.example/fresh";
    let mut fixture = SessionFixture::attach(SOLVED);
    fixture
        .peer
        .set_page_labels("Solved fixture", "Ready solved");
    prepare_filing(&fixture);
    let fresh = RecordingFreshGuest::new().with_page("Fresh fixture", "Ready fresh");
    fresh.install(&mut fixture.session);
    let input = ProposeInput {
        params: vec!["route".to_owned()],
        steps: vec![BatchStep::Open {
            url: "https://shop.example/{{route}}".to_owned(),
        }],
        postcondition: vec![heading("Ready {{route}}")],
        args: BTreeMap::from([("route".to_owned(), "solved".to_owned())]),
        replay_args: BTreeMap::from([("route".to_owned(), "fresh".to_owned())]),
        ..common_proposal()
    };
    let program = template(&input);
    let (args, replay_args) = (input.args.clone(), input.replay_args.clone());
    let mark = fixture.peer.mark();
    let result = fixture.session.library_propose(input);
    let output = fixture.expect_ok(result, "the held-out proposal answers");
    assert_disposition(&output, Some("wf1"), None, None);
    assert!(output.unmet.is_empty() && output.missed.is_empty());
    let replay = finished_replay(&output, 1, FRESH, "Fresh fixture");
    assert_no_input(&replay_requests(
        &fixture, &fresh, mark, 1, false, true, FRESH,
    ));
    let proof = WorkflowProof {
        args,
        replay_args,
        held_out: true,
        solved_url: SOLVED.to_owned(),
        solved_title: "Solved fixture".to_owned(),
        replay_url: FRESH.to_owned(),
        ..proof_for(replay)
    };
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(store.calls, filing_calls(&program, &proof, None));
    assert_eq!(store.live.len(), 1);
    assert!(store.live.contains_key("wf1") && store.retired.is_empty());
}

#[test]
fn a_live_check_handle_minted_on_the_solved_peer_files_as_a_locator() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let observed = fixture.session.observe(ObserveInput::default());
    let observed = fixture.expect_ok(observed, "the solved page reads");
    let row = observed.rows.first().expect("the solved heading");
    assert!(is_live_handle(&row.target) && !is_live_handle(&row.locator));
    let input = ProposeInput {
        postcondition: vec![ExpectInput {
            target: Some(row.target.clone()),
            ..Default::default()
        }],
        ..common_proposal()
    };
    let mut program = template(&input);
    program.postcondition[0].target = Some(row.locator.clone());
    prepare_filing(&fixture);
    let fresh = RecordingFreshGuest::new();
    fresh.install(&mut fixture.session);
    let mark = fixture.peer.mark();
    let result = fixture.session.library_propose(input);
    assert!(
        result.is_ok(),
        "the minted handle must normalize: {result:?}; unanswered: {:?}",
        fixture.peer.unanswered()
    );
    let output = fixture.expect_ok(result, "the live check is filed");
    assert_disposition(&output, Some("wf1"), None, None);
    assert!(output.unmet.is_empty() && output.missed.is_empty());
    let replay = finished_replay(&output, 1, PAGE_URL, "Ready");
    let fresh_row = &replay.observation.as_ref().expect("the fresh page").rows[0];
    assert_eq!(fresh_row.locator, row.locator);
    assert_ne!(fresh_row.target, row.target);
    assert_no_input(&replay_requests(
        &fixture, &fresh, mark, 1, false, true, PAGE_URL,
    ));
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(
        store.calls,
        filing_calls(&program, &proof_for(replay), None)
    );
    let StoreCall::Admit(_, program, _, _) = &store.calls[0] else {
        panic!("the store received a program")
    };
    assert!(!contains_fixture_value(program, &row.target));
}

#[test]
fn a_filing_time_link_refusal_keeps_the_replay_proof_in_the_answer_but_writes_nothing() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    {
        let mut store = fixture.store.lock().expect("store locks");
        store.predecessor_refusal = Some(None);
        store.admission = Some(Admitted::Refused(SupersedeRefusal::SameRecord));
    }
    let fresh = RecordingFreshGuest::new();
    fresh.install(&mut fixture.session);
    let input = ProposeInput {
        supersedes: Some("wf2".to_owned()),
        ..common_proposal()
    };
    let program = template(&input);
    let mark = fixture.peer.mark();
    let result = fixture.session.library_propose(input);
    let output = fixture.expect_ok(result, "the late refusal answers");
    assert_disposition(
        &output,
        None,
        Some(WorkflowCheck::Supersedes),
        Some(AdmissionRefusal::Supersedes {
            workflow: "wf2".to_owned(),
            why: SupersedeRefusal::SameRecord,
        }),
    );
    assert!(output.unmet.is_empty() && output.missed.is_empty());
    let replay = finished_replay(&output, 1, PAGE_URL, "Ready");
    assert_no_input(&replay_requests(
        &fixture, &fresh, mark, 1, false, true, PAGE_URL,
    ));
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(
        store.calls,
        filing_calls(&program, &proof_for(replay), Some("wf2"))
    );
    assert!(store.live.is_empty() && store.retired.is_empty());
}

#[test]
fn a_missed_replay_check_returns_its_evidence_without_writing_a_program() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    fixture.peer.set_page_labels("Ready Never", "Ready Never");
    prepare_filing(&fixture);
    let fresh = RecordingFreshGuest::new();
    fresh.install(&mut fixture.session);
    let input = ProposeInput {
        postcondition: vec![ready(), never()],
        ..common_proposal()
    };
    let mark = fixture.peer.mark();
    let result = fixture.session.library_propose(input);
    let output = fixture.expect_ok(result, "the missed replay answers");
    assert_disposition(&output, None, Some(WorkflowCheck::Replay), None);
    assert_eq!(output.unmet, [1]);
    assert_eq!(
        output.missed,
        [CheckReceipt {
            expect: never(),
            observed: ExpectOutput {
                met: false,
                row: None,
                partial: None,
                rebindings: Vec::new(),
            }
        }]
    );
    let _ = finished_replay(&output, 1, PAGE_URL, "Ready");
    assert_no_input(&replay_requests(
        &fixture, &fresh, mark, 2, false, false, PAGE_URL,
    ));
    let store = fixture.store.lock().expect("store locks");
    assert!(store.calls.is_empty() && store.live.is_empty() && store.retired.is_empty());
}

/// Checks the password's one wire send and the nonpolling act before it.
fn assert_password_send(requests: &[Request], passphrase: &str) {
    let input: Vec<_> = requests
        .iter()
        .enumerate()
        .filter(|(_, request)| request.method.starts_with("Input."))
        .collect();
    assert_eq!(input.len(), 1, "the fresh Type sends only one input");
    let (at, request) = input[0];
    assert_eq!(request.method, "Input.insertText");
    assert_eq!(request.params, json!({"text": passphrase}));
    let resolved = requests
        .iter()
        .position(|request| request.method == "DOM.resolveNode")
        .expect("the type resolves its password row");
    assert!(resolved < at, "resolution comes before the input");
    let methods: Vec<_> = requests[resolved..at]
        .iter()
        .map(|request| request.method.as_str())
        .collect();
    assert_eq!(
        methods,
        [
            "DOM.resolveNode",
            "Runtime.callFunctionOn",
            "Target.getTargetInfo",
            "Accessibility.getFullAXTree",
            "DOM.focus"
        ]
    );
    assert_eq!(requests[resolved].params, json!({"backendNodeId": 3}));
    assert_eq!(requests[at - 1].params, json!({"backendNodeId": 3}));
    let with_passphrase = requests
        .iter()
        .filter(|request| request.params.to_string().contains(passphrase));
    assert_eq!(with_passphrase.count(), 1, "only insertText receives it");
}

/// Searches a complete serialized fixture value for bytes or a run binding.
fn contains_fixture_value(value: &impl serde::Serialize, text: &str) -> bool {
    serde_json::to_string(value)
        .expect("fixture evidence encodes")
        .contains(text)
}

#[test]
fn text_typed_into_a_password_field_is_filed_as_a_slot_not_as_the_text() {
    // A made-up passphrase and run binding.
    const PASSPHRASE: &str = "fixture-passphrase";
    const BINDING: &str = "sc7";
    let mut fixture = SessionFixture::attach(PAGE_URL);
    fixture.peer.show_password_field();
    let proposer_custody = RecordingSecretCustody::new(BINDING);
    fixture
        .session
        .set_secret_custody(Arc::new(proposer_custody.clone()));
    let fresh_custody = RecordingSecretCustody::new(BINDING).checking_value(PASSPHRASE);
    let fresh = RecordingFreshGuest::new()
        .with_password_field()
        .with_custody(fresh_custody.clone());
    let observed = fixture.session.observe(ObserveInput::default());
    let observed = fixture.expect_ok(observed, "the blank password page reads");
    let row = observed
        .rows
        .iter()
        .find(|row| row.name == "Password")
        .expect("the solved page shows a password field");
    assert_eq!(
        row.secret.as_ref().map(|secret| secret.kind),
        Some(SecretKind::Password)
    );
    let locator = &row.locator;
    let type_step = |text, secret| BatchStep::Type {
        target: locator.clone(),
        text,
        secret,
        clear: false,
    };
    let type_action = |operand| ReplayAction::Type {
        locator: locator.clone(),
        operand,
        clear: false,
    };
    let mut input = common_proposal();
    input
        .steps
        .push(type_step(Some(PASSPHRASE.to_owned()), None));
    let mut program = template(&input);
    program.params = vec!["password".to_owned()];
    program.secret_params = vec![SecretParam {
        name: "password".to_owned(),
        kind: SecretKind::Password,
    }];
    program.steps[1] = type_step(None, Some("{{password}}".to_owned()));
    fresh.install(&mut fixture.session);
    prepare_filing(&fixture);
    let mark = fixture.peer.mark();
    let result = fixture.session.library_propose(input);
    let output = fixture.expect_ok(result, "the password-slot proposal answers");
    let requests = replay_requests(&fixture, &fresh, mark, 1, false, true, PAGE_URL);
    assert_password_send(&requests, PASSPHRASE);
    assert!(
        fixture
            .peer
            .requests_since(0)
            .iter()
            .all(|request| !request.params.to_string().contains(PASSPHRASE))
    );
    assert_disposition(&output, Some("wf1"), None, None);
    assert!(output.unmet.is_empty() && output.missed.is_empty());
    let replay = finished_replay(&output, 2, PAGE_URL, "Ready");
    assert_eq!(
        (replay.receipts[1].seq, replay.receipts[1].verb.as_str()),
        (2, "type")
    );
    assert_eq!(
        replay.receipts[1].action,
        Some(type_action(TypeOperand::Secret {
            kind: SecretKind::Password,
            handle: BINDING.to_owned(),
        }))
    );
    let mut proof = proof_for(replay);
    proof.replay_receipts[1].action = Some(type_action(TypeOperand::Withheld {
        kind: Some(SecretKind::Password),
        cause: OperandGap::Unbound,
    }));
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(store.calls, filing_calls(&program, &proof, None));
    assert_eq!(store.live.len(), 1);
    assert!(store.live.contains_key("wf1") && store.retired.is_empty());
    let StoreCall::Admit(_, program, proof, _) = &store.calls[0] else {
        panic!("the store receives the filing")
    };
    let proposer_calls = proposer_custody.calls();
    let fresh_calls = fresh_custody.calls();
    assert!(
        proposer_calls.is_empty(),
        "the blank password acquires nothing"
    );
    assert_eq!(
        fresh_calls,
        [CustodyCall::CheckedAcquire {
            kind: SecretKind::Password,
            matches_expected: true,
            origin: ORIGIN.to_owned()
        }]
    );
    for text in [PASSPHRASE, BINDING] {
        assert!(!contains_fixture_value(program, text));
        assert!(!contains_fixture_value(proof, text));
        assert!(!contains_fixture_value(&proposer_calls, text));
        assert!(!contains_fixture_value(&fresh_calls, text));
    }
    assert!(!contains_fixture_value(&output, PASSPHRASE));
    assert!(
        contains_fixture_value(&output, BINDING),
        "the live receipt keeps its run binding"
    );
}

#[test]
fn a_replay_miss_on_an_unchanged_otp_names_the_slot_not_a_generic_replay_failure() {
    // A made-up one-time code and made-up custody handles.
    const OTP: &str = "654321";
    const BINDING: &str = "sc8";
    const FRESH_BINDING: &str = "sc9";
    let mut fixture = SessionFixture::attach(PAGE_URL);
    fixture.peer.show_otp_field(Some(OTP));
    let proposer_custody = RecordingSecretCustody::new(BINDING);
    fixture
        .session
        .set_secret_custody(Arc::new(proposer_custody.clone()));
    let fresh_custody = RecordingSecretCustody::new(FRESH_BINDING);
    let fresh = RecordingFreshGuest::new()
        .with_otp_field()
        .with_custody(fresh_custody.clone());
    fresh.install(&mut fixture.session);
    let check = ExpectInput {
        role: Some("textbox".to_owned()),
        name: Some("Verification code".to_owned()),
        ..Default::default()
    };
    let input = ProposeInput {
        postcondition: vec![ExpectInput {
            value: Some(OTP.to_owned()),
            ..check.clone()
        }],
        ..common_proposal()
    };
    let mark = fixture.peer.mark();
    let result = fixture.session.library_propose(input);
    let output = fixture.expect_ok(result, "the OTP replay refusal answers");
    assert_no_input(&replay_requests(
        &fixture, &fresh, mark, 1, true, false, PAGE_URL,
    ));
    let _ = finished_replay(&output, 1, PAGE_URL, "Ready");
    assert_disposition(
        &output,
        None,
        Some(WorkflowCheck::SecretReplay),
        Some(AdmissionRefusal::SecretReplay {
            slots: vec!["otp".to_owned()],
        }),
    );
    assert_eq!(output.unmet, [0]);
    assert_eq!(output.missed.len(), 1);
    let missed = &output.missed[0];
    // The miss's `value` is not pinned: `library::missed` clones the filled check
    // (FIX [BROWSER-PROPOSE-MISS-EVIDENCE-KEEPS-A-SECRET-SLOTS-FILLED-VALUE]).
    assert_eq!(
        ExpectInput {
            value: None,
            ..missed.expect.clone()
        },
        check
    );
    assert!(
        !missed.observed.met
            && missed.observed.partial.is_none()
            && missed.observed.rebindings.is_empty()
    );
    let row = missed
        .observed
        .row
        .as_ref()
        .expect("the replay finds a blank OTP field");
    assert_eq!(
        (row.role.as_str(), row.name.as_str()),
        ("textbox", "Verification code")
    );
    assert_eq!(row.value, None);
    let secret = row
        .secret
        .as_ref()
        .expect("the blank OTP field is classified");
    assert_eq!(secret.kind, SecretKind::Otp);
    assert!(secret.handle.is_none() && secret.note.is_none());
    let store = fixture.store.lock().expect("store locks");
    assert!(
        store.calls.is_empty() && store.live.is_empty() && store.retired.is_empty(),
        "no program or proof is offered to the store"
    );
    let proposer_calls = proposer_custody.calls();
    let fresh_calls = fresh_custody.calls();
    assert_eq!(
        proposer_calls,
        [CustodyCall::Acquire {
            kind: SecretKind::Otp,
            value: OTP.to_owned(),
            origin: ORIGIN.to_owned()
        }]
    );
    assert!(fresh_calls.is_empty());
    let mut public_answer = serde_json::to_value(&output).expect("the OTP refusal encodes");
    if let Some(filled_check) = public_answer
        .pointer_mut("/missed/0/expect")
        .and_then(Value::as_object_mut)
    {
        filled_check.remove("value");
    }
    assert!(!contains_fixture_value(&public_answer, OTP));
    assert!(contains_fixture_value(&proposer_calls, OTP));
    assert!(!contains_fixture_value(&fresh_calls, OTP));
    for binding in [BINDING, FRESH_BINDING] {
        assert!(!contains_fixture_value(&output, binding));
        assert!(!contains_fixture_value(&proposer_calls, binding));
        assert!(!contains_fixture_value(&fresh_calls, binding));
    }
}
