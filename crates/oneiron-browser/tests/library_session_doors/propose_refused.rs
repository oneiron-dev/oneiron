//! The `library_propose` door's four refusals before any replay starts
//! (FIX [BROWSER-LIBRARY-SESSION-DOORS-HELD-BY-NO-TEST]): a store-refused
//! cross-site link, unchanged held-out values, a missed solved check, and a
//! missing fresh guest. The session is real; the browser and the store are
//! fakes. The peer proves the door's hidden read and checks, not a real
//! browser's answers. No secret appears here.

use super::fresh_guest::RecordingFreshGuest;
use super::session_fixture::SessionFixture;
use super::workflow_store::{PAGE_URL, StoreCall, card, filed_workflow};
use oneiron_browser::{
    AdmissionRefusal, BatchStep, BrowserDriver, CheckReceipt, ExpectInput, ExpectOutput,
    ProposeInput, SupersedeRefusal, SwitchStage, WorkflowCheck,
};
use std::collections::BTreeMap;

/// The door's hidden read of the solved page: the tab follow, the capture's
/// frame tree, document, access tree, frame graft, document, and second
/// frame tree with document, then the page's shown URL and title.
const HIDDEN_READ_METHODS: [&str; 9] = [
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Target.getTargetInfo",
];

/// The hidden read and one check.
const HIDDEN_READ_AND_ONE_CHECK_METHODS: [&str; 17] = [
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Target.getTargetInfo",
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
];

/// The hidden read and two checks.
const HIDDEN_READ_AND_TWO_CHECKS_METHODS: [&str; 25] = [
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Target.getTargetInfo",
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
];

/// A check the fixture page meets: its Ready heading.
fn ready() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Ready".to_owned()),
        ..Default::default()
    }
}

/// A check the fixture page misses: no row is named Never.
fn never() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Never".to_owned()),
        ..Default::default()
    }
}

/// The common proposal: the Ready form's opening and its met check, with no
/// parameters, values or links.
fn proposal() -> ProposeInput {
    ProposeInput {
        subgoal: "Ready form".to_owned(),
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

/// What a missed check's read found: no row, no cut tree, no rebindings.
fn unmet_observed() -> ExpectOutput {
    ExpectOutput {
        met: false,
        row: None,
        partial: None,
        rebindings: Vec::new(),
    }
}

/// Asserts the door drove nothing in its window: no navigation, no input.
fn assert_no_drive(fixture: &SessionFixture, mark: usize) {
    let requests = fixture.peer.requests_since(mark);
    assert!(
        requests
            .iter()
            .all(|request| request.method != "Page.navigate"),
        "a refused proposal navigates nowhere"
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.method.starts_with("Input.")),
        "a refused proposal sends no input"
    );
}

#[test]
fn a_cross_site_link_refused_by_the_store_never_starts_a_fresh_guest() {
    const OTHER_PAGE: &str = "https://other.example/form";
    let mut fixture = SessionFixture::attach(PAGE_URL);
    {
        let mut store = fixture.store.lock().expect("store state locks");
        let mut predecessor = card("wf2");
        predecessor.site = "other.example".to_owned();
        let mut filed = filed_workflow();
        filed.program.steps = vec![BatchStep::Open {
            url: OTHER_PAGE.to_owned(),
        }];
        filed.proof.solved_url = OTHER_PAGE.to_owned();
        filed.proof.replay_url = OTHER_PAGE.to_owned();
        store.live.insert("wf2".to_owned(), (predecessor, filed));
        store.predecessor_refusal = Some(Some(SupersedeRefusal::NotOnSite));
    }
    let fresh = RecordingFreshGuest::refusing();
    fresh.install(&mut fixture.session);
    let mark = fixture.peer.mark();
    let input = ProposeInput {
        supersedes: Some("wf2".to_owned()),
        ..proposal()
    };
    let result = fixture.session.library_propose(input);
    let output = fixture.expect_ok(result, "a refused link still answers");
    assert!(!output.admitted, "a refused link files nothing");
    assert_eq!(output.workflow, None, "no ref without a filing");
    assert_eq!(
        output.refused_by,
        Some(WorkflowCheck::Supersedes),
        "the link check refuses"
    );
    assert_eq!(
        output.refusal,
        Some(AdmissionRefusal::Supersedes {
            workflow: "wf2".to_owned(),
            why: SupersedeRefusal::NotOnSite,
        }),
        "the link and the store's reason"
    );
    assert!(output.unmet.is_empty(), "no check missed");
    assert!(output.missed.is_empty(), "no check evidence");
    assert!(output.replay.is_none(), "no replay ran");
    assert!(output.replay_guest.is_none(), "no guest started");
    assert_eq!(output.superseded, None, "nothing retired");
    assert!(
        fresh.calls().is_empty(),
        "the refused link starts no fresh guest"
    );
    assert_eq!(
        fixture.session.history_mark(),
        None,
        "the refusal notes nothing"
    );
    fixture.assert_methods(mark, &HIDDEN_READ_AND_ONE_CHECK_METHODS);
    assert_no_drive(&fixture, mark);
    let store = fixture.store.lock().expect("store state locks");
    assert_eq!(
        store.calls,
        [StoreCall::SupersedesRefused(
            "shop.example".to_owned(),
            "wf2".to_owned()
        )],
        "one early link read, no filing"
    );
    assert_eq!(store.live.len(), 1);
    assert!(store.live.contains_key("wf2") && store.retired.is_empty());
}

#[test]
fn unchanged_replay_values_refuse_at_the_door_before_reading_solved_checks() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let fresh = RecordingFreshGuest::refusing();
    fresh.install(&mut fixture.session);
    let mark = fixture.peer.mark();
    let input = ProposeInput {
        params: vec!["name".to_owned()],
        postcondition: vec![ExpectInput {
            role: Some("heading".to_owned()),
            name: Some("{{name}}".to_owned()),
            ..Default::default()
        }],
        args: BTreeMap::from([("name".to_owned(), "Ready".to_owned())]),
        replay_args: BTreeMap::from([("name".to_owned(), "Ready".to_owned())]),
        ..proposal()
    };
    let result = fixture.session.library_propose(input);
    let output = fixture.expect_ok(result, "held-out values still answer");
    assert!(!output.admitted, "held-out values file nothing");
    assert_eq!(output.workflow, None, "no ref without a filing");
    assert_eq!(
        output.refused_by,
        Some(WorkflowCheck::HeldOut),
        "the held-out check refuses"
    );
    assert_eq!(
        output.refusal,
        Some(AdmissionRefusal::HeldOut {
            used: vec!["name".to_owned()],
            missing: Vec::new(),
            unknown: Vec::new(),
            same: vec!["name".to_owned()],
        }),
        "the used slot, kept at the solved value"
    );
    assert!(output.unmet.is_empty(), "no check missed");
    assert!(output.missed.is_empty(), "no check evidence");
    assert!(output.replay.is_none(), "no replay ran");
    assert!(output.replay_guest.is_none(), "no guest started");
    assert_eq!(output.superseded, None, "nothing retired");
    assert!(
        fresh.calls().is_empty(),
        "the held-out refusal starts no fresh guest"
    );
    assert_eq!(
        fixture.session.history_mark(),
        None,
        "the refusal notes nothing"
    );
    fixture.assert_methods(mark, &HIDDEN_READ_METHODS);
    let store = fixture.store.lock().expect("store state locks");
    assert!(store.calls.is_empty(), "no store read before the refusal");
}

#[test]
fn a_missed_solved_check_names_its_input_index_and_never_starts_replay() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let fresh = RecordingFreshGuest::refusing();
    fresh.install(&mut fixture.session);
    let mark = fixture.peer.mark();
    let input = ProposeInput {
        postcondition: vec![ready(), never()],
        ..proposal()
    };
    let result = fixture.session.library_propose(input);
    let output = fixture.expect_ok(result, "a missed check still answers");
    assert!(!output.admitted, "a missed check files nothing");
    assert_eq!(output.workflow, None, "no ref without a filing");
    assert_eq!(
        output.refused_by,
        Some(WorkflowCheck::Solved),
        "the solved check refuses"
    );
    assert_eq!(output.refusal, None, "the misses say it");
    assert_eq!(output.unmet, [1_usize], "the miss at its own index");
    assert_eq!(
        output.missed,
        [CheckReceipt {
            expect: never(),
            observed: unmet_observed(),
        }],
        "the check, with what its read found"
    );
    assert!(output.replay.is_none(), "no replay ran");
    assert!(output.replay_guest.is_none(), "no guest started");
    assert_eq!(output.superseded, None, "nothing retired");
    assert!(
        fresh.calls().is_empty(),
        "the missed check starts no fresh guest"
    );
    assert_eq!(
        fixture.session.history_mark(),
        None,
        "the refusal notes nothing"
    );
    fixture.assert_methods(mark, &HIDDEN_READ_AND_TWO_CHECKS_METHODS);
    let store = fixture.store.lock().expect("store state locks");
    assert!(store.calls.is_empty(), "no store read before the refusal");
}

#[test]
fn an_unconfigured_fresh_guest_is_a_start_refusal_not_a_replay_on_the_solved_page() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    // No fresh guest is installed: the door must refuse without a start path.
    let mark = fixture.peer.mark();
    let result = fixture.session.library_propose(proposal());
    let output = fixture.expect_ok(result, "a missing guest still answers");
    assert!(!output.admitted, "a missing guest files nothing");
    assert_eq!(output.workflow, None, "no ref without a filing");
    assert_eq!(
        output.refused_by,
        Some(WorkflowCheck::FreshGuest),
        "the fresh-guest check refuses"
    );
    assert_eq!(
        output.refusal,
        Some(AdmissionRefusal::FreshGuest {
            stage: SwitchStage::Start,
            code: "browser_unsupported".to_owned(),
            detail: "this driver does not serve a proposal's fresh guest".to_owned(),
        }),
        "the start stage and the host's words"
    );
    assert!(output.unmet.is_empty(), "no check missed");
    assert!(output.missed.is_empty(), "no check evidence");
    assert!(output.replay.is_none(), "no replay ran");
    assert!(output.replay_guest.is_none(), "no guest started");
    assert_eq!(output.superseded, None, "nothing retired");
    assert_eq!(
        fixture.session.history_mark(),
        None,
        "the refusal notes nothing"
    );
    fixture.assert_methods(mark, &HIDDEN_READ_AND_ONE_CHECK_METHODS);
    assert_no_drive(&fixture, mark);
    let store = fixture.store.lock().expect("store state locks");
    assert!(store.calls.is_empty(), "no store read before the refusal");
}
