//! The `library_retire` door's tests: the forwarded reason and the
//! returned card, the missing card's answer, and the held browser's
//! refusal.
//!
//! The store is a fake: these tests prove what the door forwards and
//! returns, not the real vault store's retire or ownership rules.

use super::session_fixture::SessionFixture;
use super::workflow_store::{StoreCall, card, filed_workflow, trace};
use oneiron_browser::{BrowserDriver, BrowserError, LibraryRetireInput};

#[test]
fn a_retire_forwards_its_reason_and_returns_the_removed_card() {
    let mut fixture = SessionFixture::attach("about:blank");
    let card1 = card("wf1");
    fixture
        .store
        .lock()
        .expect("store locks")
        .live
        .insert("wf1".to_owned(), (card1.clone(), filed_workflow()));
    let mark = fixture.peer.mark();
    let result = fixture.session.library_retire(LibraryRetireInput {
        workflow: "wf1".to_owned(),
        reason: Some(" owner request ".to_owned()),
    });
    let output = fixture.expect_ok(result, "a live card retires");
    assert_eq!(
        serde_json::to_value(&output.retired).expect("retired card encodes"),
        serde_json::to_value(&card1).expect("card encodes")
    );
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(
        store.calls,
        [StoreCall::Retire(
            "wf1".to_owned(),
            Some(" owner request ".to_owned())
        )]
    );
    assert!(!store.live.contains_key("wf1"));
    assert_eq!(store.retired.len(), 1);
    assert_eq!(
        serde_json::to_value(&store.retired[0].card).expect("trace card encodes"),
        serde_json::to_value(&card1).expect("card encodes")
    );
    assert_eq!(store.retired[0].reason, Some(" owner request ".to_owned()));
    drop(store);
    fixture.assert_methods(mark, &[]);
}

#[test]
fn a_retire_with_no_live_card_answers_no_workflow() {
    let mut fixture = SessionFixture::attach("about:blank");
    let card1 = card("wf1");
    let kept = trace(card1, 9, None);
    fixture
        .store
        .lock()
        .expect("store locks")
        .retired
        .push(kept.clone());
    let mark = fixture.peer.mark();
    let error = fixture
        .session
        .library_retire(LibraryRetireInput {
            workflow: "wf1".to_owned(),
            reason: None,
        })
        .expect_err("no live card is no workflow");
    assert_eq!(error, BrowserError::NoWorkflow("wf1".to_owned()));
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(store.calls, [StoreCall::Retire("wf1".to_owned(), None)]);
    assert_eq!(
        serde_json::to_value(&store.retired).expect("traces encode"),
        serde_json::to_value(&[kept]).expect("trace encodes")
    );
    assert!(store.live.is_empty());
    drop(store);
    fixture.assert_methods(mark, &[]);
}

#[test]
fn a_person_holding_the_browser_prevents_retirement() {
    let mut fixture = SessionFixture::attach("about:blank");
    fixture
        .store
        .lock()
        .expect("store locks")
        .live
        .insert("wf1".to_owned(), (card("wf1"), filed_workflow()));
    let setup_mark = fixture.peer.mark();
    let takeover = fixture.session.take_over("person-1").map(drop);
    fixture.expect_ok(takeover, "a person takes the browser");
    fixture.assert_methods(setup_mark, &[]);
    let mark = fixture.peer.mark();
    let error = fixture
        .session
        .library_retire(LibraryRetireInput {
            workflow: "wf1".to_owned(),
            reason: None,
        })
        .expect_err("a held browser refuses a retire");
    assert_eq!(error, BrowserError::BrowserTakenOver("held".to_owned()));
    let store = fixture.store.lock().expect("store locks");
    assert!(store.calls.is_empty(), "a refused retire reads no store");
    assert!(store.live.contains_key("wf1"));
    drop(store);
    fixture.assert_methods(mark, &[]);
}
