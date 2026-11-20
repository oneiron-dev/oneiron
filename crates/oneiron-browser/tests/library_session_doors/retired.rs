//! The `library_retired` door's tests: the normalized explicit site,
//! the open page's site by default, and the refusal on a blank page.
//!
//! The store is a fake: these tests prove what the door forwards and
//! returns, not the real vault store's filter or order.

use super::session_fixture::SessionFixture;
use super::workflow_store::{PAGE_URL, StoreCall, card, trace};
use oneiron_browser::{BrowserDriver, BrowserError, LibraryRetiredInput};

#[test]
fn retired_uses_the_normalized_explicit_site_and_preserves_the_traces() {
    let mut fixture = SessionFixture::attach("about:blank");
    let first = trace(card("wf2"), 12, Some("second"));
    let second = trace(card("wf1"), 9, None);
    fixture.store.lock().expect("store locks").retired = vec![first.clone(), second.clone()];
    let mark = fixture.peer.mark();
    let result = fixture.session.library_retired(LibraryRetiredInput {
        site: Some(" SHOP.EXAMPLE ".to_owned()),
    });
    let output = fixture.expect_ok(result, "an explicit site lists");
    assert_eq!(output.site, "shop.example");
    assert_eq!(
        serde_json::to_value(&output.retired).expect("traces encode"),
        serde_json::to_value(&[first, second]).expect("canned traces encode")
    );
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(store.calls, [StoreCall::Retired("shop.example".to_owned())]);
    drop(store);
    fixture.assert_methods(mark, &[]);
}

#[test]
fn retired_defaults_to_the_raw_open_page_site() {
    let mut fixture = SessionFixture::attach(PAGE_URL);
    let kept = trace(card("wf1"), 9, None);
    fixture.store.lock().expect("store locks").retired = vec![kept.clone()];
    let mark = fixture.peer.mark();
    let result = fixture
        .session
        .library_retired(LibraryRetiredInput::default());
    let output = fixture.expect_ok(result, "the open page names the site");
    assert_eq!(output.site, "shop.example");
    assert_eq!(
        serde_json::to_value(&output.retired).expect("traces encode"),
        serde_json::to_value(&[kept]).expect("canned trace encodes")
    );
    let store = fixture.store.lock().expect("store locks");
    assert_eq!(store.calls, [StoreCall::Retired("shop.example".to_owned())]);
    drop(store);
    fixture.assert_methods(mark, &["Target.getTargets", "Target.getTargetInfo"]);
}

#[test]
fn retired_without_a_site_on_a_blank_page_refuses_before_the_store() {
    let mut fixture = SessionFixture::attach("about:blank");
    let mark = fixture.peer.mark();
    let error = fixture
        .session
        .library_retired(LibraryRetiredInput::default())
        .expect_err("a blank page names no site");
    assert_eq!(
        error,
        BrowserError::Input("the open page has no site; name one".to_owned())
    );
    let store = fixture.store.lock().expect("store locks");
    assert!(store.calls.is_empty(), "a refused listing reads no store");
    drop(store);
    fixture.assert_methods(mark, &["Target.getTargets", "Target.getTargetInfo"]);
}
