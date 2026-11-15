//! Rung 2's reply (INBOX-RESIDUE PR-3b-3c-2): only an email reply on the
//! thread a first send of the page's agent began is a rung-2 reply; it counts
//! against the page's session caps in the vault (RUNG2-REPLY-CAP = B), and
//! its one parse decides what it says (RUNG2-REPLY-CONSTRAINT = B,
//! RUNG2-REPLY-OFF-TOPIC = B). The parse is injected here: the seat's own is
//! the page's (`free_text.rs`).

use std::cell::Cell;

use oneiron::booking::constraint::ConstraintParseDisposition;
use oneiron::{EdgeActorClass, WriteActor};

use super::*;
use crate::api::booking::rung2_reply::{Rung2Reply, rung2_reply_with, rung2_thread_send};
use crate::error::ApiError;

/// The owner's off-topic line in [`front`].
const OFF_TOPIC_LINE: &str = "I can help with scheduling only.";

/// The page session's first send, kept by the visitor's press and held.
fn kept_send(page: &Rung2Page, session: &str) -> Rung2FirstSend {
    page.turn_kept(session);
    let dispatched = RefCell::new(Vec::new());
    page.press(session, VISITOR, &dispatched)
        .expect("the visitor's press");
    page.kept(session).expect("the first send is kept")
}

/// The reply event `event_id` on `kept`'s thread, its parse answering
/// `parse`; each parse it runs is counted in `parses`.
fn reply(
    page: &Rung2Page,
    kept: &Rung2FirstSend,
    event_id: &str,
    parses: &Cell<usize>,
    parse: Result<ConstraintParseDisposition, ApiError>,
) -> Option<Rung2Reply> {
    rung2_reply_with(page.server(), kept, event_id, now(), |_| {
        parses.set(parses.get() + 1);
        parse
    })
    .expect("the reply")
}

/// A parse that names no new constraint.
fn unparsed() -> Result<ConstraintParseDisposition, ApiError> {
    Err(ApiError::invalid_state(Some("booking_parse_not_admitted")))
}

/// Any time a month from now: past the fixture's 7-day booking window, so
/// nothing fits it.
fn a_month_out() -> ConstraintObject {
    let start = now() + 30 * 86_400;
    ConstraintObject {
        schema_version: CONSTRAINT_SCHEMA_VERSION,
        weekdays: Vec::new(),
        local_time_windows: Vec::new(),
        utc_window: Some(TimeRange {
            start,
            end: start + 86_400,
        }),
        allow_flex_pool: false,
    }
}

fn offer_count(text: &str) -> usize {
    text.lines().filter(|line| line.starts_with("- ")).count()
}

/// A reply that parses solves its own constraint, not the kept one, and
/// the agent answers it with the solver's offers in its context and
/// appended to its words. The page's sponsor pays: here the fixture's
/// owner, whom the publish door stamps as the page's sponsor; never the
/// agent.
#[test]
fn a_reply_that_parses_solves_its_own_constraint_and_the_sponsor_pays() {
    let page = Rung2Page::new(true);
    let kept = kept_send(&page, "rung2-reply-parse");
    let parses = Cell::new(0);
    let parsed = ConstraintParseDisposition::Constraint {
        object: a_month_out(),
        visitor_tz_override: None,
    };
    let answer = match reply(&page, &kept, "reply-1", &parses, Ok(parsed)) {
        Some(Rung2Reply::Answer(answer)) => answer,
        other => panic!("an admitted reply that parses is the agent's to answer: {other:?}"),
    };
    assert_eq!(parses.get(), 1, "one parse");
    assert!(
        answer.offers.starts_with(NO_FIT_LINE),
        "the reply's own constraint fits nothing; the kept one fits: {}",
        answer.offers
    );
    assert_eq!(offer_count(&answer.offers), 0, "{}", answer.offers);
    assert!(
        answer.context.ends_with(&answer.offers),
        "the agent reads the offers its words go out with: {}",
        answer.context
    );
    assert_eq!(
        answer.payer,
        WriteActor::new(id(0x77), EdgeActorClass::Human)
    );
    assert_ne!(answer.payer.entity_ref(), page.agent);
}

/// A reply that names no new constraint re-solves the kept one, and the
/// kept send is never rewritten.
#[test]
fn a_reply_that_does_not_parse_re_solves_the_kept_constraint() {
    let page = Rung2Page::new(true);
    let session = "rung2-reply-unparsed";
    let kept = kept_send(&page, session);
    let parses = Cell::new(0);
    let answer = match reply(&page, &kept, "reply-1", &parses, unparsed()) {
        Some(Rung2Reply::Answer(answer)) => answer,
        other => panic!("an admitted reply is the agent's to answer: {other:?}"),
    };
    assert!(
        answer.offers.starts_with(SLOTS_LINE),
        "the kept constraint fits: {}",
        answer.offers
    );
    assert!(
        (1..=3).contains(&offer_count(&answer.offers)),
        "one to three solver offers: {}",
        answer.offers
    );
    assert_eq!(page.kept(session), Some(kept), "the kept send stands");
}

/// A reply about something other than scheduling gets the owner's
/// off-topic line, signed as the page signs, and no answer from a model.
#[test]
fn an_off_topic_reply_answers_the_owners_off_topic_line() {
    let page = Rung2Page::new(true);
    let kept = kept_send(&page, "rung2-reply-off-topic");
    let parses = Cell::new(0);
    let off_topic = Ok(ConstraintParseDisposition::OffTopic);
    let words = match reply(&page, &kept, "reply-1", &parses, off_topic) {
        Some(Rung2Reply::Fixed(words)) => words,
        other => panic!("an off-topic reply is the owner's line alone: {other:?}"),
    };
    assert!(words.starts_with(OFF_TOPIC_LINE), "{words}");
    assert!(words.contains("Fixture scheduling"), "{words}");
    assert_eq!(offer_count(&words), 0, "{words}");
}

/// The thread's replies count against the page's caps (4 turns, 4 model
/// calls) after the session's no-fit turn (1 turn, 1 call): the first reply
/// (1 turn, 2 calls) fits, and the next would need 5 calls. Past the caps a
/// reply parses nothing and answers the owner's no-fit line with the kept
/// constraint's offers. A rerun of an admitted event counts once.
#[test]
fn a_reply_past_the_pages_caps_answers_the_no_fit_line_and_the_offers_without_a_model_call() {
    let page = Rung2Page::new(true);
    let kept = kept_send(&page, "rung2-reply-cap");
    let parses = Cell::new(0);
    for _ in 0..2 {
        assert!(
            matches!(
                reply(&page, &kept, "reply-1", &parses, unparsed()),
                Some(Rung2Reply::Answer(_))
            ),
            "the first reply, and a rerun of it, fit the caps"
        );
    }
    assert_eq!(parses.get(), 2);
    for event in ["reply-2", "reply-3"] {
        let words = match reply(&page, &kept, event, &parses, unparsed()) {
            Some(Rung2Reply::Fixed(words)) => words,
            other => panic!("{event} is past the caps: {other:?}"),
        };
        assert!(words.starts_with(NO_FIT_LINE), "{words}");
        assert!(
            (1..=3).contains(&offer_count(&words)),
            "the kept constraint's offers: {words}"
        );
    }
    assert_eq!(parses.get(), 2, "a reply past the caps parses nothing");
}

/// Once the page no longer publishes, its thread is an ordinary one: no
/// tally, no parse, no offers.
#[test]
fn a_reply_after_the_page_is_unpublished_is_an_ordinary_reply() {
    let page = Rung2Page::new(true);
    let kept = kept_send(&page, "rung2-reply-unpublished");
    page.fixture
        .publish_page(page.fixture.page, false, 1, now() + 86_400);
    let parses = Cell::new(0);
    assert!(reply(&page, &kept, "reply-1", &parses, unparsed()).is_none());
    assert_eq!(parses.get(), 0);
}

/// Only an email reply on a thread can be a rung-2 reply, and a thread ref
/// no passport can carry is the agent's ordinary reply, never an error. A
/// held first send began no thread.
#[test]
fn a_reply_off_a_rung2_thread_is_an_ordinary_reply() {
    let page = Rung2Page::new(true);
    let kept = kept_send(&page, "rung2-reply-no-thread");
    let thread = oneiron::canonical_message_id(&kept.message_id)
        .expect("the kept Message-ID")
        .minted_thread_ref();
    for (channel, thread_ref) in [
        ("slack", Some(thread.as_str())),
        ("email", None),
        ("email", Some("not a thread ref")),
        ("email", Some(thread.as_str())),
    ] {
        let found = rung2_thread_send(&page.server().vault, channel, thread_ref, page.agent)
            .expect("an ordinary reply is no error");
        assert_eq!(found, None, "{channel} {thread_ref:?}");
    }
}

/// The owner's press delivers the first send, which files its thread, and a
/// reply on that thread is the page agent's rung-2 reply. Another agent on
/// the thread answers as itself.
#[cfg(oneiron_test_support)]
#[test]
fn a_reply_on_a_delivered_first_sends_thread_is_its_agents_rung2_reply() {
    let page = Rung2Page::new(true);
    let vault = &page.server().vault;
    oneiron::test_doors::booking_rung2_thread::hold_cold_mail_for_owner_press(vault, page.agent)
        .expect("the cold-send policy");
    let session = "rung2-reply-delivered";
    page.turn_kept(session);
    let transport = RefCell::new(CountingTransport::default());
    page.press_with(session, VISITOR, |vault, kept| {
        dispatch_through(&page.adapter, &transport, vault, kept)
    })
    .expect("the visitor's press");
    let owner = crate::test_credentials::embedded_owner(vault);
    release_kept_first_send(
        vault,
        &owner,
        &page.adapter,
        &rung2_send_ref(&page.fixture.page, session),
        |vault, kept| dispatch_through(&page.adapter, &transport, vault, kept),
    )
    .expect("the owner's press");
    assert_eq!(transport.borrow().delivered, 1, "the first send went out");
    let kept = page.kept(session).expect("the first send is kept");
    let thread = oneiron::canonical_message_id(&kept.message_id)
        .expect("the kept Message-ID")
        .minted_thread_ref();
    assert_eq!(
        rung2_thread_send(vault, "email", Some(&thread), page.agent).expect("lookup"),
        Some(kept),
        "the page agent's reply on the thread is a rung-2 reply"
    );
    assert_eq!(
        rung2_thread_send(vault, "email", Some(&thread), id(0x82)).expect("lookup"),
        None,
        "another agent's reply on the thread is its own"
    );
}
