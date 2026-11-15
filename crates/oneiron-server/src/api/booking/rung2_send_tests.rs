//! Rung 2 on the public page (INBOX-RESIDUE PR-3b-3b): the turn keeps the
//! continuation host-side, the visitor's send keeps the page agent's first
//! send once per session and to one address, the owner's rate row bounds it,
//! and a page that cannot continue by email asks for none. The owner's press
//! (PR-3b-3c, `vault.booking.rung2.release_once`) approves the kept words
//! once and sends them.
//!
//! The send runs on a test native-mail adapter on [`DOMAIN`], and its
//! dispatch is recorded rather than sent: the cold-send hold of a kept send
//! is the engine's own (`tests/booking_rung2_thread.rs`). With
//! `--cfg oneiron_test_support` one press test meets that hold for real,
//! through the engine's own dispatch into a counting transport.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use oneiron::booking::agent_front::{ConstraintContinuation, ConstraintFrontConfig};
use oneiron::booking::anti_abuse::BookingRequestFacts;
use oneiron::booking::constraint::{
    CONSTRAINT_SCHEMA_VERSION, ConstraintObject, ConstraintWeekday, LocalMinuteWindow,
};
use oneiron::booking::publication::PublicBookingAuthority;
use oneiron::booking::rung2::{
    BOOKING_RUNG2_NOTICE_PRODUCER, Rung2FirstSend, Rung2Offer, Rung2Sender, rung2_send_ref,
};
use oneiron::channel_identity::{ChannelIdentityFulfillment, ChannelIdentityStep};
use oneiron::channel_identity_lifecycle::ProvisionIntent;
use oneiron::channel_identity_provider::EmailProviderInbound;
use oneiron::channel_identity_provider::native_mail::{
    NativeMailAdapter, NativeMailHost, NativeMailRunMode,
};
use oneiron::task_verb::sdk::{BookingRung2ReleaseOnceResponse, BookingRung2ReleaseOutcome};

use super::super::admission::rung2_send_facts;
use super::super::front::ConstraintTurnResponse;
use super::super::rung2::{
    Rung2Dispatched, Rung2Send, Rung2SendInput, Rung2SendResponse, rung2_continuations,
    rung2_turn_answer,
};
use super::super::rung2_release::release_kept_first_send;
use super::super::subject::session_key;
use super::fixture::*;
use super::*;
use crate::config::BookingConfig;

/// The host's managed native-mail domain in these tests.
const DOMAIN: &str = "agents.example.com";
const VISITOR: &str = "visitor@example.org";
const NO_FIT_LINE: &str = "Nothing fits that yet; every open time is on the page.";
const SLOTS_LINE: &str = "These times fit what you asked for.";

/// The host behind the test adapter: it provisions nothing and verifies no
/// webhook. The send's Message-ID needs only the domain.
struct Host;

impl NativeMailHost for Host {
    fn provision(
        &self,
        intent: &ProvisionIntent,
        mode: NativeMailRunMode,
    ) -> oneiron::Result<String> {
        Ok(format!("{mode:?}:{}", intent.identity_id.to_hex()))
    }

    fn verify_webhook(
        &self,
        _body: &[u8],
        _headers: &BTreeMap<String, String>,
    ) -> oneiron::Result<EmailProviderInbound> {
        Err(oneiron::Error::InvalidConfig(
            "the fixture verifies no webhook".to_owned(),
        ))
    }
}

/// A published page whose front names an agent, and that agent.
struct Rung2Page {
    fixture: Fixture,
    adapter: NativeMailAdapter<Host>,
    agent: EntityId,
}

impl Rung2Page {
    /// The page's agent holds a live derived native mailbox on [`DOMAIN`]
    /// when `mailbox`.
    fn new(mailbox: bool) -> Self {
        Self::on(Fixture::new(), mailbox)
    }

    fn on(fixture: Fixture, mailbox: bool) -> Self {
        let adapter =
            NativeMailAdapter::new(DOMAIN, NativeMailRunMode::SelfRun, Host).expect("adapter");
        let agent = id(0x81);
        let vault = &fixture.server.vault;
        vault
            .put_entity(
                &agent,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"scheduling agent",
            )
            .expect("the page's agent");
        if mailbox {
            let identity = EntityId::now();
            vault
                .create_channel_identity(&identity, &adapter.requested_identity(identity, agent, 1))
                .expect("birth the mailbox");
            vault
                .step_channel_identity(
                    &identity,
                    ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
                    2,
                )
                .expect("bind the mailbox");
            vault
                .step_channel_identity(&identity, ChannelIdentityStep::Fulfill, 3)
                .expect("fulfill the mailbox");
        }
        fixture.publish_front(&front(agent));
        Self {
            fixture,
            adapter,
            agent,
        }
    }

    fn server(&self) -> &SyncServer {
        &self.fixture.server
    }

    fn authority(&self) -> PublicBookingAuthority {
        let (page_ref, publication) =
            resolve_public_booking_page(self.server(), &self.fixture.token).expect("live page");
        PublicBookingAuthority {
            page_ref,
            publication,
        }
    }

    fn sender(&self) -> Rung2Sender {
        let offer = self
            .server()
            .vault
            .booking_rung2_offer_on_native_mail(self.fixture.page, now(), Some(DOMAIN))
            .expect("offer");
        let Rung2Offer::Offered(sender) = offer else {
            panic!("the agent's native mailbox is its named address: {offer:?}")
        };
        assert_eq!(sender.agent_ref, self.agent);
        sender
    }

    /// A no-fit turn of `session` kept its continuation for the send.
    fn turn_kept(&self, session: &str) {
        rung2_continuations().keep(
            session_key(self.fixture.page, session),
            continuation(session),
            now(),
        );
    }

    /// One press of `session` for `email`, its dispatch recorded in
    /// `dispatched` and answered held.
    fn press(
        &self,
        session: &str,
        email: &str,
        dispatched: &RefCell<Vec<Rung2FirstSend>>,
    ) -> Result<Rung2SendResponse, ApiError> {
        self.press_with(session, email, |_, kept| {
            dispatched.borrow_mut().push(kept.clone());
            Ok(Rung2Dispatched::Held)
        })
    }

    /// One press of `session` for `email`, its kept send handed to
    /// `dispatch`.
    fn press_with(
        &self,
        session: &str,
        email: &str,
        dispatch: impl FnOnce(&Vault, &Rung2FirstSend) -> Result<Rung2Dispatched, ApiError>,
    ) -> Result<Rung2SendResponse, ApiError> {
        let authority = self.authority();
        let front = authority
            .publication
            .constraint_front
            .clone()
            .expect("front");
        let input = Rung2SendInput {
            visitor_email: email.to_owned(),
            session_ref: session.to_owned(),
        };
        let facts = facts(self.fixture.page, email, session);
        Rung2Send {
            server: self.server(),
            authority: &authority,
            front: &front,
            sender: &self.sender(),
            input: &input,
            facts: &facts,
            now: now(),
        }
        .run(&self.adapter, dispatch)
    }

    /// The owner's press on `send_ref`, its dispatch recorded in
    /// `dispatched` and answered sent.
    fn release(
        &self,
        send_ref: &str,
        dispatched: &RefCell<Vec<Rung2FirstSend>>,
    ) -> Result<BookingRung2ReleaseOnceResponse, ApiError> {
        release_kept_first_send(
            &self.server().vault,
            &crate::test_credentials::embedded_owner(&self.server().vault),
            &self.adapter,
            send_ref,
            |_, kept| {
                dispatched.borrow_mut().push(kept.clone());
                Ok(Rung2Dispatched::Sent)
            },
        )
    }

    /// Whether the owner's one-send approval of `kept`'s exact request is
    /// already minted: minting it again is refused as spent.
    fn press_minted(&self, kept: &Rung2FirstSend) -> bool {
        let request = kept.dispatch_request().expect("request");
        match self.adapter.approve_send_once(
            &self.server().vault,
            &crate::test_credentials::embedded_owner(&self.server().vault),
            &request,
        ) {
            Ok(_) => false,
            Err(error) => {
                assert_eq!(
                    error.kind(),
                    oneiron::ErrorKind::ConsentApproveOnceSpent,
                    "{error}"
                );
                true
            }
        }
    }

    fn kept(&self, session: &str) -> Option<Rung2FirstSend> {
        self.server()
            .vault
            .booking_rung2_first_send(&self.adapter, self.fixture.page, session)
            .expect("kept send read")
    }

    /// The rung-2 notices the vault holds, each addressed to an owner and
    /// naming this page.
    fn owner_notices(&self) -> usize {
        let vault = &self.server().vault;
        let ids = vault
            .entities_by_type_page(oneiron::registry::ENTITY_TYPE_NOTIFICATION, None, 256)
            .expect("notifications");
        let mut notices = 0;
        for id in ids {
            let raw = vault.get(&id).expect("read").expect("live notification");
            let body = oneiron::inbox::decode_notification_body(&raw).expect("decode");
            if body.source.producer != BOOKING_RUNG2_NOTICE_PRODUCER {
                continue;
            }
            assert!(body.recipient.is_some(), "a notice is an owner's own");
            assert_eq!(body.subject_refs, vec![self.fixture.page.to_hex()]);
            assert!(
                body.source
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("named work address")),
                "the notice says why"
            );
            notices += 1;
        }
        notices
    }
}

fn now() -> u64 {
    now_secs().expect("clock")
}

fn front(agent: EntityId) -> ConstraintFrontConfig {
    ConstraintFrontConfig {
        speaker: "Fixture scheduling".to_owned(),
        slots_line: SLOTS_LINE.to_owned(),
        no_fit_line: NO_FIT_LINE.to_owned(),
        off_topic_line: "I can help with scheduling only.".to_owned(),
        max_turns: 4,
        max_model_calls: 4,
        agent_ref: Some(agent),
    }
}

/// Tuesday or Thursday mornings: the canonical constraint a turn parsed.
fn continuation(session: &str) -> ConstraintContinuation {
    ConstraintContinuation {
        event_type: EventTypeKey("intro".to_owned()),
        visitor_tz: "UTC".to_owned(),
        constraint: ConstraintObject {
            schema_version: CONSTRAINT_SCHEMA_VERSION,
            weekdays: vec![ConstraintWeekday::Tuesday, ConstraintWeekday::Thursday],
            local_time_windows: vec![LocalMinuteWindow {
                start_minute: 540,
                end_minute: 720,
            }],
            utc_window: None,
            allow_flex_pool: false,
        },
        session_ref: session.to_owned(),
    }
}

/// The facts the public route builds for a press from the loopback peer.
fn facts(page: EntityId, email: &str, session: &str) -> BookingRequestFacts {
    let transport = public_http_transport_context(crate::auth::ClientAddress(Some(IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    ))))
    .expect("transport");
    rung2_send_facts(
        page,
        Some(EventTypeKey("intro".to_owned())),
        &BookingAdmissionContext::from(&transport),
        email,
        session,
        now(),
    )
}

fn install(fixture: &Fixture, rule: BookingAntiAbuseRule) {
    let scope = BookingRuleScope {
        page_ref: fixture.page,
        event_type: None,
    };
    apply_rule_amendment(
        &fixture.server.vault,
        &crate::test_credentials::embedded_owner(&fixture.server.vault),
        0,
        BookingAntiAbuseRuleRow {
            row_id: booking_rule_row_id(&scope, &rule),
            scope,
            rule,
            version: 1,
            amended_at: 0,
            amended_by: fixture.owner_actor(),
            owner_stamp_ref: None,
        },
        None,
    )
    .expect("rung-2 send rate row");
}

/// A visitor's press keeps the page agent's first send for the session:
/// the template over the solver's offers for the kept constraint, to the
/// visitor's address, from the agent's named mailbox. It is dispatched once
/// and answered held, and the continuation it used is gone.
#[test]
fn a_press_keeps_the_agents_first_send_and_holds_for_the_owners_press() {
    let page = Rung2Page::new(true);
    let session = "rung2-hold";
    page.turn_kept(session);
    let dispatched = RefCell::new(Vec::new());
    let response = page.press(session, VISITOR, &dispatched).expect("press");
    let send_ref = rung2_send_ref(&page.fixture.page, session);
    let (answered, message_id, line) = match response {
        Rung2SendResponse::Held {
            send_ref,
            message_id,
            line,
        } => (send_ref, message_id, line),
        other => panic!("a kept send the owner has not pressed is held: {other:?}"),
    };
    assert_eq!(answered, send_ref);
    assert!(
        line.starts_with("DRAFT:"),
        "held-window copy is DRAFT: {line}"
    );
    let kept = page.kept(session).expect("the send is kept");
    assert_eq!(kept.message_id, message_id);
    assert_eq!(kept.agent_ref, page.agent);
    assert_eq!(kept.identity_ref, page.sender().identity_ref);
    assert_eq!(kept.message.to, VISITOR);
    assert_eq!(kept.continuation, continuation(session));
    let text = kept.message.text.clone().expect("text body");
    assert!(
        text.starts_with(SLOTS_LINE),
        "the owner's slots line: {text}"
    );
    let offers = text.lines().filter(|line| line.starts_with("- ")).count();
    assert!(
        (1..=3).contains(&offers),
        "one to three solver offers: {text}"
    );
    assert!(
        text.lines()
            .filter(|line| line.starts_with("- "))
            .all(|line| line.ends_with(" UTC)")),
        "each offer is a zoned time: {text}"
    );
    assert!(
        !text.contains("https://"),
        "no public page URL is configured, so no slot link: {text}"
    );
    assert_eq!(dispatched.borrow().len(), 1, "dispatched once");
    assert_eq!(dispatched.borrow()[0], kept);
    assert!(
        rung2_continuations()
            .find(&session_key(page.fixture.page, session), now())
            .is_none(),
        "the continuation is used once"
    );
}

/// With `[booking] public_page_url`, each offer carries its slot link to
/// the page (RUNG2-SLOT-LINK-URL = A).
#[test]
fn a_configured_public_page_url_links_each_offer() {
    let mut fixture = Fixture::new();
    Arc::get_mut(&mut fixture.server)
        .expect("the fixture alone holds its server")
        .config
        .booking = Some(BookingConfig {
        public_page_url: "https://book.example.com/b".to_owned(),
    });
    let page = Rung2Page::on(fixture, true);
    let session = "rung2-links";
    page.turn_kept(session);
    let dispatched = RefCell::new(Vec::new());
    page.press(session, VISITOR, &dispatched).expect("press");
    let text = page
        .kept(session)
        .and_then(|kept| kept.message.text)
        .expect("kept text");
    let page_url = format!(
        "https://book.example.com/b/{}?event_type=intro&start_utc=",
        page.fixture.token
    );
    let links = text
        .lines()
        .filter(|line| line.trim_start().starts_with(&page_url))
        .count();
    let offers = text.lines().filter(|line| line.starts_with("- ")).count();
    assert!(offers > 0, "the solver offered times: {text}");
    assert_eq!(links, offers, "one slot link per offer: {text}");
}

/// One address per page session (RUNG2-ONE-ADDRESS = A): a second address
/// is refused as a correction on the address, and the same address again is
/// answered with the send first kept, its words unchanged and not
/// dispatched again.
#[test]
fn a_session_continues_by_email_to_one_address() {
    let page = Rung2Page::new(true);
    let session = "rung2-one-address";
    page.turn_kept(session);
    let dispatched = RefCell::new(Vec::new());
    page.press(session, VISITOR, &dispatched)
        .expect("first press");
    let first = page.kept(session).expect("kept");

    page.turn_kept(session);
    let refused = page
        .press(session, "someone.else@example.org", &dispatched)
        .expect_err("a second address is refused");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    let again = page
        .press(session, VISITOR, &dispatched)
        .expect("the same address again");
    let (send_ref, message_id) = match again {
        Rung2SendResponse::AlreadyKept {
            send_ref,
            message_id,
        } => (send_ref, message_id),
        other => panic!("a retried press finds its send kept: {other:?}"),
    };
    assert_eq!(send_ref, first.send_ref);
    assert_eq!(message_id, first.message_id);
    assert_eq!(page.kept(session), Some(first), "the first words stay");
    assert_eq!(dispatched.borrow().len(), 1, "never dispatched again");
}

/// The owner's `Rung2SendRate` row bounds presses per source address per
/// minute: past it a press is refused before anything is kept, and its
/// session's continuation stays for a later press.
#[test]
fn the_owners_per_ip_minute_cap_refuses_a_press_past_it() {
    // The booking clock stands still, so both presses meet one minute.
    let mut fixture = Fixture::new();
    Arc::get_mut(&mut fixture.server)
        .expect("the fixture alone holds its server")
        .booking_test_now_secs = Some(now());
    let page = Rung2Page::on(fixture, true);
    install(
        &page.fixture,
        BookingAntiAbuseRule::Rung2SendRate {
            per_minute_per_ip: NonZeroU32::new(1).expect("one"),
            per_day_per_page: NonZeroU32::new(50).expect("fifty"),
        },
    );
    let dispatched = RefCell::new(Vec::new());
    page.turn_kept("rung2-cap-1");
    page.press("rung2-cap-1", VISITOR, &dispatched)
        .expect("the first press of the minute");
    page.turn_kept("rung2-cap-2");
    let refused = page
        .press("rung2-cap-2", "second@example.org", &dispatched)
        .expect_err("the second press from the same address this minute");
    assert!(
        refused.message().contains("rate limited"),
        "{}",
        refused.message()
    );
    assert!(page.kept("rung2-cap-2").is_none(), "nothing kept");
    assert!(
        rung2_continuations()
            .find(&session_key(page.fixture.page, "rung2-cap-2"), now())
            .is_some(),
        "the continuation stays"
    );
    assert_eq!(dispatched.borrow().len(), 1);
}

/// A press whose session ran no no-fit turn has no continuation to send on.
#[test]
fn a_press_with_no_turn_answers_no_continuation() {
    let page = Rung2Page::new(true);
    let dispatched = RefCell::new(Vec::new());
    let response = page
        .press("rung2-no-turn", VISITOR, &dispatched)
        .expect("press");
    assert!(
        matches!(response, Rung2SendResponse::NoContinuation),
        "{response:?}"
    );
    assert!(page.kept("rung2-no-turn").is_none());
    assert!(dispatched.borrow().is_empty());
}

/// On a page that offers rung 2, a no-fit turn asks for the email, and the
/// host keeps its continuation for an anonymous visitor only: the public
/// send serves no other caller.
#[test]
fn a_no_fit_turn_keeps_the_continuation_for_an_anonymous_visitor() {
    let page = Rung2Page::new(true);
    let authority = page.authority();
    let front = front(page.agent);
    for (session, anonymous) in [("rung2-turn-visitor", true), ("rung2-turn-caller", false)] {
        let answer = rung2_turn_answer(
            page.server(),
            &authority,
            &front,
            continuation(session),
            anonymous,
            now(),
            Some(DOMAIN),
        )
        .expect("turn answer");
        assert!(
            matches!(answer, ConstraintTurnResponse::ContinueByEmail { .. }),
            "{answer:?}"
        );
        assert_eq!(
            rung2_continuations()
                .find(&session_key(page.fixture.page, session), now())
                .is_some(),
            anonymous
        );
    }
}

/// A page whose agent holds no named address offers no rung 2
/// (RUNG2-NO-SENDER = A): the no-fit turn answers the owner's no-fit line
/// with no control and keeps nothing, the public send answers the same and
/// asks for no email, and the vault's owner hears why once.
#[tokio::test]
async fn a_page_with_no_named_address_answers_its_no_fit_line_and_asks_no_email() {
    let page = Rung2Page::new(false);
    let session = "rung2-no-sender";
    let answer = rung2_turn_answer(
        page.server(),
        &page.authority(),
        &front(page.agent),
        continuation(session),
        true,
        now(),
        Some(DOMAIN),
    )
    .expect("turn answer");
    let card = match answer {
        ConstraintTurnResponse::Deflect { card } => card,
        other => panic!("no email is asked: {other:?}"),
    };
    let card = serde_json::to_string(&card).expect("card");
    assert!(card.contains(NO_FIT_LINE), "{card}");
    assert!(!card.contains("booking.select_slot"), "no control: {card}");
    assert!(
        rung2_continuations()
            .find(&session_key(page.fixture.page, session), now())
            .is_none()
    );

    // The host names no [native_mail] server here, so the public route
    // finds no named address either.
    for _ in 0..2 {
        let response = page
            .fixture
            .route(
                "POST",
                &format!("/public/booking/{}/rung2-send", page.fixture.token),
                json!({ "visitor_email": VISITOR, "session_ref": session }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_inline(&response);
        let value: Value = serde_json::from_slice(&bytes(response).await).expect("JSON");
        assert_eq!(value["outcome"], "not_offered", "{value}");
        assert!(value["card"].to_string().contains(NO_FIT_LINE), "{value}");
    }
    assert!(page.kept(session).is_none());
    assert_eq!(page.owner_notices(), 1, "one notice per page, deduped");
}

/// The visitor posts an address and a session, never a continuation.
#[tokio::test]
async fn the_public_send_takes_no_posted_continuation() {
    let page = Rung2Page::new(true);
    let response = page
        .fixture
        .route(
            "POST",
            &format!("/public/booking/{}/rung2-send", page.fixture.token),
            json!({
                "visitor_email": VISITOR,
                "session_ref": "rung2-posted",
                "continuation": continuation("rung2-posted"),
            }),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_inline(&response);
}

/// The `[booking]` prefix must build the page's slot links.
#[test]
fn the_public_page_url_prefix_is_https_on_a_dotted_host() {
    let config = |url: &str| BookingConfig {
        public_page_url: url.to_owned(),
    };
    for valid in [
        "https://book.example.com",
        "https://book.example.com/b/pages",
    ] {
        assert!(config(valid).validate().is_ok(), "{valid}");
    }
    for invalid in [
        "http://book.example.com",
        "https://localhost/b",
        "https://book.example.com/",
        "https://book.example.com/b?x=1",
        "https://book.example.com//b",
    ] {
        assert!(config(invalid).validate().is_err(), "{invalid}");
    }
}

/// The owner's press names a kept send by its ref and approves exactly
/// those words once, with the owner's proof, then hands them to the send:
/// the answer names the send and its Message-ID.
#[test]
fn the_owners_press_approves_the_kept_words_once_and_sends_them() {
    let page = Rung2Page::new(true);
    let session = "rung2-release";
    page.turn_kept(session);
    let held = RefCell::new(Vec::new());
    page.press(session, VISITOR, &held)
        .expect("the visitor's press");
    let kept = page.kept(session).expect("kept");

    let sent = RefCell::new(Vec::new());
    let send_ref = rung2_send_ref(&page.fixture.page, session);
    let released = page.release(&send_ref, &sent).expect("the owner's press");
    assert_eq!(
        released,
        BookingRung2ReleaseOnceResponse {
            send_ref: send_ref.clone(),
            message_id: kept.message_id.clone(),
            outcome: BookingRung2ReleaseOutcome::Sent,
        }
    );
    assert_eq!(*sent.borrow(), [kept.clone()], "the kept words go");
    assert!(
        page.press_minted(&kept),
        "the press minted the one-send approval of the kept request"
    );
}

/// A second press approves nothing more and answers the same send: the
/// first approval stands, and the send is the same kept words.
#[test]
fn a_second_press_approves_nothing_more_and_answers_the_same_send() {
    let page = Rung2Page::new(true);
    let session = "rung2-release-twice";
    page.turn_kept(session);
    let held = RefCell::new(Vec::new());
    page.press(session, VISITOR, &held)
        .expect("the visitor's press");
    let kept = page.kept(session).expect("kept");
    let send_ref = rung2_send_ref(&page.fixture.page, session);

    let sent = RefCell::new(Vec::new());
    let first = page.release(&send_ref, &sent).expect("first press");
    let second = page
        .release(&send_ref, &sent)
        .expect("a second press is no refusal");
    assert_eq!(first, second);
    assert_eq!(*sent.borrow(), [kept.clone(), kept.clone()]);
    assert!(page.press_minted(&kept), "one approval, minted once");
}

/// A press names a kept send by the ref its hold carries: a ref the host
/// could not have written is refused as a bad request, and a well-formed ref
/// that kept nothing (another session, another page) is not found. Nothing
/// is sent.
#[test]
fn a_press_names_a_kept_send_by_its_ref() {
    let page = Rung2Page::new(true);
    let session = "rung2-release-ref";
    page.turn_kept(session);
    let held = RefCell::new(Vec::new());
    page.press(session, VISITOR, &held)
        .expect("the visitor's press");

    let sent = RefCell::new(Vec::new());
    let page_hex = page.fixture.page.to_hex();
    for malformed in [
        String::new(),
        format!("{page_hex}:{session}"),
        format!("booking-rung2:{page_hex}"),
        format!("booking-rung2:not-hex:{session}"),
        format!("booking-rung2:{page_hex}:"),
    ] {
        let refused = page
            .release(&malformed, &sent)
            .expect_err("a malformed ref is refused");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{malformed}");
    }
    for unkept in [
        rung2_send_ref(&page.fixture.page, "another-session"),
        rung2_send_ref(&id(0x82), session),
    ] {
        let refused = page
            .release(&unkept, &sent)
            .expect_err("a ref that kept nothing");
        assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{unkept}");
    }
    assert!(sent.borrow().is_empty(), "nothing is sent");
}

/// The host's mail transport in the held-send test: it delivers every send
/// it is handed and counts them.
#[cfg(oneiron_test_support)]
#[derive(Default)]
struct CountingTransport {
    delivered: usize,
}

#[cfg(oneiron_test_support)]
impl oneiron::outbound::OutboundExecutionSink for CountingTransport {
    fn execute(
        &mut self,
        _request: &oneiron::outbound::OutboundExecutionRequest<'_>,
    ) -> oneiron::outbound::OutboundExecutionOutcome {
        self.delivered += 1;
        oneiron::outbound::OutboundExecutionOutcome::delivered_to_channel("host:rung2")
    }
}

/// The engine's own dispatch of `kept` through `transport`.
#[cfg(oneiron_test_support)]
fn dispatch_through(
    adapter: &NativeMailAdapter<Host>,
    transport: &RefCell<CountingTransport>,
    vault: &Vault,
    kept: &Rung2FirstSend,
) -> Result<Rung2Dispatched, ApiError> {
    let request = kept.dispatch_request().expect("request");
    let result = adapter
        .dispatch_send(vault, request, &mut *transport.borrow_mut())
        .expect("dispatch");
    match result.outcome {
        oneiron::outbound::OutboundDispatchOutcome::Held => Ok(Rung2Dispatched::Held),
        oneiron::outbound::OutboundDispatchOutcome::DeliveredToChannel => Ok(Rung2Dispatched::Sent),
        outcome => panic!("a rung-2 first send is held or sent: {outcome:?}"),
    }
}

/// Under the cold-send law the visitor's send holds for the owner, and the
/// owner's press releases it: the kept words reach the transport once, and a
/// second press sends nothing more.
#[cfg(oneiron_test_support)]
#[test]
fn the_owners_press_releases_a_held_first_send_to_the_visitor_once() {
    let page = Rung2Page::new(true);
    oneiron::test_doors::booking_rung2_thread::hold_cold_mail_for_owner_press(
        &page.server().vault,
        page.agent,
    )
    .expect("the cold-send policy");
    let session = "rung2-release-held";
    page.turn_kept(session);
    let transport = RefCell::new(CountingTransport::default());
    let answered = page
        .press_with(session, VISITOR, |vault, kept| {
            dispatch_through(&page.adapter, &transport, vault, kept)
        })
        .expect("the visitor's press");
    assert!(
        matches!(answered, Rung2SendResponse::Held { .. }),
        "a first send to a stranger holds: {answered:?}"
    );
    assert_eq!(
        transport.borrow().delivered,
        0,
        "a held send reaches no transport"
    );

    let send_ref = rung2_send_ref(&page.fixture.page, session);
    let owner = crate::test_credentials::embedded_owner(&page.server().vault);
    let release = || {
        release_kept_first_send(
            &page.server().vault,
            &owner,
            &page.adapter,
            &send_ref,
            |vault, kept| dispatch_through(&page.adapter, &transport, vault, kept),
        )
        .expect("the owner's press")
    };
    let first = release();
    assert_eq!(first.outcome, BookingRung2ReleaseOutcome::Sent);
    assert_eq!(
        transport.borrow().delivered,
        1,
        "the press sends the kept words"
    );
    let second = release();
    assert_eq!(second, first);
    assert_eq!(
        transport.borrow().delivered,
        1,
        "a second press answers from the recorded send"
    );
}
