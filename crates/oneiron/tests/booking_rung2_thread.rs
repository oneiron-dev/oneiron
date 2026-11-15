//! INBOX-RESIDUE PR-3b-2: rung 2's first send and its thread (ARCH-0062:145-147,
//! ARCH-0063:48; Engine RULINGs RUNG2-NO-SENDER = A, RUNG2-HELD-WINDOW = B,
//! 15 Nov).
//!
//! When no slot fits, the page's agent emails the visitor from the identity
//! rung 2 picked (PR-3b-1). The vault keeps that first send before it goes
//! out: the exact message, which the owner's one-send press releases (a first
//! send to a stranger holds under the cold-send law), and the continuation,
//! whose canonical constraint a reply on its thread re-solves on. The kept
//! copy is keyed by the Message-ID the send goes out under; a delivered
//! native send files its own sent passport under that Message-ID, so the
//! visitor's reply lands on the thread the send began, finds the kept
//! continuation, and wears the first send's mask.
//!
//! Red on main: `Rung2FirstSend`, `Vault::keep_booking_rung2_first_send`,
//! `Vault::booking_rung2_thread_first_send`,
//! `NativeMailAdapter::send_message_id` and the test door
//! `test_doors::booking_rung2_thread` do not exist there, so this file does
//! not build. Red base: the head with only the sent-passport call taken out
//! of `NativeMailAdapter::dispatch_send`, where the three thread tests fail.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test booking_rung2_thread`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use oneiron::booking::EventTypeKey;
use oneiron::booking::agent_front::ConstraintContinuation;
use oneiron::booking::constraint::{
    CONSTRAINT_SCHEMA_VERSION, ConstraintObject, ConstraintWeekday, LocalMinuteWindow,
};
use oneiron::booking::rung2::{
    BOOKING_RUNG2_FIRST_SEND_SCHEMA_VERSION, Rung2FirstSend, Rung2Sender, rung2_send_ref,
};
use oneiron::channel_identity::{ChannelIdentityFulfillment, ChannelIdentityStep};
use oneiron::channel_identity_lifecycle::{ChannelIdentityLifecycleActor, ProvisionIntent};
use oneiron::channel_identity_provider::native_mail::{
    NativeMailAdapter, NativeMailHost, NativeMailRunMode,
};
use oneiron::channel_identity_provider::stalwart::NativeMailMessage;
use oneiron::channel_identity_provider::{ChannelIdentityProviderAdapter, EmailProviderInbound};
use oneiron::channel_identity_selection::ChannelIdentityFace;
use oneiron::consent::AuthenticatedOwner;
use oneiron::outbound::{
    OutboundDispatchOutcome, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::booking_rung2_thread::hold_cold_mail_for_owner_press;
use oneiron::{
    CanonicalMessageId, EntityId, StickyMaskDecision, ThreadMask, ThreadPassportInput, TimeRange,
    Vault, VaultConfig, canonical_message_id,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const AT: u64 = 1_800_000_000;
const DOMAIN: &str = "example.com";
const SESSION: &str = "visitor-session-1";
const VISITOR: &str = "visitor@example.org";
const SUBJECT: &str = "Times for an intro call";
const WORDS: &str = "None of this week's times fit what you asked for. Reply with a day that \
                     suits you and I will look again.";

/// The host fixture behind the adapter: it names each mailbox it provisions
/// and verifies no webhook.
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

/// The host's mail transport: it delivers every send it is handed and counts
/// them.
#[derive(Default)]
struct HostSink {
    delivered: usize,
}

impl OutboundExecutionSink for HostSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.delivered += 1;
        OutboundExecutionOutcome::delivered_to_channel("host:rung2")
    }
}

/// A vault with its authenticated owner, the page's agent with two native
/// mailboxes, the policy that holds a first send to a stranger for the
/// owner's press, and the rung-2 sender. The vault closes before its
/// directory.
struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    adapter: NativeMailAdapter<Host>,
    agent: EntityId,
    /// The identity rung 2 picked.
    identity: EntityId,
    /// Another mailbox of the same agent.
    other_identity: EntityId,
    sender: Rung2Sender,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
        let owner_id = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .map_err(at("authenticate the owner"))?;
        let agent = EntityId::now();
        vault
            .put_entity(
                &agent,
                ENTITY_TYPE_PERSON,
                TimeRange { start: AT, end: AT },
                AT,
                b"scheduling agent",
            )
            .map_err(at("seat the page's agent"))?;
        let adapter = NativeMailAdapter::new(DOMAIN, NativeMailRunMode::SelfRun, Host)
            .map_err(at("the adapter"))?;
        let identity = mailbox(&vault, &adapter, agent)?;
        let other_identity = mailbox(&vault, &adapter, agent)?;
        hold_cold_mail_for_owner_press(&vault, agent).map_err(at("the mail policy"))?;
        let sender = Rung2Sender {
            page_ref: EntityId::now(),
            agent_ref: agent,
            identity_ref: identity,
            facet_ref: None,
            face: ChannelIdentityFace::AgentNamedAddress,
        };
        Ok(Self {
            vault,
            owner,
            adapter,
            agent,
            identity,
            other_identity,
            sender,
            _dir: dir,
        })
    }

    /// Keeps the session's first send of `words`.
    fn keep(&self, session_ref: &str, words: &str) -> TestResult<Rung2FirstSend> {
        let kept = self
            .vault
            .keep_booking_rung2_first_send(
                &self.adapter,
                &self.sender,
                continuation(session_ref),
                message(words)?,
                AT + 60,
            )
            .map_err(at("keep the first send"))?
            .ok_or("the agent was not erased, so the send is kept")?;
        Ok(kept)
    }

    /// Dispatches the kept send's request through the adapter.
    fn dispatch(
        &self,
        kept: &Rung2FirstSend,
        sink: &mut HostSink,
    ) -> TestResult<OutboundDispatchOutcome> {
        let request = kept.dispatch_request().map_err(at("the request"))?;
        let result = self
            .adapter
            .dispatch_send(&self.vault, request, sink)
            .map_err(at("dispatch the first send"))?;
        Ok(result.outcome)
    }

    /// Holds the session's first send, then the owner presses once and the
    /// rebuilt request goes out: the first send delivered.
    fn deliver(&self, sink: &mut HostSink) -> TestResult<Rung2FirstSend> {
        let kept = self.keep(SESSION, WORDS)?;
        assert_eq!(self.dispatch(&kept, sink)?, OutboundDispatchOutcome::Held);
        let request = kept.dispatch_request().map_err(at("the request"))?;
        self.adapter
            .approve_send_once(&self.vault, &self.owner, &request)
            .map_err(at("the owner's press"))?;
        let rebuilt = self
            .vault
            .booking_rung2_first_send(&self.adapter, self.sender.page_ref, SESSION)
            .map_err(at("read the kept send"))?
            .ok_or("the kept send reads back")?;
        assert_eq!(
            self.dispatch(&rebuilt, sink)?,
            OutboundDispatchOutcome::DeliveredToChannel
        );
        Ok(kept)
    }

    /// The visitor's reply to the first send: its passport on the agent's
    /// mailbox, the thread it lands on.
    fn reply(&self, first: &CanonicalMessageId) -> TestResult<String> {
        let reply_id = canonical_message_id("reply-1@example.org")?;
        let landed = self
            .vault
            .record_thread_passport(
                ThreadPassportInput::new(self.identity, self.agent, reply_id, AT + 600)
                    .with_in_reply_to(first.clone()),
            )
            .map_err(at("the visitor's reply lands"))?;
        Ok(landed.canonical_thread_ref)
    }
}

/// A live native mailbox of `agent`, provisioned through the adapter.
fn mailbox(
    vault: &Vault,
    adapter: &NativeMailAdapter<Host>,
    agent: EntityId,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let requested = adapter.requested_identity(id, agent, AT);
    vault
        .create_channel_identity(&id, &requested)
        .map_err(at("birth the mailbox"))?;
    vault
        .step_channel_identity(
            &id,
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            AT + 10,
        )
        .map_err(at("bind the mailbox"))?;
    let provision = adapter
        .provision(
            &ProvisionIntent {
                identity_id: id,
                identity: requested,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            AT + 20,
        )
        .map_err(at("provision the mailbox"))?;
    vault
        .fulfill_channel_identity(
            provision.fulfillment_input(ChannelIdentityLifecycleActor::agent(agent)),
        )
        .map_err(at("fulfill the mailbox"))?;
    Ok(id)
}

/// Tuesday or Thursday mornings, the canonical constraint the visitor's
/// sentence parsed to.
fn constraint() -> ConstraintObject {
    ConstraintObject {
        schema_version: CONSTRAINT_SCHEMA_VERSION,
        weekdays: vec![ConstraintWeekday::Tuesday, ConstraintWeekday::Thursday],
        local_time_windows: vec![LocalMinuteWindow {
            start_minute: 540,
            end_minute: 720,
        }],
        utc_window: None,
        allow_flex_pool: false,
    }
}

fn continuation(session_ref: &str) -> ConstraintContinuation {
    ConstraintContinuation {
        event_type: EventTypeKey("intro".to_owned()),
        visitor_tz: "UTC".to_owned(),
        constraint: constraint(),
        session_ref: session_ref.to_owned(),
    }
}

fn message(words: &str) -> TestResult<NativeMailMessage> {
    Ok(NativeMailMessage::new(
        VISITOR,
        SUBJECT,
        Some(words.to_owned()),
        None,
    )?)
}

/// The vault keeps a session's first send once: a retried keep with other
/// words returns the words first kept, and its request is the same request
/// on every rebuild: the session's send ref as intent ref and idempotency
/// key, the message's own content ref, the picked identity, the visitor.
#[test]
fn a_kept_first_send_is_the_one_a_retried_press_sends() -> TestResult {
    let fx = Fixture::open()?;
    let kept = fx.keep(SESSION, WORDS)?;
    let send_ref = rung2_send_ref(&fx.sender.page_ref, SESSION);
    assert_eq!(kept.schema_version, BOOKING_RUNG2_FIRST_SEND_SCHEMA_VERSION);
    assert_eq!(kept.send_ref, send_ref);
    assert_eq!(kept.identity_ref, fx.identity);
    assert_eq!(kept.agent_ref, fx.agent);
    assert_eq!(
        kept.message_id,
        fx.adapter.send_message_id(&send_ref)?.as_str(),
        "the kept send names the Message-ID its sink drafts under"
    );
    assert_eq!(kept.continuation.constraint, constraint());

    let retried = fx.keep(SESSION, "Other words, from a retried press.")?;
    assert_eq!(retried, kept, "a retried keep returns the send first kept");
    assert_eq!(
        fx.vault
            .booking_rung2_first_send(&fx.adapter, fx.sender.page_ref, SESSION)?,
        Some(kept.clone())
    );
    assert_eq!(
        fx.vault
            .booking_rung2_first_send(&fx.adapter, fx.sender.page_ref, "another-session")?,
        None,
        "a session that kept no send has none"
    );

    let request = kept.dispatch_request()?;
    assert_eq!(request, retried.dispatch_request()?);
    assert_eq!(request.intent_ref, send_ref);
    assert_eq!(
        request.intent.idempotency_key.as_deref(),
        Some(send_ref.as_str())
    );
    assert_eq!(
        request.intent.content_ref,
        Some(message(WORDS)?.content_ref()?)
    );
    assert_eq!(request.intent.channel, "email");
    assert_eq!(request.intent.verb, "send");
    assert_eq!(request.intent.target, VISITOR);
    assert_eq!(request.channel_identity_ref, Some(fx.identity));
    assert_eq!(request.actor.actor_entity_ref, Some(fx.agent));
    Ok(())
}

/// A first send to a stranger holds for the owner's press: nothing reaches
/// the transport, the hold carries no generic digest (the press recomposes
/// mail's own canonical one), and a held send files no passport, so no
/// thread names it yet.
#[test]
fn the_first_send_to_a_stranger_holds_for_the_owners_press() -> TestResult {
    let fx = Fixture::open()?;
    let kept = fx.keep(SESSION, WORDS)?;
    let mut sink = HostSink::default();
    let request = kept.dispatch_request()?;
    let held = fx
        .adapter
        .dispatch_send(&fx.vault, request, &mut sink)
        .map_err(at("dispatch the first send"))?;
    assert_eq!(held.outcome, OutboundDispatchOutcome::Held, "{held:?}");
    assert_eq!(sink.delivered, 0, "a held send reaches no transport");
    assert!(
        held.approval_digest.is_none(),
        "a native-mail cold hold names no generic digest; the press recomposes mail's canonical one: {held:?}"
    );
    let first = canonical_message_id(&kept.message_id)?;
    assert_eq!(fx.vault.thread_passport(&fx.identity, &first)?, None);
    assert_eq!(
        fx.vault
            .booking_rung2_thread_first_send(&first.minted_thread_ref())?,
        None,
        "a held send began no thread"
    );
    Ok(())
}

/// After the owner's press the rebuilt request goes out once, and the
/// delivered send files its passport: the picked identity, the agent's mask,
/// the thread its own Message-ID mints. A replayed dispatch sends nothing
/// more and files nothing new.
#[test]
fn the_delivered_first_send_files_its_threads_passport() -> TestResult {
    let fx = Fixture::open()?;
    let mut sink = HostSink::default();
    let kept = fx.deliver(&mut sink)?;
    assert_eq!(sink.delivered, 1);
    let first = canonical_message_id(&kept.message_id)?;
    let passport = fx
        .vault
        .thread_passport(&fx.identity, &first)?
        .ok_or("the delivered send filed its passport")?;
    assert_eq!(passport.mask, ThreadMask::new(fx.identity, fx.agent));
    assert_eq!(passport.thread_ref, first.minted_thread_ref());

    assert_eq!(
        fx.dispatch(&kept, &mut sink)?,
        OutboundDispatchOutcome::DeliveredToChannel,
        "a replay answers from the recorded send"
    );
    assert_eq!(sink.delivered, 1, "a replay sends nothing more");
    assert_eq!(fx.vault.thread_passports(&passport.thread_ref)?.len(), 1);
    Ok(())
}

/// The visitor's reply to the first send lands on its thread, and the
/// thread names the kept send: its page, its agent and the canonical
/// constraint the reply re-solves on. A thread no rung-2 send began names
/// none.
#[test]
fn a_reply_on_the_thread_finds_the_kept_continuation() -> TestResult {
    let fx = Fixture::open()?;
    let mut sink = HostSink::default();
    let kept = fx.deliver(&mut sink)?;
    let first = canonical_message_id(&kept.message_id)?;
    let thread = fx.reply(&first)?;
    assert_eq!(
        thread,
        first.minted_thread_ref(),
        "the reply joins the send's thread"
    );
    let found = fx
        .vault
        .booking_rung2_thread_first_send(&thread)?
        .ok_or("the reply's thread names the kept send")?;
    assert_eq!(found, kept);
    assert_eq!(found.page_ref, fx.sender.page_ref);
    assert_eq!(found.continuation.constraint, constraint());
    assert_eq!(found.continuation.session_ref, SESSION);

    let unrelated = fx.vault.record_thread_passport(ThreadPassportInput::new(
        fx.identity,
        fx.agent,
        canonical_message_id("unrelated-1@example.org")?,
        AT + 700,
    ))?;
    assert_eq!(
        fx.vault
            .booking_rung2_thread_first_send(&unrelated.canonical_thread_ref)?,
        None,
        "a thread an inbound message began names no rung-2 send"
    );
    Ok(())
}

/// The thread wears the first send's mask: the agent's other mailbox asking
/// to speak on it is a conflict the composer must answer, never a flip.
#[test]
fn the_thread_keeps_the_first_sends_mask() -> TestResult {
    let fx = Fixture::open()?;
    let mut sink = HostSink::default();
    let kept = fx.deliver(&mut sink)?;
    let thread = fx.reply(&canonical_message_id(&kept.message_id)?)?;
    let pinned = ThreadMask::new(fx.identity, fx.agent);
    let other = ThreadMask::new(fx.other_identity, fx.agent);
    assert_eq!(
        fx.vault.sticky_thread_mask(&thread, Some(other))?,
        StickyMaskDecision::Conflict {
            pinned,
            requested: other,
        }
    );
    assert_eq!(
        fx.vault.sticky_thread_mask(&thread, Some(pinned))?,
        StickyMaskDecision::Keep(pinned)
    );
    Ok(())
}
