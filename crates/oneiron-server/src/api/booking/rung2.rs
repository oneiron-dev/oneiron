//! Rung 2 on the public page: the visitor's send (ARCH-0062:145-151,
//! INBOX-RESIDUE PR-3b-3b).
//!
//! When no slot fits, a turn on a page that offers rung 2 answers
//! `continue_by_email`, and the host keeps that turn's continuation for the
//! session ([`Rung2Continuations`]). The visitor then posts only an address
//! and the session to `POST /public/booking/{page_token}/rung2-send`: the
//! send never trusts a continuation a page posts, since that would choose the
//! offers and the words of the email. The send is the page agent's own
//! native mail from the address the vault's law picked, composed from a
//! template with no model call (the solver picks every time), kept once per
//! session before it is dispatched, and held by the cold-send law for the
//! owner's one-send press.
//!
//! On a page that does not offer rung 2 the turn answers the owner's no-fit
//! line, asks for no email, and the vault's owners hear once why
//! (RUNG2-NO-SENDER = A).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use oneiron::booking::agent_front::{
    ConstraintContinuation, ConstraintFrontConfig, constraint_no_fit, top_ranked_slots,
};
use oneiron::booking::anti_abuse::BookingRequestFacts;
use oneiron::booking::publication::PublicBookingAuthority;
use oneiron::booking::rung2::{Rung2FirstSend, Rung2Offer, Rung2Sender, Rung2Unavailable};
use oneiron::booking::{
    PublicBookingPageToken, RankedSlot, SessionKey, SlotMask, SlotOracle, SolveRequest,
    booking_snippet_links, booking_zoned_time, slot_mask,
};
use oneiron::channel_identity_provider::native_mail::{
    NativeMailAdapter, NativeMailHost, NativeMailPack,
};
use oneiron::channel_identity_provider::stalwart::NativeMailMessage;
use oneiron::lens::GeneratedUiCard;
use oneiron::outbound::OutboundDispatchOutcome;
use oneiron::{EntityId, TimeRange, Vault};
use serde::{Deserialize, Serialize};

use super::admission::{prompt_correction_error, rate_limited_error, rung2_send_facts};
use super::constants::MAX_BOOKER_EMAIL_BYTES;
use super::email_evidence::email_domain_evidence;
use super::front::{ConstraintTurnResponse, PublicSlotOracle};
use super::helpers::{booking_error, engine_read_error, now_secs};
use super::lifecycle::booking_oracle;
use super::public::public_booking_not_found;
use super::rung2_copy::{
    RUNG2_HELD_LINE_DRAFT, RUNG2_ONE_ADDRESS_DRAFT, RUNG2_SENT_LINE_DRAFT, Rung2OfferLine,
    render_rung2_first_send_text, rung2_first_send_subject,
};
use super::subject::session_key;
use super::validate::validate_session_ref;
use super::{BookingAdmissionContext, public_availability};
use crate::api::booking_anti_abuse::{BookingHttpDisposition, enforce_rung2_send};
use crate::error::ApiError;
use crate::server::SyncServer;

/// How far ahead a first send's solve may look: the solver clips it to the
/// event type's own booking window and notice (`bookable_extent`), so the
/// page's own horizon is the real bound.
const RUNG2_SOLVE_HORIZON_SECS: u64 = 366 * 86_400;

/// The bound on the kept continuations and their idle expiry: the front's
/// own session bound. Past it, the oldest continuation goes first.
const RUNG2_CONTINUATIONS: Rung2ContinuationBound = Rung2ContinuationBound {
    max_sessions: 4_096,
    idle_expiry_secs: 30 * 60,
};

struct Rung2ContinuationBound {
    max_sessions: usize,
    idle_expiry_secs: u64,
}

/// What the visitor posts: an address and the session whose turn asked for
/// it. Nothing else; the continuation is the host's.
// RED STUB 6: unknown fields pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Rung2SendInput {
    pub(super) visitor_email: String,
    pub(super) session_ref: String,
}

/// What a rung-2 send answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(super) enum Rung2SendResponse {
    /// Kept, and held for the owner's one-send press.
    Held {
        send_ref: String,
        message_id: String,
        line: String,
    },
    /// Kept, and sent at once: the owner's policy already admits the address.
    Sent {
        send_ref: String,
        message_id: String,
        line: String,
    },
    /// This session's send was kept before, to this same address.
    AlreadyKept {
        send_ref: String,
        message_id: String,
    },
    /// The page cannot continue by email: the owner's no-fit line, no email
    /// asked.
    NotOffered { card: Box<GeneratedUiCard> },
    /// No turn of this session asked for an email, or its continuation
    /// expired: the visitor runs a turn first.
    NoContinuation,
}

/// What a dispatch of a kept first send came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rung2Dispatched {
    Held,
    Sent,
}

/// The managed domain the host sends native mail on: its `[native_mail]`
/// server's. `None` when the host names none, and then no page offers rung 2.
pub(super) fn rung2_native_mail_domain(server: &SyncServer) -> Option<String> {
    let config = server.config.native_mail.as_ref()?;
    config
        .stalwart()
        .ok()
        .map(|stalwart| stalwart.domain().to_owned())
}

/// Whether `page_ref` offers rung 2 now, with the vault's own native-mail
/// faces on `native_mail_domain`.
fn rung2_offer(
    server: &SyncServer,
    page_ref: EntityId,
    now: u64,
    native_mail_domain: Option<&str>,
) -> Result<Rung2Offer, ApiError> {
    server
        .vault
        .booking_rung2_offer_on_native_mail(page_ref, now, native_mail_domain)
        .map_err(engine_read_error)
}

/// The owner's no-fit line for a page that offers no rung 2. When the page's
/// agent holds no named address, the vault's owners hear why, once per page.
fn not_offered_card(
    server: &SyncServer,
    page_ref: EntityId,
    front: &ConstraintFrontConfig,
    session_ref: &str,
    reason: Rung2Unavailable,
    now: u64,
) -> Result<GeneratedUiCard, ApiError> {
    // The visitor's answer does not wait on the owner's notice.
    // RED STUB 7: the owners hear nothing.
    if reason == Rung2Unavailable::NoNamedAddress
        && false
        && let Err(error) = server.vault.notify_booking_rung2_no_sender(page_ref, now)
    {
        tracing::warn!(kind = ?error.kind(), "booking rung-2 no-sender notice was not written");
    }
    constraint_no_fit(session_ref, &front.copy())
        .map(|answer| answer.card)
        .map_err(booking_error)
}

/// What a turn whose solve fit nothing answers. On a page that offers rung
/// 2 it asks for the visitor's email, and for an anonymous visitor, the only
/// caller the public send serves, the host keeps the continuation the send
/// reads. On a page that does not, it answers the owner's no-fit line and
/// asks for no email.
pub(super) fn rung2_turn_answer(
    server: &SyncServer,
    authority: &PublicBookingAuthority,
    front: &ConstraintFrontConfig,
    continuation: ConstraintContinuation,
    anonymous: bool,
    now: u64,
    native_mail_domain: Option<&str>,
) -> Result<ConstraintTurnResponse, ApiError> {
    match rung2_offer(server, authority.page_ref, now, native_mail_domain)? {
        Rung2Offer::Offered(_) => {
            // RED STUB 1: the continuation is kept for every caller.
            if anonymous || true {
                rung2_continuations().keep(
                    session_key(authority.page_ref, &continuation.session_ref),
                    continuation.clone(),
                    now,
                );
            }
            Ok(ConstraintTurnResponse::ContinueByEmail { continuation })
        }
        // RED STUB 2: a page with no rung 2 still asks for the email.
        Rung2Offer::NotOffered(_) => {
            let _ = front;
            Ok(ConstraintTurnResponse::ContinueByEmail { continuation })
        }
    }
}

/// One visitor's rung-2 send, authorized only by the published page.
///
/// Order: the input's shape, the page's front, the offer (a page with none
/// answers its no-fit line), the address evidence the owner's rules ask
/// for, then on the native mail pack: the one-address law against a kept
/// send, the kept continuation, the guard, the compose, a publication
/// recheck, the keep and the dispatch.
pub(super) async fn run_public_rung2_send(
    server: &Arc<SyncServer>,
    authority: PublicBookingAuthority,
    input: Rung2SendInput,
    transport: &BookingAdmissionContext,
) -> Result<Rung2SendResponse, ApiError> {
    validate_rung2_send_input(&input)?;
    let page_ref = authority.page_ref;
    let front = authority
        .publication
        .constraint_front
        .clone()
        .ok_or_else(public_booking_not_found)?;
    let now = now_secs()?;
    let domain = rung2_native_mail_domain(server);
    let sender = match rung2_offer(server, page_ref, now, domain.as_deref())? {
        Rung2Offer::Offered(sender) => sender,
        Rung2Offer::NotOffered(reason) => {
            return Ok(Rung2SendResponse::NotOffered {
                card: Box::new(not_offered_card(
                    server,
                    page_ref,
                    &front,
                    &input.session_ref,
                    reason,
                    now,
                )?),
            });
        }
    };
    // The owner's rules scoped to the event type the session's turn solved.
    let event_type = rung2_continuations()
        .find(&session_key(page_ref, &input.session_ref), now)
        .map(|continuation| continuation.event_type);
    let mut facts = rung2_send_facts(
        page_ref,
        event_type,
        transport,
        &input.visitor_email,
        &input.session_ref,
        now,
    );
    email_domain_evidence(server, &facts, &input.visitor_email)
        .await?
        .apply(&mut facts);
    let server = Arc::clone(server);
    // The send's JMAP submission blocks on the mail server.
    tokio::task::spawn_blocking(move || {
        let send = Rung2Send {
            server: &server,
            authority: &authority,
            front: &front,
            sender: &sender,
            input: &input,
            facts: &facts,
            now,
        };
        server
            .builtin_handles
            .with_native_mail_pack(|pack| {
                send.run(pack.adapter(), |vault, kept| {
                    dispatch_on_pack(pack, vault, kept)
                })
            })
            .unwrap_or_else(|| Err(native_mail_unavailable()))
    })
    .await
    .map_err(|_| ApiError::internal_server_error("booking rung-2 send stopped"))?
}

/// The address is bounded as a booker's is, and the session is a front
/// session's.
fn validate_rung2_send_input(input: &Rung2SendInput) -> Result<(), ApiError> {
    if input.visitor_email.trim().is_empty() || input.visitor_email.len() > MAX_BOOKER_EMAIL_BYTES {
        return Err(ApiError::bad_request(
            format!("visitor_email must be non-blank and at most {MAX_BOOKER_EMAIL_BYTES} bytes"),
            Some("visitor_email"),
        ));
    }
    validate_session_ref(&input.session_ref)
}

/// The host names a `[native_mail]` server, but no pack is connected to it
/// now.
fn native_mail_unavailable() -> ApiError {
    ApiError::internal_server_error("booking rung-2 mail unavailable")
}

/// One send on the native mail pack, with everything it was admitted on.
pub(super) struct Rung2Send<'a> {
    pub(super) server: &'a SyncServer,
    pub(super) authority: &'a PublicBookingAuthority,
    pub(super) front: &'a ConstraintFrontConfig,
    pub(super) sender: &'a Rung2Sender,
    pub(super) input: &'a Rung2SendInput,
    pub(super) facts: &'a BookingRequestFacts,
    pub(super) now: u64,
}

impl Rung2Send<'_> {
    /// Keeps and dispatches the session's first send. `adapter` names the
    /// Message-ID it goes out under; `dispatch` sends a kept send.
    pub(super) fn run<H: NativeMailHost>(
        &self,
        adapter: &NativeMailAdapter<H>,
        dispatch: impl FnOnce(&Vault, &Rung2FirstSend) -> Result<Rung2Dispatched, ApiError>,
    ) -> Result<Rung2SendResponse, ApiError> {
        let vault = &self.server.vault;
        let page_ref = self.authority.page_ref;
        let session_ref = self.input.session_ref.as_str();
        // One address per page session (RUNG2-ONE-ADDRESS = A): a retried
        // press finds its send kept, and another address is refused.
        if let Some(kept) = vault
            .booking_rung2_first_send(adapter, page_ref, session_ref)
            .map_err(engine_read_error)?
        {
            return self.kept_answer(&kept);
        }
        let key = session_key(page_ref, session_ref);
        let Some(continuation) = rung2_continuations().find(&key, self.now) else {
            return Ok(Rung2SendResponse::NoContinuation);
        };
        match enforce_rung2_send(self.server, self.facts)? {
            BookingHttpDisposition::Continue => {}
            BookingHttpDisposition::PromptCorrection { body } => {
                return Err(prompt_correction_error(&body));
            }
            BookingHttpDisposition::RetryAfter { seconds, .. } => {
                return Err(rate_limited_error(seconds));
            }
            BookingHttpDisposition::SilentOk | BookingHttpDisposition::QuarantineAndAccept => {
                return Err(ApiError::internal_server_error(
                    "booking rung-2 send admission invariant",
                ));
            }
        }
        let message = self.compose(&continuation)?;
        // Never keep a send for a publication the owner revoked or edited
        // meanwhile.
        public_availability::recheck(self.server, Some(self.authority))?;
        let kept = vault
            .keep_booking_rung2_first_send(adapter, self.sender, continuation, message, self.now)
            .map_err(|error| {
                tracing::warn!(kind = ?error.kind(), "booking rung-2 first send was not kept");
                ApiError::internal_server_error("booking rung-2 first send not kept")
            })?
            .ok_or_else(public_booking_not_found)?;
        // RED STUB 4: the continuation is not used up.
        let _ = &key;
        // A concurrent press of this session may have kept another address
        // first: the kept words are the ones that go.
        if !kept.is_addressed_to(&self.input.visitor_email) {
            return Err(one_address_refusal());
        }
        Ok(match dispatch(vault, &kept)? {
            Rung2Dispatched::Held => Rung2SendResponse::Held {
                send_ref: kept.send_ref,
                message_id: kept.message_id,
                line: RUNG2_HELD_LINE_DRAFT.to_owned(),
            },
            Rung2Dispatched::Sent => Rung2SendResponse::Sent {
                send_ref: kept.send_ref,
                message_id: kept.message_id,
                line: RUNG2_SENT_LINE_DRAFT.to_owned(),
            },
        })
    }

    /// The answer to a press whose session already kept its send.
    fn kept_answer(&self, kept: &Rung2FirstSend) -> Result<Rung2SendResponse, ApiError> {
        // RED STUB 3: any address finds the kept send.
        Ok(Rung2SendResponse::AlreadyKept {
            send_ref: kept.send_ref.clone(),
            message_id: kept.message_id.clone(),
        })
    }

    /// The first send's message: the template over the solver's offers for
    /// the kept constraint, from now over the event type's own booking
    /// window, to the visitor's address.
    fn compose(
        &self,
        continuation: &ConstraintContinuation,
    ) -> Result<NativeMailMessage, ApiError> {
        let page_ref = self.authority.page_ref;
        let request = SolveRequest {
            event_type: continuation.event_type.clone(),
            window: TimeRange {
                start: self.now,
                end: self.now.saturating_add(RUNG2_SOLVE_HORIZON_SECS),
            },
            constraint: Some(continuation.constraint.clone()),
            visitor_tz: continuation.visitor_tz.clone(),
        };
        let oracle = PublicSlotOracle(booking_oracle(self.server, page_ref, None, self.now)?);
        let mask = slot_mask(&request, oracle.solve(&request).map_err(booking_error)?);
        let offered = top_ranked_slots(&mask.slots);
        let token = PublicBookingPageToken::for_page(page_ref);
        let page_url = self
            .server
            .config
            .booking
            .as_ref()
            // RED STUB 5: no slot links.
            .and_then(|_| None::<String>);
        let offers = offer_lines(&mask, &offered, &continuation.visitor_tz, &token, page_url)?;
        let text = render_rung2_first_send_text(&self.front.copy(), &offers);
        NativeMailMessage::new(
            &self.input.visitor_email,
            rung2_first_send_subject(&self.authority.publication.owner_display),
            Some(text),
            None,
        )
        .map_err(|_| {
            ApiError::bad_request(
                "visitor_email is not a deliverable address",
                Some("visitor_email"),
            )
        })
    }
}

/// Each offered slot's line: its slot link when the host names its public
/// page URL (RUNG2-SLOT-LINK-URL = A), else its time in the visitor's zone.
fn offer_lines(
    mask: &SlotMask,
    offered: &[&RankedSlot],
    visitor_tz: &str,
    token: &PublicBookingPageToken,
    page_url: Option<String>,
) -> Result<Vec<Rung2OfferLine>, ApiError> {
    if offered.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(page_url) = page_url {
        let starts: Vec<u64> = offered.iter().map(|slot| slot.start_utc).collect();
        return Ok(
            booking_snippet_links(mask, &starts, visitor_tz, token, &page_url)
                .map_err(booking_error)?
                .into_iter()
                .map(|link| Rung2OfferLine {
                    label: link.label,
                    href: Some(link.href),
                })
                .collect(),
        );
    }
    offered
        .iter()
        .map(|slot| {
            let zoned = booking_zoned_time(slot.start_utc, visitor_tz);
            let utc = booking_zoned_time(slot.start_utc, "UTC");
            match (zoned, utc) {
                (Ok(zoned), Ok(utc)) => Ok(Rung2OfferLine {
                    label: format!("{} {} ({} UTC)", zoned.local, zoned.zone, utc.local),
                    href: None,
                }),
                _ => Err(ApiError::internal_server_error(
                    "booking rung-2 offer time did not render",
                )),
            }
        })
        .collect()
}

/// Sends a kept first send through the native mail pack: the cold-send law
/// holds a first send to a stranger for the owner's one-send press.
fn dispatch_on_pack(
    pack: &NativeMailPack,
    vault: &Vault,
    kept: &Rung2FirstSend,
) -> Result<Rung2Dispatched, ApiError> {
    let request = kept
        .dispatch_request()
        .map_err(|error| send_unavailable("request", &error))?;
    let prepared = pack
        .prepare_send(request, kept.message.clone())
        .map_err(|error| send_unavailable("prepare", &error))?;
    let result = pack
        .dispatch_send(vault, prepared)
        .map_err(|error| send_unavailable("dispatch", &error))?;
    match result.outcome {
        OutboundDispatchOutcome::Held => Ok(Rung2Dispatched::Held),
        OutboundDispatchOutcome::DeliveredToChannel => Ok(Rung2Dispatched::Sent),
        outcome => {
            tracing::warn!(
                ?outcome,
                "booking rung-2 first send was neither held nor sent"
            );
            Err(ApiError::internal_server_error(
                "booking rung-2 first send unavailable",
            ))
        }
    }
}

/// A first send that did not reach the mail server at `stage`.
fn send_unavailable(stage: &'static str, error: &dyn std::fmt::Display) -> ApiError {
    tracing::warn!(stage, %error, "booking rung-2 first send did not go out");
    ApiError::internal_server_error("booking rung-2 first send unavailable")
}

/// The refusal a second address in one page session gets, as a correction
/// prompt on the address (RUNG2-ONE-ADDRESS = A).
fn one_address_refusal() -> ApiError {
    ApiError::bad_request(RUNG2_ONE_ADDRESS_DRAFT, Some("visitor_email"))
}

/// The continuation each page session's last rung-2 turn kept, host-owned:
/// never read from a request.
#[derive(Default)]
pub(super) struct Rung2Continuations {
    by_session: HashMap<SessionKey, KeptContinuation>,
}

struct KeptContinuation {
    kept_at: u64,
    continuation: ConstraintContinuation,
}

impl Rung2Continuations {
    /// Keeps the turn's continuation for its session, in place of any the
    /// session kept before.
    pub(super) fn keep(&mut self, key: SessionKey, continuation: ConstraintContinuation, now: u64) {
        self.expire(now);
        if !self.by_session.contains_key(&key)
            && self.by_session.len() >= RUNG2_CONTINUATIONS.max_sessions
        {
            let oldest = self
                .by_session
                .iter()
                .min_by_key(|(_, kept)| kept.kept_at)
                .map(|(oldest, _)| oldest.clone());
            if let Some(oldest) = oldest {
                self.by_session.remove(&oldest);
            }
        }
        self.by_session.insert(
            key,
            KeptContinuation {
                kept_at: now,
                continuation,
            },
        );
    }

    /// The session's live continuation.
    pub(super) fn find(&mut self, key: &SessionKey, now: u64) -> Option<ConstraintContinuation> {
        self.expire(now);
        self.by_session
            .get(key)
            .map(|kept| kept.continuation.clone())
    }

    /// Drops the session's continuation once its send is kept: it is used
    /// once.
    pub(super) fn take(&mut self, key: &SessionKey) {
        self.by_session.remove(key);
    }

    fn expire(&mut self, now: u64) {
        self.by_session.retain(|_, kept| {
            now.saturating_sub(kept.kept_at) < RUNG2_CONTINUATIONS.idle_expiry_secs
        });
    }
}

pub(super) fn rung2_continuations() -> MutexGuard<'static, Rung2Continuations> {
    static CONTINUATIONS: OnceLock<Mutex<Rung2Continuations>> = OnceLock::new();
    CONTINUATIONS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}
