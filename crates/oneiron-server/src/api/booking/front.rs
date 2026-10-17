//! ONE-1816 / ARCH-0062 §5: a published page's interactive constraint front.
//!
//! A constraint field on availability, not a chat: one visitor sentence in,
//! one card out. The cheap seat parses the sentence once, the page's own
//! oracle proposes the real slots (clamped to the public rung), and a
//! program-generated button carries the only slot action. A
//! `booking.select_slot` click is the public hold (`verbs/hold`) built from
//! [`HoldContext`] plus the button's `[start_utc, end_utc)`; confirmation stays
//! its own step. No fit hands back the canonical constraint for the email
//! continuation, and an off-topic sentence gets the owner's one deflect line.
//!
//! This door sits beside the executor and never parses twice: it admits once,
//! in the listing class, before the parser or the oracle, and the turn's own
//! parse is the only one. The session counters are host-owned
//! ([`FrontSessions`]): never read from a request, never reset by one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use axum::extract::State;
use oneiron::TimeRange;
use oneiron::booking::agent_api::{
    BookingAvailabilityInput, BookingConstraintInput, BookingOperationRequest,
};
use oneiron::booking::agent_front::{
    ConstraintContinuation, ConstraintFrontConfig, ConstraintFrontOutcome, ConstraintTurnRequest,
    constraint_deflect, run_constraint_turn,
};
use oneiron::booking::constraint::ConstraintSessionState;
use oneiron::booking::publication::PublicBookingAuthority;
use oneiron::booking::{
    BookingError, ConstraintObject, EventTypeKey, RungProjection, SessionKey, SlotOracle,
    SolveRequest, SolveResult, bounded_public_slots, slot_mask,
};
use oneiron::lens::GeneratedUiCard;
use serde::{Deserialize, Serialize};

use super::admission::{admission_facts, admission_short_circuit};
use super::free_text::{on_parse_seat, parse_seat_settings};
use super::helpers::{booking_error, now_secs};
use super::lifecycle::{ServerBookingOracle, booking_oracle};
use super::subject::session_key;
use super::validate::validate_operation_shape;
use super::{BookingTransportContext, public_availability, turn};
use crate::api::booking_anti_abuse::enforce_slot_list;
use crate::error::ApiError;
use crate::ladder_poll::block_on;
use crate::server::SyncServer;

/// The bound on the host-owned session counters and their idle expiry. Past
/// the bound, the least recently used session goes first. One CALLS row
/// ("booking front sessions").
const FRONT_SESSIONS: FrontSessionBound = FrontSessionBound {
    max_sessions: 4_096,
    idle_expiry_secs: 30 * 60,
};

struct FrontSessionBound {
    max_sessions: usize,
    idle_expiry_secs: u64,
}

/// One visitor turn on a published page's constraint field.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConstraintTurnInput {
    event_type: EventTypeKey,
    window: TurnWindow,
    /// The zone the page detected. The sentence may name another.
    visitor_tz: String,
    free_text: String,
    session_ref: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnWindow {
    start: u64,
    end: u64,
}

/// The three terminal shapes of a turn, on the wire. The oracle's raw solve
/// never travels: the card holds the offers.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(super) enum ConstraintTurnResponse {
    /// One voice line and up to three slot buttons, each a real public slot.
    Slots {
        card: GeneratedUiCard,
        flex_used: bool,
        hold: HoldContext,
    },
    /// No fit: the canonical constraint the email continuation carries. No
    /// raw sentence.
    ContinueByEmail {
        continuation: ConstraintContinuation,
    },
    /// Off-topic: the one configured line, and no control.
    Deflect { card: GeneratedUiCard },
}

/// The rest of a `verbs/hold` input for a `booking.select_slot` click: the
/// click supplies `selected_slot` from the button's two arguments and its own
/// `idempotency_key`. The constraint is the one the oracle solved, so the
/// hold's offerability check re-solves the same bytes.
#[derive(Debug, Serialize)]
pub(super) struct HoldContext {
    event_type: EventTypeKey,
    visitor_tz: String,
    constraint: ConstraintObject,
    session_ref: String,
}

/// Runs one admitted turn for an anonymous visitor of a live publication.
///
/// Order: the listing's shape and publication checks (the event card is
/// listed, the constraint field enabled), the owner's front config and the
/// parse seat, the one admission call, then the turn on a blocking thread,
/// then a recheck that the publication did not change while it ran.
pub(super) async fn run_public_constraint_turn(
    server: &Arc<SyncServer>,
    authority: PublicBookingAuthority,
    input: ConstraintTurnInput,
    transport: &BookingTransportContext,
) -> Result<ConstraintTurnResponse, ApiError> {
    let page_ref = authority.page_ref;
    let window = TimeRange {
        start: input.window.start,
        end: input.window.end,
    };
    // The listing this turn is, so the public checks and admission it meets
    // are a free-text availability request's own.
    let listing = BookingOperationRequest::Availability(BookingAvailabilityInput {
        event_type: input.event_type.clone(),
        window,
        visitor_tz: input.visitor_tz.clone(),
        constraint: Some(BookingConstraintInput::FreeText(input.free_text.clone())),
        session_ref: input.session_ref.clone(),
    });
    public_availability::validate_public_request(&authority.publication, &listing)?;
    validate_operation_shape(&listing)?;
    let front = authority
        .publication
        .constraint_front
        .clone()
        .ok_or_else(front_not_configured)?;
    let settings = parse_seat_settings(server)?;

    // ── the one admission call, in the listing class ────────────────────
    let mut turn = turn::Turn::new(server, transport);
    let (now, disposition) = loop {
        let now = now_secs()?;
        let facts = admission_facts(server, page_ref, &listing, transport, now)?;
        let disposition = enforce_slot_list(State(Arc::clone(server)), facts, false).await?;
        if let Some(disposition) = turn.after(disposition).await? {
            break (now, disposition);
        }
    };
    if admission_short_circuit(&listing, disposition)?.is_some() {
        tracing::debug!(
            transport = transport.transport.as_str(),
            "booking front admission answered without parsing or solving"
        );
        return silent_answer(&input.session_ref, &front);
    }

    let session = front_sessions().checkout(session_key(page_ref, &input.session_ref), now);
    let event_type = input.event_type.clone();
    let session_ref = input.session_ref.clone();
    let request = ConstraintTurnRequest {
        session_ref: input.session_ref,
        event_type: input.event_type,
        window,
        detected_visitor_tz: input.visitor_tz,
        free_text: input.free_text,
    };
    let principal = transport.principal;
    let turn_server = Arc::clone(server);
    // The ladder's model rungs block on the server's runtime.
    let outcome = tokio::task::spawn_blocking(move || {
        let oracle = PublicSlotOracle(booking_oracle(&turn_server, page_ref, None, now)?);
        let mut state = session.lock().unwrap_or_else(PoisonError::into_inner);
        let (caps, copy) = (front.caps(), front.copy());
        on_parse_seat(
            &turn_server,
            &settings,
            principal,
            now,
            |backend, lease, config| {
                block_on(run_constraint_turn(
                    &oracle, backend, lease, config, &caps, &mut state, &copy, request,
                ))
                .map_err(booking_error)
            },
        )
    })
    .await
    .map_err(|_| ApiError::internal_server_error("booking constraint turn stopped"))??;
    // Never answer from a publication the owner revoked or edited meanwhile.
    public_availability::recheck(server, Some(&authority))?;
    Ok(match outcome {
        ConstraintFrontOutcome::Slots(reply) => ConstraintTurnResponse::Slots {
            card: reply.card,
            flex_used: reply.solve_result.flex_used,
            hold: HoldContext {
                event_type,
                visitor_tz: reply.visitor_tz,
                constraint: reply.constraint,
                session_ref,
            },
        },
        ConstraintFrontOutcome::ContinueByEmail(continuation) => {
            ConstraintTurnResponse::ContinueByEmail { continuation }
        }
        ConstraintFrontOutcome::Deflect(deflect) => {
            ConstraintTurnResponse::Deflect { card: deflect.card }
        }
    })
}

/// The answer a silently declined or quarantined turn gets: success-shaped,
/// the owner's deflect line, with no parse, no solve and no session spent.
/// One CALLS row ("booking front silent answer").
fn silent_answer(
    session_ref: &str,
    front: &ConstraintFrontConfig,
) -> Result<ConstraintTurnResponse, ApiError> {
    let deflect = constraint_deflect(session_ref, &front.copy()).map_err(booking_error)?;
    Ok(ConstraintTurnResponse::Deflect { card: deflect.card })
}

/// The publication has the constraint field but no front config of its own:
/// nothing here supplies copy or caps in its place.
fn front_not_configured() -> ApiError {
    ApiError::invalid_state(Some("booking_constraint_front_not_configured"))
}

/// The page's real oracle, clamped to the public rung on the way out: the
/// front ranks and renders only slots the public availability answer would
/// show, and never sees a host binding.
struct PublicSlotOracle<'a>(ServerBookingOracle<'a>);

impl SlotOracle for PublicSlotOracle<'_> {
    fn solve(&self, request: &SolveRequest) -> Result<SolveResult, BookingError> {
        let solved = self.0.solve(request)?;
        let RungProjection::Slots(mask) = bounded_public_slots(slot_mask(request, solved))? else {
            return Err(BookingError::SlotOracle(
                "public booking projection is not a slot mask".to_owned(),
            ));
        };
        Ok(SolveResult {
            slots: mask.slots,
            flex_used: mask.flex_used,
            host_bindings: Vec::new(),
        })
    }
}

/// Per page and session: the counters `run_constraint_turn` admits against.
/// A turn locks its own session for its whole run, so two turns of one
/// session never both spend the same count.
#[derive(Default)]
struct FrontSessions {
    by_key: HashMap<SessionKey, FrontSession>,
}

struct FrontSession {
    last_used: u64,
    state: Arc<Mutex<ConstraintSessionState>>,
}

impl FrontSessions {
    fn checkout(&mut self, key: SessionKey, now: u64) -> Arc<Mutex<ConstraintSessionState>> {
        self.by_key.retain(|_, session| {
            now.saturating_sub(session.last_used) < FRONT_SESSIONS.idle_expiry_secs
        });
        if !self.by_key.contains_key(&key) && self.by_key.len() >= FRONT_SESSIONS.max_sessions {
            let oldest = self
                .by_key
                .iter()
                .min_by_key(|(_, session)| session.last_used)
                .map(|(oldest, _)| *oldest);
            if let Some(oldest) = oldest {
                self.by_key.remove(&oldest);
            }
        }
        let session = self.by_key.entry(key).or_insert_with(|| FrontSession {
            last_used: now,
            state: Arc::default(),
        });
        session.last_used = now;
        Arc::clone(&session.state)
    }
}

fn front_sessions() -> std::sync::MutexGuard<'static, FrontSessions> {
    static SESSIONS: OnceLock<Mutex<FrontSessions>> = OnceLock::new();
    SESSIONS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}
