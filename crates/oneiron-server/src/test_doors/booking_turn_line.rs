//! Door for `tests/booking_turn_line.rs` (census L3-11, ARCH-0062
//! #booking-turn-divergence): authenticated hold requests on a page
//! session's hold cap, each run through the booking executor's own turn
//! (`api::booking::turn::Turn`) over an admission pass the test scripts.

use oneiron::booking::SessionKey;

use crate::api::{BookingHttpDisposition, BookingTurn};
use crate::error::{ApiError, ApiErrorDetails};
use crate::server::SyncServer;

/// What one admission pass answers, as the test scripts it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pass {
    /// Admitted: the request goes on to its write.
    Admitted,
    /// Refused for the window, which opens in `seconds` (the hold cap's
    /// answer, as `booking_anti_abuse::guards::enforce_hold` gives it).
    Wait { seconds: u64 },
}

/// How one request's turn ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnEnd {
    /// Admitted by a pass.
    Admitted,
    /// Answered `booking_turn_waited_out`: its deadline came first.
    WaitedOut,
    /// Any other answer, with its message.
    Refused(String),
}

/// Runs one authenticated hold request on `server` for the page session
/// `session` (its 32-byte session key) as the executor runs a hold: it takes
/// its place in the session's line, then runs one `pass` per admission pass
/// and waits as its turn says, until it is answered. Its place is given up
/// when this returns, as the executor gives it up after the hold's write.
pub async fn authenticated_hold(
    server: &SyncServer,
    session: [u8; 32],
    mut pass: impl FnMut() -> Pass,
) -> TurnEnd {
    let mut turn = BookingTurn::new(server, true);
    let answered: Result<(), ApiError> = async {
        turn.line_up(SessionKey(session)).await?;
        loop {
            let disposition = match pass() {
                Pass::Admitted => BookingHttpDisposition::Continue,
                Pass::Wait { seconds } => BookingHttpDisposition::RetryAfter { seconds, bound: 1 },
            };
            if turn.after(disposition).await?.is_some() {
                return Ok::<(), ApiError>(());
            }
        }
    }
    .await;
    match answered {
        Ok(()) => TurnEnd::Admitted,
        Err(error) => match error.details() {
            ApiErrorDetails::InvalidState { state }
                if state.as_deref() == Some("booking_turn_waited_out") =>
            {
                TurnEnd::WaitedOut
            }
            _ => TurnEnd::Refused(error.message().to_owned()),
        },
    }
}

/// How many page sessions have a line on `server`. A line nobody holds or
/// waits in is forgotten, so this is 0 once every hold was answered or
/// dropped.
pub fn lines_held(server: &SyncServer) -> usize {
    server.booking_turn_lines.held()
}

/// What [`waiter_dropped_after_the_head_leaves`] saw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DroppedWaiter {
    /// The second hold was still waiting in line after its first poll.
    pub waited: bool,
    /// The lines `server` holds once both holds are gone.
    pub lines_held: usize,
}

/// Plays one order by hand, as no scheduler would promise it: a hold takes
/// the head of `session`'s line; a second joins and is polled once, so it
/// waits behind the first; the first is answered, and its head passes to the
/// waiter; the waiter's request is dropped before it is polled again (its
/// client went away). Both are gone at the end. `Err` is the head's
/// refusal, with its message.
pub async fn waiter_dropped_after_the_head_leaves(
    server: &SyncServer,
    session: [u8; 32],
) -> Result<DroppedWaiter, String> {
    let window = SessionKey(session);
    let mut head = BookingTurn::new(server, true);
    head.line_up(window)
        .await
        .map_err(|error| error.message().to_owned())?;
    let mut waiter = BookingTurn::new(server, true);
    let waited = {
        let mut waiting = std::pin::pin!(waiter.line_up(window));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let waited = waiting.as_mut().poll(&mut context).is_pending();
        drop(head);
        waited
    };
    drop(waiter);
    Ok(DroppedWaiter {
        waited,
        lines_held: lines_held(server),
    })
}
